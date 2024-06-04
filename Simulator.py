import numpy as np
import random
import math
import threading
import time
import warnings
import json
from numpy import savetxt
from numpy import loadtxt
from queue import Queue
from blspy import (PrivateKey, AugSchemeMPL, PopSchemeMPL, G1Element, G2Element)
from EdgeServer import EdgeServer
from Logger import Logger
from sklearn.cluster import SpectralClustering
from RecursiveSpectralClustering import RecursiveSpectralClustering
from RandomClustering import RandomClustering

class Simulator:
    def __init__(self, edge_scale, replica_scale, replica_size, 
                 corruption_rate, dt1, dt2, dt3):
        self.logger = Logger(self)
        self.n = edge_scale
        self.replica_scale = replica_scale
        self.replica_size = replica_size
        self.corruption_rate = corruption_rate
        self.dt1 = dt1
        self.dt2 = dt2
        self.dt3 = dt3
        
    def __str__(self):
        return f"Simulator"
                 
    def run(self):
        self.logger.debug("Simulation started.")
        self.logger.debug(f"""Parameter settings: 
                        edge_scale={self.n}, 
                        replica_scale={self.replica_scale},
                        replica_size={self.replica_size}bytes, 
                        corruption_rate={self.corruption_rate}""")

        # Run Cluster Formation
        self.logger.debug("Running cluster formation...")
        st0 = time.time()
        self.rtt_matrix = self.get_rtt_matrix()
        self.similarity_matrix = self.get_similarity_matrix()
        self.clusters = self.get_clusters()
        self.cluster_heads = self.get_cluster_heads()
        self.corrupted_servers = self.get_corrupted_servers()
        self.logger.debug("Clusters formed successfully!")

        # Initialize Servers
        self.logger.debug("Initializing edge servers...")
        st1 = time.time()
        self.l_times = [-1]*self.n
        self.g_times = [-1]*self.n
        self.t1s = [0]*self.n
        self.t2s = [0]*self.n
        self.timed_out = [False]*self.n
        self.hashes = self.get_data_hashes()
        self.hash_ds = [bytes.fromhex(self.hashes[i]) if self.corrupted_servers[i] else bytes.fromhex(self.hashes[-1]) for i in range(self.n)]
        self.private_keys = [AugSchemeMPL.key_gen(bytes([random.randint(0, 255) for i in range(32)])) for j in range(self.n)]
        self.public_keys = [self.private_keys[i].get_g1() for i in range(self.n)]
        self.ss_queue = Queue()
        self.sp_queues = [Queue() for i in range(self.n)]
        self.ap_queues = [Queue() for i in range(self.n)]
        self.lv_queues = [Queue() for i in range(self.n)]
        self.gv_queues = [Queue() for i in range(self.n)]
        self.edge_servers = []
        for i in range(self.n):
            edge_server = EdgeServer(
                id=i,
                n=self.n,
                is_corrupted=bool(self.corrupted_servers[i]),
                hash_ds=self.hash_ds,
                private_key=self.private_keys[i],
                public_keys=self.public_keys,
                proof=PopSchemeMPL.sign(self.private_keys[i], self.hash_ds[i]),
                c_id=next((c_id for c_id, servers in self.clusters.items() if i in servers), None),
                clusters=self.clusters,
                ch_id=next((self.cluster_heads[c_id] for c_id, servers in self.clusters.items() if i in servers), None),
                cluster_heads=self.cluster_heads,
                latency_matrix=self.rtt_matrix/2,
                ss_queue=self.ss_queue,
                sp_queues=self.sp_queues,
                ap_queues=self.ap_queues,
                lv_queues=self.lv_queues,
                gv_queues=self.gv_queues,
                dt1=self.dt1,
                dt2=self.dt2, 
                dt3=self.dt3,
                t1s=self.t1s,
                t2s=self.t2s,
                l_times=self.l_times,
                g_times=self.g_times,
                timed_out=self.timed_out)
            self.edge_servers.append(edge_server)
        self.logger.debug("Edge servers initialized successfully!")
        
        # Run Data Sharing and Verification
        self.logger.debug("Starting data sharing and verification...")
        st2 = time.time()
        init_thread_count = threading.active_count()
        # for i in range(self.n):
        #     threading.Thread(target=self.edge_servers[i].run).start()
        for edge_server in self.edge_servers:
            edge_server.start()
        
        # Wait for all threads to finish and then wait for few more seconds 
        # to ensure that all threads have completed the verification process.
        self.logger.debug("Running data sharing and verification...")
        st3 = time.time()
        while threading.active_count() > init_thread_count:
            time.sleep(0.0001)
        self.logger.debug("Data verification completed successfully!")
        
        # Construct the metrics report
        self.metrics = {
            "parameter_settings": {
                "edge_scale": self.n,
                "replica_scale": self.replica_scale,
                "replica_size": self.replica_size,
                "corruption_rate": self.corruption_rate
            },
            "duration": {
                "s_local": self.l_times,
                "t_local": [t*self.replica_scale for t in self.l_times],
                "s_global": self.g_times,
                "t_global": [t*self.replica_scale for t in self.g_times],
                "dt1": self.dt1,
                "dt2": self.dt2,
                "dt3": self.dt3,
                "t1s": self.t1s,
                "t2s": self.t2s,
                "timed_out": str([int(x) for x in self.timed_out]),
                "cluster_formation": st1-st0,
                "server_initialization": st2-st1,
                "thread_creation": st3-st2,
                "total_runtime": time.time()-st0
            },
            "cluster_info": {
                "clusters": str(self.clusters),
                "cluster_heads": str(self.cluster_heads),
                "n_clusters": len(self.clusters),
                "corrupted_servers": str(self.corrupted_servers)
            }
        }

        self.logger.debug("Simulation ended.")
        return self.metrics

    def get_rtt_matrix(self):
        try:
            rtt_matrix = loadtxt(f"data/rtt_matrix_{self.n}.csv", delimiter=",")
            self.logger.debug("Loading the rtt_matrix...")
            return rtt_matrix
        except:
            pass

        self.logger.debug("Creating the rtt_matrix...")
        # Initialize rtt_matrix with random values. Each (i, j) element is the 
        # round trip time (s) between i and j.
        rtt_matrix = np.random.rand(self.n, self.n)

        # This matrix is symmetric such that RTT between i and j is same as 
        # between j and i. Therefore, add the transpose of the matrix to itself
        # and divide by 2 to make it symmetric.
        rtt_matrix = (rtt_matrix + rtt_matrix.T) / 2

        # Add some noise to make rtt_matrix more realistic. By changing the 
        # failure_range, we can control the failure rate. Here, failure rate 
        # represents the percentage of servers that are not responding. Failures
        # are represented by negative values in the matrix.
        failure_range = 0.1
        noise = np.random.rand(self.n, self.n) * failure_range - (failure_range/2)
        rtt_matrix = rtt_matrix + noise

        # Multiply rtt_matrix to get the round trip time in between 5 and 10ms. 
        # Finally, divide by 1000 to convert it to seconds.
        rtt_matrix[rtt_matrix > 0] = rtt_matrix[rtt_matrix > 0]*5+5
        rtt_matrix = rtt_matrix/1000
        
        # Save the rtt_matrix to a file for future use.
        savetxt(f"data/rtt_matrix_{self.n}.csv", rtt_matrix, delimiter=",")
        self.logger.debug("RTT matrix created successfully!")

        return rtt_matrix

    def get_similarity_matrix(self):
        try:
            similarity_matrix = loadtxt(f"data/similarity_matrix_{self.n}.csv", delimiter=",")
            self.logger.debug("Loading the similarity_matrix...")
            return similarity_matrix
        except:
            pass

        self.logger.debug("Creating the similarity_matrix...")

        # Compute the similarity matrix using the formula. We only consider the
        # rtt between servers for similarity calculation for simplicity.
        similarity_matrix = np.zeros((self.n, self.n))
        for i in range(self.n):
            for j in range(self.n):
                similarity_matrix[i][j] = 1 / (self.rtt_matrix[i][j])
        np.fill_diagonal(similarity_matrix, 0)
        similarity_matrix[similarity_matrix < 0] = 0

        self.logger.debug(f"""Parameter settings: 
                        failure_rate={(np.count_nonzero(similarity_matrix == 0)-self.n)/self.n**2}""")
        
        # Save the similarity_matrix to a file for future use.
        savetxt(f"data/similarity_matrix_{self.n}.csv", similarity_matrix, delimiter=",")
        self.logger.debug("Similarity matrix created successfully!")

        return similarity_matrix
    
    def get_clusters(self):
        self.logger.debug("Clustering the servers...")
        warnings.simplefilter("ignore", UserWarning)

        # No of clusters based on the number of servers is computed using the
        # probability function maximizing the P(Z).
        n_clusters_by_n = {10: 3, 20: 6, 50: 13, 100: 17, 200: 27}
        n_clusters = n_clusters_by_n[self.n] if self.n in n_clusters_by_n.keys() else math.floor(self.n**0.5)
        adjacency_matrix = self.similarity_matrix

        # Change Clustering class here to use different clustering algorithms.
        # [SpectralClustering, RecursiveSpectralClustering, RandomClustering]
        # clustering = RandomClustering(n_clusters=n_clusters, affinity='precomputed', assign_labels='kmeans')
        # clustering = SpectralClustering(n_clusters=n_clusters, affinity='precomputed', assign_labels='kmeans')
        clustering = RecursiveSpectralClustering(n_clusters=n_clusters, affinity='precomputed', assign_labels='kmeans')
        clustering.fit(adjacency_matrix)
        self.logger.debug("Servers clustered successfully!")

        clusters = {}
        for i in range(len(clustering.labels_)):
            if clustering.labels_[i] not in clusters:
                clusters[clustering.labels_[i]] = []
            clusters[clustering.labels_[i]].append(i)
        
        return clusters

    def get_cluster_heads(self):
        # Get the cluster head for each cluster having the maximum similarity
        cluster_heads = {}
        for c_id, servers in self.clusters.items():
            total_scores = {}
            for i in servers:
                total_scores[i] = 0
                for j in servers:
                    total_scores[i] += self.similarity_matrix[i][j] + self.similarity_matrix[j][i]
            cluster_heads[c_id] = max(total_scores, key=total_scores.get)
        return cluster_heads                

    def get_corrupted_servers(self):
        try:
            corrupted_servers = loadtxt(f"data/corrupted_servers_{self.n}_{self.corruption_rate}.csv", 
                                        delimiter=",")
            self.logger.debug("Loading the corrupted_servers...")
            return corrupted_servers
        except:
            pass

        # Create a list of corrupted servers based on the corruption rate.
        self.logger.debug("Creating corrupted_servers...")
        corrupted_servers = [0] * self.n
        indices = random.sample(range(self.n), math.floor(
            self.n*self.corruption_rate))
        for index in indices:
            corrupted_servers[index] = 1
        savetxt(f"data/corrupted_servers_{self.n}_{self.corruption_rate}.csv", corrupted_servers, 
                delimiter=",")
        self.logger.debug("Corrupted servers created successfully!")
        
        return corrupted_servers

    def get_data_hashes(self):
        with open("data/data_hashes.json", "r") as f:
            data_hashes = json.load(f)
        return data_hashes[str(self.replica_size)]
