import numpy as np
import random
import math
import threading
import time
import warnings
import json
from numpy import savetxt, loadtxt
from queue import Queue
from blspy import (PrivateKey, AugSchemeMPL, PopSchemeMPL, G1Element, G2Element)
from EdgeServer import EdgeServer
from sklearn.cluster import SpectralClustering
from RecursiveSpectralClustering import RecursiveSpectralClustering
from RandomClustering import RandomClustering

class Simulator:
    def __init__(self, edge_scale, replica_scale, replica_size, corruption_rate, 
                 dt1, dt2, dt3):
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
        # Load delay times
        with open(f"data/data_hashing_delays.json", "r") as f:
            data_hashing_delays = json.load(f)
        with open(f"data/hash_signing_delays.json", "r") as f:
            hash_signing_delays = json.load(f)
        with open(f"data/proof_aggregation_delays.json", "r") as f:
            proof_aggregation_delays = json.load(f)
        with open(f"data/proof_verification_delays.json", "r") as f:
            proof_verification_delays = json.load(f)

        # Load configurations
        st0 = time.time()
        rtt_matrix = self.get_rtt_matrix()
        similarity_matrix = self.get_similarity_matrix(rtt_matrix)
        clusters = self.get_clusters(similarity_matrix)
        cluster_heads = self.get_cluster_heads(clusters, similarity_matrix)
        corrupted_servers = self.get_corrupted_servers()
        server_types = self.get_server_types()
        hashes = self.get_data_hashes()

        # Initialize Servers
        st1 = time.time()
        l_times = [[-1 for _ in range(self.replica_scale)] for _ in range(self.n)]
        g_times = [[-1 for _ in range(self.replica_scale)] for _ in range(self.n)]
        t1s = [[0 for _ in range(self.replica_scale)] for _ in range(self.n)]
        t2s = [[0 for _ in range(self.replica_scale)] for _ in range(self.n)]
        hash_ds = [bytes.fromhex(hashes[i]) if corrupted_servers[i] else bytes.fromhex(hashes[-1]) for i in range(self.n)]
        private_keys = [AugSchemeMPL.key_gen(bytes([random.randint(0, 255) for _ in range(32)])) for _ in range(self.n)]
        public_keys = [private_keys[i].get_g1() for i in range(self.n)]
        ss_queue = Queue()
        sp_queues = [[Queue() for _ in range(self.replica_scale)] for _ in range(self.n)]
        ap_queues = [[Queue() for _ in range(self.replica_scale)] for _ in range(self.n)]
        lv_queues = [[Queue() for _ in range(self.replica_scale)] for _ in range(self.n)]
        gv_queues = [[Queue() for _ in range(self.replica_scale)] for _ in range(self.n)]
        edge_servers = []
        for i in range(self.n):
            edge_server = EdgeServer(
                id=i,
                n=self.n,
                replica_scale=self.replica_scale,
                is_corrupted=bool(corrupted_servers[i]),
                server_type=server_types[i],
                hash_ds=hash_ds,
                private_key=private_keys[i],
                public_keys=public_keys,
                proof=PopSchemeMPL.sign(private_keys[i], hash_ds[i]),
                c_id=next((c_id for c_id, servers in clusters.items() if i in servers), None),
                clusters=clusters,
                ch_id=next((cluster_heads[c_id] for c_id, servers in clusters.items() if i in servers), None),
                cluster_heads=cluster_heads,
                latency_matrix=rtt_matrix/2,
                ss_queue=ss_queue,
                sp_queues=sp_queues,
                ap_queues=ap_queues,
                lv_queues=lv_queues,
                gv_queues=gv_queues,
                dt1=self.dt1,
                dt2=self.dt2, 
                dt3=self.dt3,
                t1s=t1s,
                t2s=t2s,
                l_times=l_times,
                g_times=g_times,
                data_hashing_delay=random.uniform(
                    data_hashing_delays[server_types[i]][str(self.replica_size)]["min"],
                    data_hashing_delays[server_types[i]][str(self.replica_size)]["max"]),
                hash_signing_delay=random.uniform(
                    hash_signing_delays[server_types[i]]["min"],
                    hash_signing_delays[server_types[i]]["max"]),
                proof_aggregation_delays=proof_aggregation_delays[server_types[i]],
                proof_verification_delays=proof_verification_delays[server_types[i]])
            edge_servers.append(edge_server)
        
        # Run Data Sharing and Verification
        st2 = time.time()
        init_thread_count = threading.active_count()
        # for i in range(self.n):
        #     threading.Thread(target=self.edge_servers[i].run).start()
        for edge_server in edge_servers:
            edge_server.start()
        
        # Wait for all threads to finish and then wait for few more seconds 
        # to ensure that all threads have completed the verification process.
        st3 = time.time()
        while threading.active_count() > init_thread_count:
            time.sleep(0.0001)
        
        # Construct the metrics report
        metrics = {
            "parameter_settings": {
                "edge_scale": self.n,
                "replica_scale": self.replica_scale,
                "replica_size": self.replica_size,
                "corruption_rate": self.corruption_rate
            },
            "duration": {
                "local": l_times,
                "global": g_times,
                # "t1s": self.t1s,
                # "t2s": self.t2s,
                "cluster_formation": st1-st0,
                "server_initialization": st2-st1,
                "thread_creation": st3-st2,
                "total_runtime": time.time()-st0
            },
            "cluster_info": {
                "clusters": str(clusters),
                "cluster_heads": str(cluster_heads),
                "n_clusters": len(clusters),
                "corrupted_servers": str(corrupted_servers),
                "server_types": str(server_types)
            }
        }

        return metrics

    def get_rtt_matrix(self):
        try:
            rtt_matrix = loadtxt(f"data/rtt_matrix_{self.n}.csv", delimiter=",")
            return rtt_matrix
        except:
            pass

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

        return rtt_matrix

    def get_similarity_matrix(self, rtt_matrix):
        try:
            similarity_matrix = loadtxt(f"data/similarity_matrix_{self.n}.csv", delimiter=",")
            return similarity_matrix
        except:
            pass

        # Compute the similarity matrix using the formula. We only consider the
        # rtt between servers for similarity calculation for simplicity.
        similarity_matrix = np.zeros((self.n, self.n))
        for i in range(self.n):
            for j in range(self.n):
                similarity_matrix[i][j] = 1 / (rtt_matrix[i][j])
        np.fill_diagonal(similarity_matrix, 0)
        similarity_matrix[similarity_matrix < 0] = 0

        self.logger.debug(f"""Parameter settings: 
                        failure_rate={(np.count_nonzero(similarity_matrix == 0)-self.n)/self.n**2}""")
        
        # Save the similarity_matrix to a file for future use.
        savetxt(f"data/similarity_matrix_{self.n}.csv", similarity_matrix, delimiter=",")

        return similarity_matrix
    
    def get_clusters(self, adjacency_matrix):
        warnings.simplefilter("ignore", UserWarning)

        # No of clusters based on the number of servers is computed using the
        # probability function maximizing the P(Z).
        n_clusters_by_n = {10: 3, 20: 6, 50: 13, 100: 17, 200: 27}
        n_clusters = n_clusters_by_n[self.n] if self.n in n_clusters_by_n.keys() else math.floor(self.n**0.5)

        # Change Clustering class here to use different clustering algorithms.
        # [SpectralClustering, RecursiveSpectralClustering, RandomClustering]
        # clustering = RandomClustering(n_clusters=n_clusters, affinity='precomputed', assign_labels='kmeans')
        # clustering = SpectralClustering(n_clusters=n_clusters, affinity='precomputed', assign_labels='kmeans')
        clustering = RecursiveSpectralClustering(n_clusters=n_clusters, affinity='precomputed', assign_labels='kmeans')
        clustering.fit(adjacency_matrix)

        clusters = {}
        for i in range(len(clustering.labels_)):
            if clustering.labels_[i] not in clusters:
                clusters[clustering.labels_[i]] = []
            clusters[clustering.labels_[i]].append(i)
        
        return clusters

    def get_cluster_heads(self, clusters, similarity_matrix):
        # Get the cluster head for each cluster having the maximum similarity
        cluster_heads = {}
        for c_id, servers in clusters.items():
            total_scores = {}
            for i in servers:
                total_scores[i] = 0
                for j in servers:
                    total_scores[i] += similarity_matrix[i][j] + similarity_matrix[j][i]
            cluster_heads[c_id] = max(total_scores, key=total_scores.get)
        return cluster_heads                

    def get_corrupted_servers(self):
        try:
            corrupted_servers = loadtxt(f"data/corrupted_servers_{self.n}_{self.corruption_rate}.csv", 
                                        delimiter=",")
            return corrupted_servers
        except:
            pass

        # Create a list of corrupted servers based on the corruption rate.
        corrupted_servers = [0] * self.n
        indices = random.sample(range(self.n), math.floor(
            self.n*self.corruption_rate))
        for index in indices:
            corrupted_servers[index] = 1
        savetxt(f"data/corrupted_servers_{self.n}_{self.corruption_rate}.csv", corrupted_servers, 
                delimiter=",")
        
        return corrupted_servers
    
    def get_server_types(self):
        types_map = {1: 'rpi4_4', 2: 'rpi4_8', 3: 'rpi5_4', 4: 'rpi5_8', 5: 'msl5_16'}
        try:
            server_types = loadtxt(f"data/server_types_{self.n}.csv", delimiter=",")
            server_types = [types_map[server_type] for server_type in server_types]
            return server_types
        except:
            pass

        # Create a list of server types based on the number of servers.
        server_types = [random.randint(1, 5) for _ in range(self.n)]
        savetxt(f"data/server_types_{self.n}.csv", server_types, delimiter=",")
        server_types = [types_map[server_type] for server_type in server_types]
        return server_types

    def get_data_hashes(self):
        with open("data/data_hashes.json", "r") as f:
            data_hashes = json.load(f)
        return data_hashes[str(self.replica_size)]
