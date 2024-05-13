from EdgeServer import EdgeServer
from AppVendor import AppVendor
from Logger import Logger
import numpy as np
import random
import math
import threading
from sklearn.cluster import SpectralClustering
from blspy import AugSchemeMPL
import warnings

class Simulator:
    def __init__(self, n, data_replica_size, corruption_rate):
        self.logger = Logger(self)
        self.n = n
        self.data_replica_size = data_replica_size
        self.corruption_rate = corruption_rate
        self.dt1 = 10
        self.dt2 = 20
        
    def __str__(self):
        return f"Simulator"
                 
    def run(self):
        self.logger.log("Simulation started.")
        self.logger.log(f"""Parameter settings: 
                        n={self.n}, 
                        data_replica_size={self.data_replica_size}bytes, 
                        corruption_rate={self.corruption_rate}""")

        # 1: Cluster Formation
        self.logger.log("Running cluster formation...")
        self.similarity_matrix = self.get_similarity_matrix()
        self.clusters = self.get_clusters()
        self.cluster_heads = self.get_cluster_heads()
        self.app_vendor = AppVendor()
        self.edge_servers = []
        data_replica = bytes([random.randint(0, 255) for i in range(
                    self.data_replica_size)])
        corrupted_servers = self.get_corrupted_servers()
        for i in range(self.n):
            self.edge_servers.append(EdgeServer(
                id=i,
                n=self.n,
                data_replica=data_replica,
                is_corrupted=bool(corrupted_servers[i]),
                app_vendor=self.app_vendor,
                clusters=self.clusters,
                cluster_heads=self.cluster_heads,
                dt1=self.dt1,
                dt2=self.dt2))
        for i in range(self.n):
            self.edge_servers[i].set_edge_servers(self.edge_servers)
        self.logger.log("Clusters formed successfully!")
        
        # 2. Data Sharing and Verification
        self.logger.log("Running data sharing and verification...")
        for i in range(self.n):
            threading.Thread(target=self.edge_servers[i].run).start()
            
        # 3. Reputation System
        # threading.Thread(target=self.app_vendor.run).start()

        self.logger.log("Simulation ended.")

    def get_similarity_matrix(self):
        """
        Returns the similarity_matrix, a square matrix with size of n x n.
        """
        self.logger.log("Creating the similarity matrix...")

        # Initialize rtt_matrix with random values. Each (i, j) element is the 
        # round trip time (s) between i and j. This matrix is symmetric such 
        # that RTT between i and j is same as between j and i.
        rtt_matrix = np.random.rand(self.n, self.n)
        rtt_matrix = (rtt_matrix + rtt_matrix.T) / 2

        # Add some noise to make rtt_matrix more realistic. By changing the 
        # range of the noise, we can control the ping failure rate.
        failure_range = 0.35
        noise = np.random.rand(self.n, self.n) * failure_range - (
            failure_range / 2)
        rtt_matrix = rtt_matrix + noise
        
        # Multiply rtt_matrix with by 10 to get the round trip time in between
        # 0 and 10ms.
        rtt_matrix = rtt_matrix * 10

        # Initialize hopcount_matrix with random values. We do not add noise to
        # this matrix because noise is already added to the rtt_matrix. The hop
        # count is between 1 and 4.
        hopcount_matrix = np.random.randint(1, 4, (self.n, self.n))
        hopcount_matrix = (hopcount_matrix + hopcount_matrix.T) // 2

        # Compute the similarity matrix using the formula.
        similarity_matrix = np.zeros((self.n, self.n))
        for i in range(self.n):
            for j in range(self.n):
                similarity_matrix[i][j] = 1 / (rtt_matrix[i][j] 
                                               * hopcount_matrix[i][j])
        np.fill_diagonal(similarity_matrix, 0)
        similarity_matrix[similarity_matrix < 0] = 0

        self.logger.log(f"""Parameter settings: ping_failure_rate={(
            np.count_nonzero(similarity_matrix == 0)-self.n)/self.n**2}""")
        self.logger.log("Similarity matrix created successfully!")

        return similarity_matrix
    
    def get_clusters(self):
        """
        Clusters the servers represented by the adjacency matrix using spectral 
        clustering.

        Parameters:
        - adjacency_matrix: The similarity matrix representing the graph 
        structure of the servers to be clustered. It should be a square matrix 
        where each entry (i, j) represents the similarity between servers i, j.
        - n_clusters: The number of clusters to form.

        Returns:
        - labels: An array of cluster labels assigned to each server based on 
        spectral clustering.
        """
        adjacency_matrix = self.similarity_matrix
        # TODO: Determine the number of clusters dynamically.
        n_clusters = 3
        self.logger.log("Clustering the servers...")
        warnings.simplefilter("ignore", UserWarning)
        clustering = SpectralClustering(n_clusters=n_clusters, 
                                        affinity='precomputed', 
                                        assign_labels='kmeans')
        clustering.fit(adjacency_matrix)
        self.logger.log("Servers clustered successfully!")
        clusters = {}
        for i in range(len(clustering.labels_)):
            if clustering.labels_[i] not in clusters:
                clusters[clustering.labels_[i]] = []
            clusters[clustering.labels_[i]].append(i)
        return clusters

    def get_cluster_heads(self):
        cluster_heads = {}
        for cluster_id, servers in self.clusters.items():
            total_scores = {}
            for i in servers:
                total_scores[i] = 0
                for j in servers:
                    total_scores[i] += self.similarity_matrix[i][j] 
                    + self.similarity_matrix[j][i]
            cluster_heads[cluster_id] = max(total_scores, key=total_scores.get)
        return cluster_heads                

    def get_corrupted_servers(self):
        corrupted_servers = [0] * self.n
        indices = random.sample(range(self.n), math.floor(
            self.n*self.corruption_rate))
        for index in indices:
            corrupted_servers[index] = 1
        return corrupted_servers
