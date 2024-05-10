from EdgeServer import EdgeServer
from AppVendor import AppVendor
from Logger import Logger
import numpy as np
import random
import math
import time
import threading
from sklearn.cluster import SpectralClustering

class Simulator:
    def __init__(self, n_servers):
        self.logger = Logger(self)
        self.n_servers = n_servers
    
    def __str__(self):
        return f"Simulator"
                 
    def simulate(self):
        self.logger.log("Simulation started.")

        # 1: Cluster Formation
        self.similarity_matrix = self.get_similarity_matrix(self.n_servers)
        self.clusters = self.get_clusters(self.similarity_matrix, 3)
        self.app_vendor = AppVendor()
        self.edge_servers = []
        for i in range(self.n_servers):
            self.edge_servers.append(EdgeServer(
                id=i,
                data_replica=bytes([1, 2, 3, 4, 5]),
                app_vendor=self.app_vendor))
        
        # 2. Data Sharing and Verification
        for i in range(self.n_servers):
            threading.Thread(target=self.edge_servers[i].run).start()
            
        # 3. Reputation System
        threading.Thread(target=self.app_vendor.run).start()

        self.logger.log("Simulation ended.")

    def get_similarity_matrix(self, n_servers):
        """
        Creates the similarity matrix with random values.

        Parameters:
        - n_servers: The number of edge servers in the network.

        Returns:
        - similarity_matrix: A square matrix of size n_servers x n_servers.
        """
        self.logger.log("Creating the similarity matrix...")
        # Initialize rtt_matrix with random values. Each (i, j) element is the 
        # round trip time (s) between i and j. This matrix is symmetric such 
        # that RTT between i and j is same as between j and i.
        rtt_matrix = np.random.rand(n_servers, n_servers)
        rtt_matrix = (rtt_matrix + rtt_matrix.T) / 2

        # Add some noise to the matrix to make it more realistic. By chaning the 
        # range of the noise, we can control the server failure rate. For 
        # example, if the noise is between -0.1 and 0.1, then failure rate is 
        # about 0.4% depicted by negative values in the matrix.
        noise = np.random.rand(n_servers, n_servers) * 0.2 - 0.1
        rtt_matrix = rtt_matrix + noise
        
        # Multiply rtt_matrix with by 10 to get the round trip time in between
        # 0 and 10ms.
        rtt_matrix = rtt_matrix * 10

        # Initialize hopcount_matrix with random values. We do not add noise to
        # this matrix because noise is already added to the rtt_matrix.
        hopcount_matrix = np.random.randint(1, 4, (n_servers, n_servers))
        hopcount_matrix = (hopcount_matrix + hopcount_matrix.T) // 2

        # Initialize the similarity matrix.
        similarity_matrix = np.zeros((n_servers, n_servers))
        for i in range(n_servers):
            for j in range(n_servers):
                similarity_matrix[i][j] = 1 / (rtt_matrix[i][j] 
                                               * hopcount_matrix[i][j])
        np.fill_diagonal(similarity_matrix, 0)

        # TODO: Add some server failures. The probability of having a failure is 1%.
        outliers = np.zeros((n_servers, n_servers))
        # fill negatie values with 0
        similarity_matrix[similarity_matrix < 0] = 0

        # Log the faulty rate.
        self.logger.log("Similarity matrix created successfully!")
        self.logger.log(f"Faulty rate: {(np.count_nonzero(similarity_matrix < 0)/n_servers**2)*100} %")

        return similarity_matrix
    
    def get_clusters(self, adjacency_matrix, n_clusters):
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
        self.logger.log("Clustering the servers...")
        clustering = SpectralClustering(n_clusters=n_clusters, 
                                        affinity='precomputed', 
                                        assign_labels='kmeans')
        clustering.fit(adjacency_matrix)
        self.logger.log("Servers clustered successfully!")
        return clustering.labels_
