from AppVendorRunner import AppVendor
from EdgeServer import EdgeServer
import numpy as np
import random
import math
import time
import threading
from blspy import (PrivateKey, Util, AugSchemeMPL, PopSchemeMPL, G1Element, 
                   G2Element)

class Simulator:
    def __init__(self, n_servers):
        print(f"{time.strftime('%H:%M:%S')} Initializing the simulator...")
        self.n_servers = n_servers   
        self.latency_matrix = self.create_latency_matrix(n_servers, 0.1)
        self.app_vendor = AppVendor()
        self.edge_servers = []
        for i in range(n_servers):
            self.edge_servers.append(EdgeServer(
                id=i,
                data_replica=bytes([1, 2, 3, 4, 5]),
                latency_matrix=self.latency_matrix,
                app_vendor=self.app_vendor))
        print(f"{time.strftime('%H:%M:%S')} Simulator built successfully.")  
                 
    def simulate(self):
        print(f"{time.strftime('%H:%M:%S')} Starting the simulation...")

        # Phase 1: Cluster Formation
        # TODO: Implement the cluster HEAD selection algorithm.
        n_clusters = 3
        clustering = self.app_vendor.cluster(self.latency_matrix, n_clusters)
        self.cluster_heads = []
        for i in range(self.n_servers):
            self.edge_servers[i].set_cluster(
                [j for j in range(self.n_servers) if clustering[j] == 
                 clustering[i]])
        
        # Phase 2: Data Sharing and Verification
        # TODO: This should be done using threads (parallely)
        for i in range(self.n_servers):
            threading.Thread(target=self.edge_servers[i].send_proof).start()

        # TODO: wait until all threads are done for current cluster head
        for i in range(n_clusters):
            threading.Thread(target=self.cluster_heads[i]
                             .send_aggregated_proof).start()

        
    def create_latency_matrix(self, n_servers, p_outlier):
        """
        Creates the latency matrix with random values.

        Parameters:
        - n_servers: The number of edge servers in the network.
        - p_outlier: The probability of having an outlier

        Returns:
        - latency_matrix: A square matrix of size n_servers x n_servers.
        """
        # Initialize latency_matrix with random values between 0 and 1.
        # Each (i, j) element is the round trip time (s) between i and j.
        # This matrix is symmetric such that RTT between i and j is the same as 
        # between j and i.
        latency_matrix = np.random.rand(n_servers, n_servers)
        np.fill_diagonal(latency_matrix, 0)
        latency_matrix = (latency_matrix + latency_matrix.T) / 2

        # Add some noise to the latency_matrix to make it more realistic. 
        # Noise is ranging from -0.1 to 0.1. Negative values in the final matrix
        # represent network failures, intentional delays, and other issues.
        noise = np.random.rand(n_servers, n_servers) * 0.2 - 0.1
        np.fill_diagonal(noise, 0)
        latency_matrix = latency_matrix + noise

        # Add some outliers to indicate threat actors and sudden network 
        # failures. The probability of having an outlier is p_outlier.
        outliers = np.zeros((n_servers, n_servers))
        for i in range(math.floor(n_servers * p_outlier)):
            server1 = random.randint(0, n_servers - 1)
            server2 = random.randint(0, n_servers - 1)
            if server1 != server2:
                outliers[server1][server2] = np.random.rand()
        latency_matrix = latency_matrix + outliers

        return latency_matrix