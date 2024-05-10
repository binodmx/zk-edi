import time
import random
from blspy import (PrivateKey, Util, AugSchemeMPL, PopSchemeMPL,
                   G1Element, G2Element)

class EdgeServer:
    HEARTBEAT_INTERVAL = 0.5
    
    def __init__(self, id, data_replica, latency_matrix, app_vendor):
        self.id = id
        self.data_replica = data_replica
        self.latency_matrix = latency_matrix
        self.app_vendor = app_vendor
        self.seed: bytes = bytes([random.randint(0, 255) for i in range(32)])
        self.private_key: PrivateKey = AugSchemeMPL.key_gen(self.seed)
        self.public_key: G1Element = self.private_key.get_g1()

    def __str__(self):
        return f"EdgeServer {self.id}"
    
    def send_proof(self):
        """
        Send the zero knowledge proof (BLS signature for the data replica)
        to the cluster head.
        """
        if self.cluster_head.id == self.id:
            return
        latency = self.latency_matrix[self.id][self.cluster_head.id]
        if latency < 0:
            return False
        time.sleep(latency)
        signature: G2Element = AugSchemeMPL.sign(self.private_key, 
            self.data_replica)
        return signature
    
    def send_aggregated_proof(self):
        """
        Send the aggregated zero knowledge proof to other cluster heads.
        """
        pass
    
    
    def set_cluster(self, cluster_members):
        self.cluster_members = cluster_members
        self.cluster_head = self.cluster_members[0]

    
    
    def heartbeat(self):
        while self.state == 'VERIFYING':
            for member in self.cluster_members:
                member.notify()
            time.sleep(self.HEARTBEAT_INTERVAL)