import time
import random
import threading
from Logger import Logger
from Constants import dt1, dt2, n
from blspy import (PrivateKey, Util, AugSchemeMPL, PopSchemeMPL,
                   G1Element, G2Element)

class EdgeServer:
    HEARTBEAT_INTERVAL = 0.5
    
    def __init__(self, id, private_key, public_key, data_replica, data_replica_size, 
                 is_cluster_head, is_corrupted, app_vendor, edge_servers, clusters):
        self.id = id
        self.is_cluster_head = is_cluster_head
        self.is_corrupted = is_corrupted
        self.data_replica = data_replica if not is_corrupted else bytes(
            [random.randint(0, 255) for i in range(data_replica_size)])
        self.app_vendor = app_vendor
        self.edge_servers = edge_servers
        self.clusters = clusters
        self.logger = Logger(self)
        self.cluster_head = None
        self.cluster_heads = None
        self.m = 3

        # Python does not have a lock-free ConcurrentHashMap implementation
        # due to Global Interpreter Lock (GIL). However, we can use a simple
        # dictionary as a lock-free alternative due to GIL.
        self.similar_proofs = {}
        self.distinct_proofs = {}
        self.similar_agg_proofs = {}
        self.distinct_agg_proofs = {}
        self.similar_proof_count = 0

        self.private_key: PrivateKey = private_key
        self.public_key: G1Element = public_key
        self.proof: G2Element = AugSchemeMPL.sign(self.private_key, 
                                                  self.data_replica)

    def __str__(self):
        return f"EdgeServer {self.id}"

    def run(self):
        self.t0 = time.time()
        if self.is_cluster_head:
            self.logger.log("Started as a cluster head.")
            self.send_agg_proof_to_chs()
            self.notify_cms()
        else:
            self.logger.log("Started as a cluster member.")
            self.send_proof_to_ch()
            self.listen()

    def send_proof_to_ch(self):
        proof = self.get_proof()
        self.cluster_head.set_proof(self.public_key, proof)

    def send_agg_proof_to_chs(self):
        agg_proof = self.get_agg_proof()
        pks = []
        for cluster_head in self.cluster_heads:
            threading.Thread(target=cluster_head.set_agg_proof, 
                             args=(self.id, pks, agg_proof,)).start()
    
    def get_proof(self):
        return PopSchemeMPL.sign(self.private_key, self.data_replica)
    
    # Sending public key along with the proof for ease of implementation.
    # In practice, the public key should be sent during the initializtion.
    def set_proof(self, pk, proof):
        # TODO: timeout
        t1 = time.time()
        if PopSchemeMPL.verify(pk, self.proof, proof):
            self.similar_proofs[pk] = proof
            self.similar_proof_count += 1
        else:
            self.distinct_proofs[pk] = proof

    def get_agg_proof(self):
        '''''
        Wait until timeout dt1 or all cluster members have sent their proofs.
        Then if more than half of the proofs are similar, aggregate them.
        '''
        while True:
            t1 = time.time()
            p_count = len(self.similar_proofs) + len(self.distinct_proofs)
            if t1 - self.t0 > dt1 or p_count == self.m:
                break
        if p_count > self.m / 2:
            return PopSchemeMPL.aggregate(list(self.similar_proofs.values()))
        return None
    
    def set_agg_proof(self, id, pks, agg_proof):
        # TODO: timeout
        if PopSchemeMPL.fast_aggregate_verify(pks, self.proof, agg_proof):
            self.similar_agg_proofs[id] = agg_proof
            self.similar_proof_count += len(pks)
        else:
            self.distinct_agg_proofs[id] = agg_proof            
    
    def set_cluster(self, cluster_members):
        self.cluster_members = cluster_members
        self.cluster_head = self.cluster_members[0]

    def set_verdict(self, agg_proof):
        self.verdict = agg_proof

    def listen(self):
        pass

    def notify_cms(self):
        # TODO: wait until proofs recievd
        if self.similar_proof_count > n / 2:
            for cm in self.cluster_members:
                cm.set_verdict(agg_proof)
        else:
            for cm in self.cluster_members:
                cm.set_verdict(None)

    def reset(self):
        self.similar_proofs = {}
        self.distinct_proofs = {}
