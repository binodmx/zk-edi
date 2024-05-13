import time
import threading
import hashlib
from Logger import Logger
from Config import dt1, dt2
from blspy import (PrivateKey, Util, AugSchemeMPL, PopSchemeMPL,
                   G1Element, G2Element)

class EdgeServer:
    def __init__(self, id, n, private_key, public_key, data_replica, is_corrupted, 
                 app_vendor, clusters, cluster_heads):
        self.id = id
        self.n = n
        self.logger = Logger(self)
        self.is_cluster_head = any(ch_id == self.id 
                                   for c_id, ch_id in cluster_heads.items())
        self.is_corrupted = is_corrupted
        self.data_replica = data_replica
        self.hash_d = bytes(hashlib.sha256(self.data_replica).digest())
        self.app_vendor = app_vendor
        self.clusters = clusters
        self.cluster_heads = cluster_heads
        self.c_id, self.ch_id = next(((c_id, cluster_heads[c_id])
                                  for c_id, servers in clusters.items() 
                                  if self.id in servers), None)
        self.private_key: PrivateKey = private_key
        self.public_key: G1Element = public_key
        self.proof: G2Element = AugSchemeMPL.sign(self.private_key, 
                                                  self.data_replica)

        # Python does not have a lock-free ConcurrentHashMap implementation
        # due to Global Interpreter Lock (GIL). However, we can use a simple
        # dictionary as a lock-free alternative due to GIL.
        self.similar_proofs = {}
        self.distinct_proofs = {}
        self.similar_agg_proofs = {}
        self.distinct_agg_proofs = {}
        self.similar_proof_count = 0

    def __str__(self):
        return f"EdgeServer {self.id}"

    def set_edge_servers(self, edge_servers):
        self.edge_servers = edge_servers

    def run(self):
        self.t0 = time.time()
        if self.is_cluster_head:
            self.logger.log("Started as a cluster head.")
            self.send_agg_proof_to_chs()
            self.notify_servers()
        else:
            self.logger.log("Started as a cluster member.")
            self.send_proof_to_ch()
            # self.listen()

    def send_proof_to_ch(self):
        proof = self.get_proof()
        self.edge_servers[self.ch_id].set_proof(self.id, self.public_key, proof)

    def send_agg_proof_to_chs(self):
        agg_proof = self.get_agg_proof()
        pks = []
        for c_id, ch_id in self.cluster_heads.items():
            if ch_id == self.ch_id:
                continue
            threading.Thread(target=self.edge_servers[ch_id].set_agg_proof, 
                             args=(self.id, pks, agg_proof,)).start()
    
    def get_proof(self):
        return PopSchemeMPL.sign(self.private_key, self.hash_d)
    
    # Sending public key along with the proof for ease of implementation.
    # In practice, the public key should be sent during the initializtion.
    def set_proof(self, id, pk, proof):
        # TODO: timeout
        self.t1 = time.time()
        if PopSchemeMPL.verify(pk, self.hash_d, proof):
            self.similar_proofs[id] = proof
            self.similar_proof_count += 1
        else:
            self.distinct_proofs[id] = proof

    def get_agg_proof(self):
        '''''
        Wait until timeout dt1 or all cluster members have sent their proofs.
        Then if more than half of the proofs are similar, aggregate them.
        '''
        while True:
            t1 = time.time()
            p_count = len(self.similar_proofs) + len(self.distinct_proofs)
            if t1 - self.t0 > dt1 or p_count == len(self.clusters[self.c_id]):
                break
        if p_count > len(self.clusters[self.c_id]) / 2:
            return PopSchemeMPL.aggregate(list(self.similar_proofs.values()))
        return None
    
    def set_agg_proof(self, id, pks, agg_proof):
        # TODO: timeout
        if agg_proof and PopSchemeMPL.fast_aggregate_verify(
            pks, self.hash_d, agg_proof):
            self.similar_agg_proofs[id] = agg_proof
            self.similar_proof_count += len(pks)
        else:
            self.distinct_agg_proofs[id] = agg_proof

    def set_verdict(self, agg_proof):
        self.verdict = agg_proof
        self.logger.log(f"Verdict: {agg_proof}")

    def listen(self):
        pass

    def notify_servers(self):
        # TODO: wait until proofs recievd
        if self.similar_proof_count > self.n / 2:
            for server_id in self.clusters[self.c_id]:
                self.edge_servers[server_id].set_verdict("FOUND")
        else:
            for server_id in self.clusters[self.c_id]:
                self.edge_servers[server_id].set_verdict(None)

    def reset(self):
        self.similar_proofs = {}
        self.distinct_proofs = {}
