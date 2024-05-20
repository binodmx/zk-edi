import time
import threading
import random
import hashlib
import numpy as np
from Logger import Logger
from blspy import (PrivateKey, AugSchemeMPL, PopSchemeMPL, G1Element, G2Element)

class EdgeServer:
    def __init__(self, id, n, is_corrupted, data_replica,  clusters, 
                 cluster_heads, latency_matrix, dt1, dt2):
        self.id = id
        self.logger = Logger(self)
        self.n = n
        self.is_corrupted = is_corrupted
        if is_corrupted:
            self.data_replica = data_replica[:-5] + bytes([0, 0, 0, 0, 0])
        else:
            self.data_replica = data_replica
        self.private_key: PrivateKey = AugSchemeMPL.key_gen(bytes(
            [random.randint(0, 255) for i in range(32)]))
        self.public_key: G1Element = self.private_key.get_g1()
        self.clusters = clusters
        self.cluster_heads = cluster_heads
        self.c_id, self.ch_id = next(((c_id, cluster_heads[c_id])
                                  for c_id, servers in clusters.items() 
                                  if self.id in servers), None)
        self.is_cluster_head = self.ch_id == self.id
        self.latency_matrix = latency_matrix
        self.dt1 = dt1
        self.dt2 = dt2

        # Python does not have a lock-free ConcurrentHashMap implementation
        # due to Global Interpreter Lock (GIL). However, we can use a simple
        # dictionary as a lock-free alternative due to GIL.
        self.similar_proofs = {}
        self.distinct_proofs = {}
        self.similar_agg_proofs = {}
        self.distinct_agg_proofs = {}
        self.similar_proof_count = 0
        self.generate_proof()

    def __str__(self):
        return f"EdgeServer {self.id}"

    def set_edge_servers(self, edge_servers):
        self.edge_servers = edge_servers
    
    def generate_proof(self):
        self.hash_d = bytes(hashlib.sha256(self.data_replica).digest())
        self.proof = PopSchemeMPL.sign(self.private_key, self.hash_d)
        self.similar_proofs[self.id] = self.proof
    
    def run(self, l_times, g_times, timed_out):
        self.l_times = l_times
        self.g_times = g_times
        self.timed_out = timed_out
        self.t0 = time.time()
        if self.is_cluster_head:
            self.logger.log(f"Started as a {not self.is_corrupted} CH.")
            self.run_ch()
        else:
            self.logger.log(f"Started as a {not self.is_corrupted} CM.")
            self.run_cm()   
    
    def run_cm(self):
        if not self.is_cluster_head:
            self.edge_servers[self.ch_id].set_proof(self.id, self.proof)

    def run_ch(self):
        # Wait until timeout dt1 or all cluster members have sent their proof.
        # Then if more than half of the proofs are similar, aggregate them.
        while True:
            p_count = len(self.similar_proofs) + len(self.distinct_proofs)
            if time.time() - self.t0 > self.dt1 or p_count == len(
                self.clusters[self.c_id]):
                break
        if len(self.similar_proofs) > len(self.clusters[self.c_id])/2:
            intra_agg_proof = PopSchemeMPL.aggregate(list(
                self.similar_proofs.values()))
        else:
            intra_agg_proof = None
        ids = self.similar_proofs.keys() if intra_agg_proof else []
        
        # Send the aggregated proof to other cluster heads and cluster members.
        for c_id, ch_id in self.cluster_heads.items():
            if ch_id == self.id:
                self.similar_agg_proofs[self.id] = intra_agg_proof
                self.similar_proof_count += len(ids)
                continue
            threading.Thread(target=self.edge_servers[ch_id].set_agg_proof, 
                             args=(self.id, ids, intra_agg_proof,)).start()
        for s_id in self.clusters[self.c_id]:
            threading.Thread(target=self.edge_servers[s_id].set_local_verdict, 
                             args=(ids, intra_agg_proof,)).start()
        
        # Wait until timeout dt2 or all cluster heads have sent their agg_proof.
        # Then if more than half of the proofs are similar, aggregate them.
        # Otherwise, get the mode of hash_d values and aggregate the proofs.
        while True:
            p_count = len(self.similar_agg_proofs) 
            + len(self.distinct_agg_proofs)
            if time.time() - self.t0 > self.dt1 + self.dt2 or p_count == len(
                self.cluster_heads):
                break
        if self.similar_proof_count > self.n/2:
            inter_agg_proof = PopSchemeMPL.aggregate([
                self.edge_servers[ch_id].proof 
                for ch_id in self.similar_agg_proofs.keys()])
            ids = self.similar_agg_proofs.keys() if inter_agg_proof else []
            hash_d = self.hash_d
        else:
            hash_ds = [self.edge_servers[ch_id].hash_d 
                       for ch_id in self.cluster_heads.values()]
            hash_d = max(set(hash_ds), key=hash_ds.count)
            ids = []
            for id, (pks, agg_proof) in self.distinct_agg_proofs.items():
                if agg_proof and PopSchemeMPL.fast_aggregate_verify(pks, hash_d, 
                                                                    agg_proof):
                    ids.append(id)
            inter_agg_proof = PopSchemeMPL.aggregate([
                self.edge_servers[id].proof for id in ids])            
        
        # Send the aggregated proof to cluster members.
        for s_id in self.clusters[self.c_id]:
            threading.Thread(target=self.edge_servers[s_id].set_global_verdict, 
                             args=(ids, inter_agg_proof, hash_d,)).start()

    def set_proof(self, id, proof):
        while not hasattr(self, 't0'):
            continue
        # Simulate network latency, if latency < 0, the message is dropped
        # assuming the faulty behaviour of the edge server.
        latency = self.latency_matrix[id][self.id]
        if latency >= 0:
            time.sleep(latency)
        else:
            return
        if time.time() - self.t0 < self.dt1 + self.dt2:
            if PopSchemeMPL.verify(self.edge_servers[id].public_key, 
                                   self.hash_d, proof):
                self.similar_proofs[id] = proof
            else:
                self.distinct_proofs[id] = proof
        else:
            self.timed_out[id] = True
            self.logger.log(f"EdgeServer{id}'s proof timed out.")
    
    def set_agg_proof(self, id, ids, agg_proof):
        while not hasattr(self, 't0'):
            continue
        # Simulate network latency, if latency < 0, the message is dropped
        # assuming the faulty behaviour of the edge server.
        latency = self.latency_matrix[id][self.id]
        if latency >= 0:
            time.sleep(latency)
        else:
            return
        if time.time() - self.t0 < self.dt1 + self.dt2:
            pks = [self.edge_servers[id].public_key for id in ids]
            if agg_proof and PopSchemeMPL.fast_aggregate_verify(
                pks, self.hash_d, agg_proof):
                self.similar_agg_proofs[id] = agg_proof
                self.similar_proof_count += len(pks)
            else:
                self.distinct_agg_proofs[id] = pks, agg_proof
        else:
            self.logger.log(f"EdgeServer{id}'s agg_proof timed out.")
    
    def set_local_verdict(self, ids, agg_proof):
        latency = self.latency_matrix[self.ch_id][self.id]
        if latency >= 0:
            time.sleep(latency)
        if agg_proof:
            pks = [self.edge_servers[id].public_key for id in ids]
            self.local_verdict = PopSchemeMPL.fast_aggregate_verify(
                pks, self.hash_d, agg_proof)
            if self.local_verdict:
                self.l_times[self.id] = time.time()-self.t0
                self.logger.log(f"""Local integrity reached in {(
                    self.l_times[self.id])*1000}ms.""")

    def set_global_verdict(self, ids, agg_proof, hash_d):
        latency = self.latency_matrix[self.ch_id][self.id]
        if latency >= 0:
            time.sleep(latency)
        if agg_proof:
            pks = [self.edge_servers[id].public_key for id in ids]
            if self.hash_d == hash_d:
                self.global_verdict = PopSchemeMPL.fast_aggregate_verify(
                    pks, self.hash_d, agg_proof)
            else:
                self.global_verdict = PopSchemeMPL.fast_aggregate_verify(
                    pks, hash_d, agg_proof)
            if self.global_verdict:
                self.g_times[self.id] = time.time()-self.t0
                self.logger.log(f"""Global integrity reached in {(
                    self.g_times[self.id])*1000}ms.""")
