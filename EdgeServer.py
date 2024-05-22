import time
import threading
import random
import hashlib
import numpy as np
from blspy import (PrivateKey, AugSchemeMPL, PopSchemeMPL, G1Element, G2Element)
from Logger import Logger

class EdgeServer:
    def __init__(self, id, n, is_corrupted, data_replica, clusters, 
                 cluster_heads, latency_matrix, sp_queues, ap_queues, dt1, dt2, 
                 dt3, t1s, t2s, l_times, g_times, timed_out):
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
        self.sp_queues = sp_queues
        self.ap_queues = ap_queues
        self.dt1 = dt1
        self.dt2 = dt2
        self.dt3 = dt3
        self.t1s = t1s
        self.t2s = t2s
        self.l_times = l_times
        self.g_times = g_times
        self.timed_out = timed_out
        self.similar_proofs = {}
        self.distinct_proofs = {}
        self.similar_agg_proofs = {}
        self.distinct_agg_proofs = {}
        self.similar_proof_count = 0
        self.distinct_proof_count = 0
        self.generate_proof()

    def __str__(self):
        return f"EdgeServer {self.id}"

    def set_edge_servers(self, edge_servers):
        self.edge_servers = edge_servers
    
    def generate_proof(self):
        self.hash_d = bytes(hashlib.sha256(self.data_replica).digest())
        self.proof = PopSchemeMPL.sign(self.private_key, self.hash_d)
        self.similar_proofs[self.id] = self.proof
    
    def run(self):
        self.t0 = time.time()
        if self.is_cluster_head:
            self.logger.debug(f"Started as a {not self.is_corrupted} CH.")
            self.run_ch()
        else:
            self.logger.debug(f"Started as a {not self.is_corrupted} CM.")
            self.run_cm()   
    
    def run_cm(self):
        if not self.is_cluster_head:
            # self.edge_servers[self.ch_id].set_proof(self.id, self.proof)
            self.sp_queues[self.ch_id].put({"id": self.id, "proof": self.proof})

    def set_proof(self, id, proof):
        ### Waiting until this thread has been started.
        while not hasattr(self, 't0'):
            continue

        ### Simulate network latency, if latency < 0, the message is dropped
        ### assuming the faulty behaviour of the edge server.
        latency = self.latency_matrix[id][self.id]
        if latency >= 0:
            time.sleep(latency)
        else:
            return
        
        ### Verify the local single proof
        if (time.time() - self.t0) < (self.dt1 + self.dt2):
            if PopSchemeMPL.verify(self.edge_servers[id].public_key, 
                                   self.hash_d, proof):
                self.similar_proofs[id] = proof
            else:
                self.distinct_proofs[id] = proof
        else:
            self.timed_out[id] = True
            self.logger.debug(f"EdgeServer{id}'s proof timed out.")

    def run_ch(self):
        while (time.time() - self.t0) < self.dt1:
            if not self.queues[self.id].empty():
                proof = self.queues[self.id].get()
                if PopSchemeMPL.verify(self.edge_servers[id].public_key, self.hash_d, proof):
                    self.similar_proofs[id] = proof
                else:
                    self.distinct_proofs[id] = proof

        ### Wait until timeout dt1 or similar proof count is higher than 50%.
        ### Then if more than half of the proofs are similar, aggregate them.
        ### Otherwise, create empty aggregated proof.
        while True:
            dt = time.time() - self.t0
            if dt > self.dt1 or len(self.similar_proofs) > len(
                self.clusters[self.c_id])/2:
                self.t1s[self.id] = dt
                break
        # if len(self.similar_proofs) > len(self.clusters[self.c_id])/2:
        #     intra_agg_proof = PopSchemeMPL.aggregate(list(
        #         self.similar_proofs.values()))
        # else:
        #     intra_agg_proof = None
        # ids = self.similar_proofs.keys() if intra_agg_proof else []
        
        ### Send the agg_proof to other cluster heads and cluster members.
        # for c_id, ch_id in self.cluster_heads.items():
        #     if ch_id == self.id:
        #         self.similar_agg_proofs[self.id] = intra_agg_proof
        #         self.similar_proof_count += len(ids)
        #         continue
        #     threading.Thread(target=self.edge_servers[ch_id].set_agg_proof, 
        #                      args=(self.id, ids, intra_agg_proof,)).start()
        # for s_id in self.clusters[self.c_id]:
        #     threading.Thread(target=self.edge_servers[s_id].set_local_verdict, 
        #                      args=(ids, intra_agg_proof,)).start()
        
        ### Wait until timeout dt2 or similar proof count is higher than 50%.
        ### Then if more than half of the proofs are similar, aggregate them.
        ### Otherwise, get the mode of hash_d values and aggregate the proofs.
        # while True:
        #     if (time.time() - self.t0) > (self.dt1 + self.dt2) or (
        #         self.similar_proof_count > self.n/2):
        #         self.t2s[self.id] = time.time()-self.t0
        #         break

        # if self.similar_proof_count > self.n/2:
        #     print(self.id, "I ran", len(self.similar_agg_proofs))
        #     inter_agg_proof = PopSchemeMPL.aggregate([
        #         self.edge_servers[ch_id].proof 
        #         for ch_id in self.similar_agg_proofs.keys()])
        #     print(self.id, "I ran2", len(self.similar_agg_proofs))
        #     ids = self.similar_agg_proofs.keys() if inter_agg_proof else []
        #     hash_d = self.hash_d
        # else:
        #     while True:
        #         if time.time() - self.t0 > (self.dt1 + self.dt2 + self.dt3) or (
        #             self.distinct_proof_count > self.n/2):
        #             break

        #     # Simulate network latency to get the hash_d values from other
        #     # cluster heads. Thus, sleeping for the maximum latency of the
        #     # cluster heads.
        #     max_latency = max([self.latency_matrix[self.id][id] 
        #                        for id in self.cluster_heads.values()])
        #     time.sleep(max_latency)

        #     # Retrieve the hash_d values from other cluster heads. Then, get the
        #     # mode of hash_d values.
        #     hash_ds = [self.edge_servers[ch_id].hash_d 
        #                for ch_id in self.cluster_heads.values()]
        #     hash_d = max(set(hash_ds), key=hash_ds.count)

        #     # Verify the aggregated proofs of the cluster heads using hash_d.
        #     if self.distinct_proof_count > self.n/2:
        #         ids = []
        #         for id, (pks, agg_proof) in self.distinct_agg_proofs.items():
        #             if agg_proof and PopSchemeMPL.fast_aggregate_verify(
        #                 pks, hash_d, agg_proof):
        #                 ids.append(id)
        #         inter_agg_proof = PopSchemeMPL.aggregate([
        #             self.edge_servers[id].proof for id in ids])
        #         pks = [self.edge_servers[id].public_key for id in ids]
        #     else:
        #         print(self.id, self.similar_proof_count, self.distinct_proof_count)
        #         inter_agg_proof = None
        #         pks = []
        
        ### Send the aggregated proof along with hash_d to cluster members.
        # for s_id in self.clusters[self.c_id]:
        #     threading.Thread(target=self.edge_servers[s_id].set_global_verdict, 
        #                      args=(ids, inter_agg_proof, hash_d,)).start()

    def set_agg_proof(self, id, ids, agg_proof):
        ### Waiting until this thread has been started.
        while not hasattr(self, 't0'):
            continue

        ### Simulate network latency, if latency < 0, the message is dropped
        ### assuming the faulty behaviour of the edge server.
        latency = self.latency_matrix[id][self.id]
        if latency >= 0:
            time.sleep(latency)
        else:
            return
        
        ### Verify aggregated proofs
        if (time.time() - self.t0) < (self.dt1 + self.dt2):
            pks = [self.edge_servers[id].public_key for id in ids]
            if agg_proof and PopSchemeMPL.fast_aggregate_verify(
                pks, self.hash_d, agg_proof):
                self.similar_agg_proofs[id] = agg_proof
                self.similar_proof_count += len(pks)
            else:
                self.distinct_agg_proofs[id] = pks, agg_proof
                self.distinct_proof_count += len(pks)
        else:
            self.logger.debug(f"EdgeServer{id}'s agg_proof timed out.")
    
    def set_local_verdict(self, ids, agg_proof):
        ### Waiting until this thread has been started.
        while not hasattr(self, 't0'):
            continue

        ### Simulate network latency.
        latency = self.latency_matrix[self.ch_id][self.id]
        if latency >= 0:
            time.sleep(latency)
        
        ### Verify the local aggregated proof.
        if agg_proof:
            pks = [self.edge_servers[id].public_key for id in ids]
            self.local_verdict = PopSchemeMPL.fast_aggregate_verify(
                pks, self.hash_d, agg_proof)
            if self.local_verdict:
                self.l_times[self.id] = time.time()-self.t0
                self.logger.debug(f"""Local integrity reached in {(
                    self.l_times[self.id])}s.""")

    def set_global_verdict(self, ids, agg_proof, hash_d):
        # Waiting until this thread has been started.
        while not hasattr(self, 't0'):
            continue

        # Simulate network latency.
        latency = self.latency_matrix[self.ch_id][self.id]
        if latency >= 0:
            time.sleep(latency)

        # Verify the global aggregated proof
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
                self.logger.debug(f"""Global integrity reached in {(
                    self.g_times[self.id])}s.""")
            else:
                self.g_times[self.id] = 0
                self.logger.debug(f"Global integrity failed.")
        else:
            self.g_times[self.id] = 0
            self.logger.debug(f"Global integrity failed.")
