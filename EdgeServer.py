import time
import random
import hashlib
import numpy as np
from blspy import (PrivateKey, AugSchemeMPL, PopSchemeMPL, G1Element, G2Element)
from Logger import Logger

class EdgeServer:
    def __init__(self, id, n, is_corrupted, data_replica, clusters, 
                 cluster_heads, latency_matrix, sp_queues, ap_queues, lv_queues, 
                 gv_queues, dt1, dt2, dt3, t1s, t2s, l_times, g_times, timed_out):
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
        self.hash_d = bytes(hashlib.sha256(self.data_replica).digest())
        self.proof = PopSchemeMPL.sign(self.private_key, self.hash_d)
        self.clusters = clusters
        self.cluster_heads = cluster_heads
        self.c_id, self.ch_id = next(((c_id, cluster_heads[c_id])
                                  for c_id, servers in clusters.items() 
                                  if self.id in servers), None)
        self.is_cluster_head = self.ch_id == self.id
        self.latency_matrix = latency_matrix
        self.sp_queues = sp_queues
        self.ap_queues = ap_queues
        self.lv_queues = lv_queues
        self.gv_queues = gv_queues
        self.dt1 = dt1
        self.dt2 = dt2
        self.dt3 = dt3
        self.t1s = t1s
        self.t2s = t2s
        self.l_times = l_times
        self.g_times = g_times
        self.timed_out = timed_out
        self.similar_proofs = {self.id: self.proof}
        self.distinct_proofs = {}
        self.similar_agg_proofs = {}
        self.distinct_agg_proofs = {}
        self.similar_proof_count = 0
        self.distinct_proof_count = 0

    def __str__(self):
        return f"EdgeServer {self.id}"

    def set_public_keys(self, public_keys):
        self.public_keys = public_keys
    
    def set_hash_ds(self, hash_ds):
        self.hash_ds = hash_ds
    
    def run(self):
        if self.is_cluster_head:
            self.logger.debug(f"Started as a {not self.is_corrupted} CH.")
            self.run_ch()
        else:
            self.logger.debug(f"Started as a {not self.is_corrupted} CM.")
            self.run_cm()   
    
    def run_cm(self):
        ### Set the start time of the thread to measure the elapsed time.
        self.t0 = time.time()

        ### Send the proof to the cluster head.
        if not self.is_cluster_head:
            ### Simulate network latency, if latency < 0, the message is dropped
            ### assuming the faulty behaviour of the edge server.
            latency = self.latency_matrix[self.id][self.ch_id]
            if latency >= 0:
                time.sleep(latency)
                self.sp_queues[self.ch_id].put({"id": self.id, 
                                                "proof": self.proof})

        ### Listens to the local proof from the cluster head until t2.
        lv = self.lv_queues[self.id].get(timeout=(self.dt1 + self.dt2))
        latency = self.latency_matrix[self.ch_id][self.id]
        if latency >= 0:
            time.sleep(latency)
        if lv["agg_proof"]:
            pks = [self.public_keys[id] for id in lv["ids"]]
            self.local_verdict = PopSchemeMPL.fast_aggregate_verify(
                pks, self.hash_d, lv["agg_proof"])
            if self.local_verdict:
                self.l_times[self.id] = time.time()-self.t0
                self.logger.debug(f"""Local integrity reached in {(
                    self.l_times[self.id])}s.""")
                
        ### Listens to the global proof from the cluster head until t3.
        gv = self.gv_queues[self.id].get(timeout=(self.dt1 + self.dt2 + self.dt3))
        latency = self.latency_matrix[self.ch_id][self.id]
        if latency >= 0:
            time.sleep(latency)
        if gv["agg_proof"]:
            pks = [self.public_keys[id] for id in gv["ids"]]
            if self.hash_d == gv["hash_d"]:
                self.global_verdict = PopSchemeMPL.fast_aggregate_verify(
                    pks, self.hash_d, gv["agg_proof"])
            else:
                self.global_verdict = PopSchemeMPL.fast_aggregate_verify(
                    pks, gv["hash_d"], gv["agg_proof"])
            if self.global_verdict:
                self.g_times[self.id] = time.time() - self.t0
                self.logger.debug(f"""Global integrity reached in {(
                    self.g_times[self.id])}s.""")
            ### TODO: remove following parts after checking code
            else:
                self.g_times[self.id] = 0
                self.logger.debug(f"Global integrity failed.")
        else:
            self.g_times[self.id] = -2
            self.logger.debug(f"Global integrity failed.")

    def run_ch(self):
        ### Wait until first proof is received from the cluster members. This
        ### is done because Python thread initialization takes much time.
        if len(self.clusters[self.c_id]) > 1:
            while self.sp_queues[self.id].empty():
                time.sleep(0.0001)
        self.t0 = time.time()

        ### Listens to the proofs from the cluster members until t1.
        while (time.time() - self.t0) < self.dt1 and len(
            self.similar_proofs) <= len(self.clusters[self.c_id])/2:
            if not self.sp_queues[self.id].empty():
                sp = self.sp_queues[self.id].get()
                ok = PopSchemeMPL.verify(self.public_keys[sp["id"]], 
                                         self.hash_d, sp["proof"])
                if ok:
                    self.similar_proofs[sp["id"]] = sp["proof"]
                else:
                    self.distinct_proofs[sp["id"]] = sp["proof"]
            time.sleep(0.0001)
        self.t1s[self.id] = time.time() - self.t0

        ### If more than half of the proofs are similar, aggregate them.
        ### Otherwise, create empty aggregated proof.
        if len(self.similar_proofs) > len(self.clusters[self.c_id])/2:
            intra_agg_proof = PopSchemeMPL.aggregate(list(
                self.similar_proofs.values()))
            self.local_verdict = True
            self.l_times[self.id] = time.time()-self.t0
            self.logger.debug(f"""Local integrity reached in {(self.l_times[self.id])}s.""")
        else:
            intra_agg_proof = None
        ids = self.similar_proofs.keys() if intra_agg_proof else []
        
        ### Send the agg_proof to other cluster heads.
        for ch_id in self.cluster_heads.values():
            if ch_id == self.id:
                self.similar_agg_proofs[self.id] = {"id": self.id, 
                                                    "proof": self.proof,
                                                    "ids": ids,
                                                    "agg_proof": intra_agg_proof}
                self.similar_proof_count += len(ids)
                continue
            self.ap_queues[ch_id].put({"id": self.id, 
                                       "proof": self.proof,
                                       "ids": ids,
                                       "agg_proof": intra_agg_proof})
        
        ### Send the agg_proof to other cluster members as local integrity.
        for s_id in self.clusters[self.c_id]:
            self.lv_queues[s_id].put({"ids": ids, "agg_proof": intra_agg_proof})                

        ### Listens to the agg proofs from the cluster heads until t2.
        while (time.time() - self.t0) < self.dt1+self.dt2 and self.similar_proof_count <= self.n/2:
            if not self.ap_queues[self.id].empty():
                ap = self.ap_queues[self.id].get()
                pks = [self.public_keys[id] for id in ap["ids"]]
                if ap["agg_proof"] and PopSchemeMPL.fast_aggregate_verify(pks, self.hash_d, ap["agg_proof"]):
                    self.similar_agg_proofs[ap["id"]] = ap
                    self.similar_proof_count += len(pks)
                else:
                    self.distinct_agg_proofs[ap["id"]] = ap
                    self.distinct_proof_count += len(pks)
            time.sleep(0.0001)
        self.t2s[self.id] = time.time() - self.t0
        
        if self.similar_proof_count > self.n/2:
            inter_agg_proof = PopSchemeMPL.aggregate([self.similar_agg_proofs[ch_id]["proof"] for ch_id in self.similar_agg_proofs.keys()])
            ids = self.similar_agg_proofs.keys()
            hash_d = self.hash_d
        else:
            # Simulate network latency to get the hash_d values from other
            # cluster heads. Thus, sleeping for the maximum latency of the
            # cluster heads.
            # max_latency = max([self.latency_matrix[self.id][id] 
            #                    for id in self.cluster_heads.values()])
            # time.sleep(max_latency)

            # Retrieve the hash_d values from other cluster heads. Then, get the
            # mode of hash_d values.
            hash_ds = [self.hash_ds[ch_id] for ch_id in self.cluster_heads.values()]
            hash_d = max(set(hash_ds), key=hash_ds.count)

            ### Verify the aggregated proofs of the cluster heads using hash_d.
            ids = []
            sp_count = 0
            for ap in self.distinct_agg_proofs.values():
                pks = [self.public_keys[id] for id in ap["ids"]]
                if ap["agg_proof"] and PopSchemeMPL.fast_aggregate_verify(pks, hash_d, ap["agg_proof"]):
                    ids.append(ap["id"])
                    sp_count += len(pks)
            if sp_count > self.n/2:
                inter_agg_proof = PopSchemeMPL.aggregate([self.distinct_agg_proofs[id]["proof"] for id in ids])
            else:
                inter_agg_proof = None
        
        ### Send the agg_proof to other cluster members as global integrity.
        for s_id in self.clusters[self.c_id]:
            self.gv_queues[s_id].put({"ids": ids, "agg_proof": inter_agg_proof, 
                                      "hash_d": hash_d})
        
        ### Set global integrity.
        if inter_agg_proof:
            pks = [self.public_keys[id] for id in ids]
            self.global_verdict = PopSchemeMPL.fast_aggregate_verify(pks, hash_d, inter_agg_proof)
            if self.global_verdict:
                self.g_times[self.id] = time.time() - self.t0
                self.logger.debug(f"""Global integrity reached in {(self.g_times[self.id])}s.""")
            
    # Deprecated
    def set_edge_servers(self, edge_servers):
        self.edge_servers = edge_servers

    # Deprecated
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

    # Deprecated
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
    
    # Deprecated
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

    # Deprecated
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
