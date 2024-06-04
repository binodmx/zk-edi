import time
import numpy as np
import threading
from blspy import PopSchemeMPL
from Logger import Logger

class EdgeServer(threading.Thread):
    def __init__(self, id, n, is_corrupted, hash_ds, private_key, public_keys, 
                 proof, c_id, clusters, ch_id, cluster_heads, latency_matrix, 
                 ss_queue, sp_queues, ap_queues, lv_queues, gv_queues, dt1, dt2, 
                 dt3, t1s, t2s, l_times, g_times, timed_out):
        threading.Thread.__init__(self)
        self.id = id
        self.n = n
        self.is_corrupted = is_corrupted
        self.hash_d = hash_ds[id]
        self.hash_ds = hash_ds
        self.private_key = private_key
        self.public_key = public_keys[id]
        self.public_keys = public_keys
        self.proof = proof
        self.clusters = clusters
        self.cluster_heads = cluster_heads
        self.c_id = c_id
        self.ch_id = ch_id
        self.is_cluster_head = self.ch_id == self.id
        self.latency_matrix = latency_matrix
        self.ss_queue = ss_queue
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
        # TODO: set delays
        self.data_hashing_delay = 0
        self.hash_signing_delay = 0
        self.proof_verifying_delay = 0
        self.logger = Logger(self)

    def __str__(self):
        return f"EdgeServer {self.id}"
    
    def run(self):
        # Wait until all threads are initialized. This is done because Python
        # thread initialization takes much time.
        self.ss_queue.put(self.id)
        while self.ss_queue.qsize() < self.n:
            time.sleep(0.0001)
        
        # Set the start time of the thread to measure the elapsed time.
        self.t0 = time.time()

        if self.is_cluster_head:
            self.logger.debug(f"Started as a {not self.is_corrupted} CH.")
            self.run_ch()
        else:
            self.logger.debug(f"Started as a {not self.is_corrupted} CM.")
            self.run_cm()   
    
    def run_cm(self):
        # Add delay to simulate the data hashing and signing process.
        time.sleep(self.data_hashing_delay + self.hash_signing_delay)

        # Send the proof to the cluster head.
        if not self.is_cluster_head:
            # Simulate network latency, if latency < 0, the message is dropped
            # assuming the malicious behaviour of the edge server.
            latency = self.latency_matrix[self.id][self.ch_id]
            if latency >= 0:
                time.sleep(latency)
                self.sp_queues[self.ch_id].put({"id": self.id, 
                                                "proof": self.proof})

        # Listen to local proof from the cluster head until t2 (dt1+dt2).
        lv = self.lv_queues[self.id].get(timeout=(self.dt1 + self.dt2))
        latency = self.latency_matrix[self.ch_id][self.id]
        if latency >= 0:
            time.sleep(latency)
        if lv["agg_proof"]:
            pks = [self.public_keys[id] for id in lv["ids"]]
            time.sleep(self.proof_verifying_delay)
            self.local_verdict = PopSchemeMPL.fast_aggregate_verify(
                pks, self.hash_d, lv["agg_proof"])
            if self.local_verdict:
                self.l_times[self.id] = time.time()-self.t0
                self.logger.debug(f"""Local integrity reached in {(
                    self.l_times[self.id])}s.""")
                
        # Listen to global proof from the cluster head until t3 (dt1+dt2+dt3).
        gv = self.gv_queues[self.id].get(timeout=(self.dt1+self.dt2+self.dt3))
        latency = self.latency_matrix[self.ch_id][self.id]
        if latency >= 0:
            time.sleep(latency)
        if gv["agg_proof"]:
            pks = [self.public_keys[id] for id in gv["ids"]]
            time.sleep(self.proof_verifying_delay)
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
                if self.g_times[self.id] > 1:
                    print(f"id={self.id} and is_corrupted={self.is_corrupted}")
            else:
                # If cluster head provided proof cannot be verified, edge server
                # contacts app vendor as the fallback mechanism.
                self.g_times[self.id] = 0.5
                self.logger.debug(f"Global integrity failed.")
        else:
            # If cluster head is unable to provide a proof, then edge server
            # contacts app vendor as the fallback mechanism.
            self.g_times[self.id] = 0.5
            self.logger.debug(f"Global integrity failed.")

    def run_ch(self):
        # Listen to the proofs from the cluster members until t1.
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

        # If more than half of the proofs are similar, aggregate them.
        # Otherwise, create empty aggregated proof.
        if len(self.similar_proofs) > len(self.clusters[self.c_id])/2:
            intra_agg_proof = PopSchemeMPL.aggregate(list(
                self.similar_proofs.values()))
            self.local_verdict = True
            self.l_times[self.id] = time.time()-self.t0
            self.logger.debug(f"""Local integrity reached in {(
                self.l_times[self.id])}s.""")
        else:
            intra_agg_proof = None
        ids = self.similar_proofs.keys() if intra_agg_proof else []
        
        # Send the agg_proof to other cluster heads.
        for ch_id in self.cluster_heads.values():
            if ch_id == self.id:
                self.similar_agg_proofs[self.id] = {"id": self.id, 
                                                    "proof": self.proof,
                                                    "ids": ids,
                                                    "agg_proof": intra_agg_proof
                                                    }
                self.similar_proof_count += len(ids)
                continue
            self.ap_queues[ch_id].put({"id": self.id, 
                                       "proof": self.proof,
                                       "ids": ids,
                                       "agg_proof": intra_agg_proof})
        
        # Send the agg_proof to other cluster members as local integrity.
        for s_id in self.clusters[self.c_id]:
            self.lv_queues[s_id].put({"ids": ids, "agg_proof": intra_agg_proof})                

        # Listen to the agg_proofs from the cluster heads until t2.
        while ((time.time() - self.t0) < self.dt1+self.dt2) and (
            self.similar_proof_count <= self.n/2):
            if not self.ap_queues[self.id].empty():
                ap = self.ap_queues[self.id].get()
                pks = [self.public_keys[id] for id in ap["ids"]]
                time.sleep(self.proof_verifying_delay)
                if ap["agg_proof"] and PopSchemeMPL.fast_aggregate_verify(
                    pks, self.hash_d, ap["agg_proof"]):
                    self.similar_agg_proofs[ap["id"]] = ap
                    self.similar_proof_count += len(pks)
                else:
                    self.distinct_agg_proofs[ap["id"]] = ap
                    self.distinct_proof_count += len(pks)
            time.sleep(0.0001)
        self.t2s[self.id] = time.time() - self.t0
        
        if self.similar_proof_count > self.n/2:
            inter_agg_proof = PopSchemeMPL.aggregate(
                [self.similar_agg_proofs[ch_id]["proof"] 
                 for ch_id in self.similar_agg_proofs.keys()])
            ids = self.similar_agg_proofs.keys()
            hash_d = self.hash_d
        else:
            # Simulate network latency to get the hash_d values from other
            # cluster heads. Thus, sleeping for the maximum latency of the
            # cluster heads.
            max_latency = max([self.latency_matrix[self.id][id] 
                               for id in self.cluster_heads.values()])
            time.sleep(max_latency)

            # Retrieve the hash_d values from other cluster heads. Then, get the
            # mode of hash_d values.
            hash_ds = [self.hash_ds[ch_id] 
                       for ch_id in self.cluster_heads.values()]
            hash_d = max(set(hash_ds), key=hash_ds.count)

            # Verify the aggregated proofs of the cluster heads using hash_d.
            ids = []
            sp_count = 0
            for ap in self.distinct_agg_proofs.values():
                pks = [self.public_keys[id] for id in ap["ids"]]
                time.sleep(self.proof_verifying_delay)
                if ap["agg_proof"] and PopSchemeMPL.fast_aggregate_verify(
                    pks, hash_d, ap["agg_proof"]):
                    ids.append(ap["id"])
                    sp_count += len(pks)
            if sp_count > self.n/2:
                inter_agg_proof = PopSchemeMPL.aggregate(
                    [self.distinct_agg_proofs[id]["proof"] for id in ids])
            else:
                inter_agg_proof = None
        
        # Send the agg_proof to other cluster members as global integrity.
        for s_id in self.clusters[self.c_id]:
            self.gv_queues[s_id].put({"ids": ids, "agg_proof": inter_agg_proof, 
                                      "hash_d": hash_d})
        
        # Set global integrity.
        if inter_agg_proof:
            self.global_verdict = True
            self.g_times[self.id] = time.time() - self.t0
            self.logger.debug(f"""Global integrity reached in {(
                self.g_times[self.id])}s.""")
