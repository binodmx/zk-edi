import time
import threading
from queue import Empty
from blspy import PopSchemeMPL

class EdgeServer(threading.Thread):
    def __init__(self, id, n, replica_scale, is_corrupted, server_type, hash_ds, 
                 private_key, public_keys, proof, c_id, clusters, ch_id, 
                 cluster_heads, latency_matrix, ss_queue, sp_queues, ap_queues, 
                 lv_queues, gv_queues, dt1, dt2, dt3, t1s, t2s, l_times, 
                 g_times, data_hashing_delay, hash_signing_delay, 
                 proof_aggregation_delays, proof_verification_delays):
        threading.Thread.__init__(self)
        self.id = id
        self.n = n
        self.replica_scale = replica_scale
        self.is_corrupted = is_corrupted
        self.server_type = server_type
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
        self.similar_proofs = [{self.id: self.proof} 
                               for _ in range(self.replica_scale)]
        self.distinct_proofs = [{} for _ in range(self.replica_scale)]
        self.similar_agg_proofs = [{} for _ in range(self.replica_scale)]
        self.distinct_agg_proofs = [{} for _ in range(self.replica_scale)]
        self.similar_proof_count = [0 for _ in range(self.replica_scale)]
        self.distinct_proof_count = [0 for _ in range(self.replica_scale)]
        self.data_hashing_delay = data_hashing_delay
        self.hash_signing_delay = hash_signing_delay
        self.proof_aggregation_delays = proof_aggregation_delays
        self.proof_verification_delays = proof_verification_delays
        self.local_verdicts = {}
        self.global_verdicts = {}

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

        # Start the thread as a cluster head or cluster member.
        if self.is_cluster_head:
            self.run_ch()
        else:
            self.run_cm()   

    ############################################################################
    # Cluster Member Methods
    ############################################################################

    def run_cm(self):
        for i in range(self.replica_scale):
            # Send proofs to the cluster head.
            threading.Thread(target=self.send_proof_to_cluster_head, 
                             args=(i,)).start()
            
            # Listen to local proofs until t2 (dt1+dt2).
            threading.Thread(target=self.listen_to_local_verdicts, 
                             args=(i,)).start()
            
            # Listen to global proofs from until t3 (dt1+dt2+dt3).
            threading.Thread(target=self.listen_to_global_verdicts, 
                             args=(i,)).start() 

    def send_proof_to_cluster_head(self, i):
        # Add delay to simulate the data hashing and signing process.
        time.sleep(self.data_hashing_delay + self.hash_signing_delay)
        
        # Simulate network latency, if latency < 0, the message is dropped
        # assuming the malicious behaviour of the edge server.
        latency = self.latency_matrix[self.id][self.ch_id]
        if latency >= 0:
            time.sleep(latency)
            self.sp_queues[self.ch_id][i].put({"id": self.id, 
                                               "proof": self.proof})

    def listen_to_local_verdicts(self, i):
        while (time.time() - self.t0) < self.dt1+self.dt2 and self.lv_queues[self.id][i].empty():
            time.sleep(0.0001)
        lv = self.lv_queues[self.id][i].get()
        latency = self.latency_matrix[self.ch_id][self.id]
        if latency >= 0:
            time.sleep(latency)
        if lv["agg_proof"]:
            pks = [self.public_keys[id] for id in lv["ids"]]
            time.sleep(self.proof_verification_delays[str(len(pks))]["avg"])
            self.local_verdicts[i] = PopSchemeMPL.fast_aggregate_verify(
                pks, self.hash_d, lv["agg_proof"])
            if self.local_verdicts[i]:
                self.l_times[self.id][i] = time.time() - self.t0

    def listen_to_global_verdicts(self, i):
        try:
            gv = self.gv_queues[self.id][i].get(timeout=self.dt1+self.dt2+self.dt3)
        except Empty:
            gv = {"agg_proof": None}
        latency = self.latency_matrix[self.ch_id][self.id]
        if latency >= 0:
            time.sleep(latency)
        if gv["agg_proof"]:
            pks = [self.public_keys[id] for id in gv["ids"]]
            time.sleep(self.proof_verification_delays[str(len(pks))]["avg"])
            # Using same replica for multiple rounds to simulate replica scale.
            # Thus, the hash_d value is same for all replicas.
            if self.hash_d == gv["hash_d"]:
                self.global_verdicts[i] = PopSchemeMPL.fast_aggregate_verify(
                    pks, self.hash_d, gv["agg_proof"])
            else:
                self.global_verdicts[i] = PopSchemeMPL.fast_aggregate_verify(
                    pks, gv["hash_d"], gv["agg_proof"])
            if self.global_verdicts[i]:
                self.g_times[self.id][i] = time.time() - self.t0
            else:
                # If cluster head provided proof cannot be verified, edge server
                # contacts app vendor as the fallback mechanism.
                print("cluster head provided proof cannot be verified")
                self.g_times[self.id][i] = 0.5
        else:
            # If cluster head is unable to provide a proof, then edge server
            # contacts app vendor as the fallback mechanism.
            print("cluster head is unable to provide a proof")
            self.g_times[self.id][i] = 0.5

    ############################################################################
    # Cluster Head Methods
    ############################################################################

    def run_ch(self):
        for i in range(self.replica_scale):
            threading.Thread(target=self.verify_local_proofs, 
                             args=(i,)).start()
            
            threading.Thread(target=self.send_agg_proofs, 
                             args=(i,)).start()
            
            threading.Thread(target=self.verify_agg_proofs, 
                             args=(i,)).start()
            
            threading.Thread(target=self.send_global_verdicts, 
                             args=(i,)).start()    

    def verify_local_proofs(self, i):
        while (time.time() - self.t0) < self.dt1 and len(
            self.similar_proofs[i]) <= len(self.clusters[self.c_id])/2:
            if not self.sp_queues[self.id][i].empty():
                sp = self.sp_queues[self.id][i].get()
                time.sleep(self.proof_verification_delays["1"]["avg"])
                ok = PopSchemeMPL.verify(self.public_keys[sp["id"]], 
                                         self.hash_d, sp["proof"])
                if ok:
                    self.similar_proofs[i][sp["id"]] = sp["proof"]
                else:
                    self.distinct_proofs[i][sp["id"]] = sp["proof"]
            time.sleep(0.0001)
        self.t1s[self.id][i] = time.time() - self.t0

    def send_agg_proofs(self, i):
        while (time.time() - self.t0) < self.dt1 and len(
            self.similar_proofs[i]) <= len(self.clusters[self.c_id])/2:
            time.sleep(0.0001)
        
        # If more than half of the proofs are similar, aggregate them.
        # Otherwise, create empty aggregated proof.
        if len(self.similar_proofs[i]) > len(self.clusters[self.c_id])/2:
            time.sleep(self.proof_aggregation_delays[str(len(
                self.similar_proofs[i]))]["avg"])
            intra_agg_proof = PopSchemeMPL.aggregate(list(
                self.similar_proofs[i].values()))
            self.local_verdicts[i] = True
            self.l_times[self.id][i] = time.time() - self.t0
        else:
            intra_agg_proof = None
        ids = self.similar_proofs[i].keys() if intra_agg_proof else []
        
        # Send the agg_proof to other cluster heads.
        for ch_id in self.cluster_heads.values():
            if ch_id == self.id:
                self.similar_agg_proofs[i][self.id] = {
                    "id": self.id, 
                    "proof": self.proof,
                    "ids": ids,
                    "agg_proof": intra_agg_proof}
                self.similar_proof_count[i] += len(ids)
                continue
            data = {"id": self.id, 
                    "proof": self.proof, 
                    "ids": ids, 
                    "agg_proof": intra_agg_proof}
            threading.Thread(target=self.send_agg_proofs_to_cluster_heads, 
                             args=(ch_id, i, data)).start()
        
        # Send the agg_proof to other cluster members as local integrity.
        for s_id in self.clusters[self.c_id]:
            data = {"ids": ids, "agg_proof": intra_agg_proof}
            self.send_local_verdicts(s_id, i, data)
            
    def send_agg_proofs_to_cluster_heads(self, ch_id, i, data):
        latency = self.latency_matrix[self.id][ch_id]
        if latency >= 0:
            time.sleep(latency)
        self.ap_queues[ch_id][i].put(data)

    def send_local_verdicts(self, s_id, i, data):
        self.lv_queues[s_id][i].put(data)
        
    def verify_agg_proofs(self, i):
        while ((time.time() - self.t0) < self.dt1+self.dt2) and (
            self.similar_proof_count[i] <= self.n/2):
            if not self.ap_queues[self.id][i].empty():
                ap = self.ap_queues[self.id][i].get()
                pks = [self.public_keys[id] for id in ap["ids"]]
                if ap["agg_proof"] and PopSchemeMPL.fast_aggregate_verify(
                    pks, self.hash_d, ap["agg_proof"]):
                    time.sleep(self.proof_verification_delays[str(len(pks))]["avg"])
                    self.similar_agg_proofs[i][ap["id"]] = ap
                    self.similar_proof_count[i] += len(pks)
                else:
                    self.distinct_agg_proofs[i][ap["id"]] = ap
                    self.distinct_proof_count[i] += len(pks)
            time.sleep(0.0001)
        self.t2s[self.id][i] = time.time() - self.t0

    def send_global_verdicts(self, i):
        while (time.time() - self.t0) < self.dt1 + self.dt2 and (
            self.similar_proof_count[i] <= self.n/2):
            time.sleep(0.0001)
        
        if self.similar_proof_count[i] > self.n/2:
            time.sleep(self.proof_aggregation_delays[str(len(
                self.similar_agg_proofs[i]))]["avg"])
            inter_agg_proof = PopSchemeMPL.aggregate(
                [self.similar_agg_proofs[i][ch_id]["proof"] 
                 for ch_id in self.similar_agg_proofs[i].keys()])
            ids = self.similar_agg_proofs[i].keys()
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
            for ap in self.distinct_agg_proofs[i].values():
                pks = [self.public_keys[id] for id in ap["ids"]]
                if ap["agg_proof"] and PopSchemeMPL.fast_aggregate_verify(
                    pks, hash_d, ap["agg_proof"]):
                    time.sleep(self.proof_verification_delays[str(len(pks))]["avg"])
                    ids.append(ap["id"])
                    sp_count += len(pks)
            if sp_count > self.n/2:
                time.sleep(self.proof_aggregation_delays[str(len(
                    self.distinct_agg_proofs))]["avg"])
                inter_agg_proof = PopSchemeMPL.aggregate(
                    [self.distinct_agg_proofs[i][id]["proof"] for id in ids])
            else:
                inter_agg_proof = None
        
        # Send the agg_proof to other cluster members as global verdict.
        for s_id in self.clusters[self.c_id]:
            self.gv_queues[s_id][i].put({"ids": ids, 
                                         "agg_proof": inter_agg_proof, 
                                         "hash_d": hash_d})
        
        # Set global verdict.
        if inter_agg_proof:
            self.global_verdicts[i] = True
            self.g_times[self.id][i] = time.time() - self.t0
