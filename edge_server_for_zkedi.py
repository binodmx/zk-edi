import os
import json
import time
import threading
import random
import hashlib
from blspy import AugSchemeMPL, PopSchemeMPL, PrivateKey, G1Element, G2Element


class EdgeServerForZKEDI:
    def __init__(self):
        self.id = int(os.getenv("SERVER_ID"))
        self.rtt_dict = {}
        self.ping_dict = {}
        print(f'{self.get_current_time()} SERVER{self.id} started')

    @staticmethod
    def get_current_time():
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

    def process_message(self, client, message):
        try:
            parsed_msg = json.loads(message)
            if parsed_msg['event'] == 'init':
                self.initialize_server(parsed_msg['init_config'])
            elif parsed_msg['event'] == 'ping_all':
                threading.Thread(target=self.ping_all, args=(client, parsed_msg['n'])).start()
            elif parsed_msg['event'] == 'ping':
                self.ping(client, parsed_msg['from'])
            elif parsed_msg['event'] == 'pong':
                self.pong(parsed_msg['from'])
            elif parsed_msg['event'] == 'get_rtt_dict':
                self.get_rtt_dict(client)
            elif parsed_msg['event'] == 'run':
                threading.Thread(target=self.run, args=(client,)).start()
            elif parsed_msg['event'] == 'verify_proof':
                threading.Thread(target=self.verify_proof, args=(parsed_msg,)).start()
            elif parsed_msg['event'] == 'verify_local_verdict':
                threading.Thread(target=self.verify_local_verdict, args=(parsed_msg,)).start()
            elif parsed_msg['event'] == 'verify_global_verdict':
                self.verify_global_verdict(parsed_msg)
            elif parsed_msg['event'] == 'get_data_hash':
                threading.Thread(target=self.get_data_hash, args=(client, parsed_msg['from'])).start()
            elif parsed_msg['event'] == 'set_data_hash':
                threading.Thread(target=self.set_data_hash, args=(parsed_msg,)).start()
            elif parsed_msg['event'] == 'get_info':
                self.get_info(client)
            else:
                print(f'{self.get_current_time()} Unknown event: {parsed_msg["event"]}')
        except (json.JSONDecodeError, KeyError) as e:
            print(f'{self.get_current_time()} Invalid input!')
            print(e)
            return
        except Exception as e:
            print(f'{self.get_current_time()} Encountered server error!')
            print(e)
            return

    def initialize_server(self, init_config):
        self.n = init_config['n']
        self.replica_size = init_config['replica_size']
        self.is_corrupted = init_config['is_corrupted']
        self.private_key = PrivateKey.from_bytes(bytes.fromhex(init_config['private_key']))
        self.public_keys = [G1Element.from_bytes(bytes.fromhex(pk)) for pk in init_config['public_keys']]
        self.public_key = self.public_keys[self.id]
        self.data_replica = b'\x00' * self.replica_size if self.is_corrupted else b'\x01' * self.replica_size
        self.data_hash = hashlib.sha256(self.data_replica).digest()
        self.data_hashes = {self.id: self.data_hash}
        self.proof = None
        self.clusters = {int(k): v for k, v in init_config['clusters'].items()}
        self.cluster_heads = {int(k): v for k, v in init_config['cluster_heads'].items()}
        self.c_id = init_config['c_id']
        self.ch_id = init_config['ch_id']
        self.is_cluster_head = self.ch_id == self.id
        self.t0 = None
        self.dt1 = init_config['dt1']
        self.dt2 = init_config['dt2']
        self.dt3 = init_config['dt3']
        self.similar_cm_proofs = {}
        self.distinct_cm_proofs = {}
        self.similar_ch_proofs = {}
        self.distinct_ch_proofs = {}
        self.ch_sp_count = {}
        self.similar_proof_count = 1
        self.distinct_proof_count = 0
        self.lv_verified = False
        self.lv_verified_in = None
        self.gv_verified = False
        self.gv_verified_in = None
        self.debug_log = None
        print(f'{self.get_current_time()} SERVER{self.id} initialized')
    
    def get_info(self, client):
        msg = json.dumps({"info": {"lv_verified": self.lv_verified, "lv_verified_in": self.lv_verified_in,
                                   "gv_verified": self.gv_verified, "gv_verified_in": self.gv_verified_in, 
                                   "is_corrupted": self.is_corrupted, "debug_log": self.debug_log},
                          "from": f"SERVER{self.id}"})
        client.publish('APP_VENDOR', msg)
        print(f'{self.get_current_time()} Published message on topic "APP_VENDOR": {msg}')

    def ping_all(self, client, n):
        for i in range(n):
            if i != self.id:
                msg = json.dumps({"event": "ping", "from": f"SERVER{self.id}"})
                self.ping_dict[f'SERVER{i}'] = time.time()
                client.publish(f'SERVER{i}', msg)
                time.sleep(1)

    def ping(self, client, server):
        msg = json.dumps({"event": "pong", "from": f"SERVER{self.id}"})
        client.publish(server, msg)

    def pong(self, server):
        self.rtt_dict[server] = time.time() - self.ping_dict[server]

    def get_rtt_dict(self, client):
        msg = json.dumps({"rtt_dict": self.rtt_dict, "from": f"SERVER{self.id}"})
        client.publish('APP_VENDOR', msg)

    def run(self, client):
        print(f"{self.get_current_time()} Started EDI verification")
        self.t0 = time.time()
        self.send_proof_to_cluster_head(client)
        if self.is_cluster_head:
            while (time.time() - self.t0) < self.dt1 and len(self.similar_cm_proofs) <= len(
                    self.clusters[self.c_id]) / 2:
                time.sleep(0.001)
            self.send_local_verdict(client)
            while (time.time() - self.t0) < self.dt1 + self.dt2 and self.similar_proof_count <= self.n / 3:
                time.sleep(0.001)
            self.send_global_verdict(client)

    def send_proof_to_cluster_head(self, client):
        self.proof = PopSchemeMPL.sign(self.private_key, self.data_hash)
        self.similar_cm_proofs[self.id] = self.proof
        if not self.is_cluster_head:
            msg = json.dumps({"event": "verify_proof", "proof": bytes(self.proof).hex(), "from": f"SERVER{self.id}"})
            client.publish(f'SERVER{self.ch_id}', msg)
            # print(f'{self.get_current_time()} Published message on topic "SERVER{self.ch_id}": {msg}')

    def verify_proof(self, msg):
        if (time.time() - self.t0) < self.dt1:
            id = int(msg["from"][6:])
            proof = G2Element.from_bytes(bytes.fromhex(msg["proof"]))
            ok = PopSchemeMPL.verify(self.public_keys[id], self.data_hash, proof)
            if ok:
                self.similar_cm_proofs[id] = proof
            else:
                self.distinct_cm_proofs[id] = proof

    def send_local_verdict(self, client):
        # If more than half of the proofs are similar, aggregate them. Otherwise, create empty aggregated proof
        if len(self.similar_cm_proofs) > len(self.clusters[self.c_id]) / 2:
            intra_agg_proof = PopSchemeMPL.aggregate([proof for proof in self.similar_cm_proofs.values()])
            self.lv_verified = True
            self.lv_verified_in = time.time() - self.t0
        else:
            intra_agg_proof = None
        ids = list(self.similar_cm_proofs.keys()) if intra_agg_proof else []
        self.similar_ch_proofs[self.id] = self.proof
        self.similar_proof_count += len(ids)

        # Send the agg_proof to cluster members and other cluster heads as local verdict
        lv_msg = json.dumps(
            {"event": "verify_local_verdict", "from": f"SERVER{self.id}", "proof": bytes(self.proof).hex(), "ids": ids,
             "agg_proof": bytes(intra_agg_proof).hex() if intra_agg_proof else intra_agg_proof})
        for s_id in self.clusters[self.c_id]:
            if s_id == self.id:
                continue
            client.publish(f'SERVER{s_id}', lv_msg)
            # print(f'{self.get_current_time()} Published message on topic "SERVER{s_id}": {lv_msg}')
        for ch_id in self.cluster_heads.values():
            if ch_id == self.id:
                continue
            client.publish(f'SERVER{ch_id}', lv_msg)
            # print(f'{self.get_current_time()} Published message on topic "SERVER{ch_id}": {lv_msg}')

    def verify_local_verdict(self, msg):
        if (time.time() - self.t0) < self.dt1 + self.dt2:
            pks = [self.public_keys[id] for id in msg["ids"]]
            ok = msg["agg_proof"] and PopSchemeMPL.fast_aggregate_verify(pks, self.data_hash, G2Element.from_bytes(
                bytes.fromhex(msg["agg_proof"])))
            if self.is_cluster_head:
                if ok:
                    self.similar_ch_proofs[int(msg["from"][6:])] = G2Element.from_bytes(bytes.fromhex(msg["proof"]))
                    self.similar_proof_count += len(pks)
                else:
                    self.distinct_ch_proofs[int(msg["from"][6:])] = G2Element.from_bytes(bytes.fromhex(msg["proof"]))
                    self.distinct_proof_count += len(pks)
                self.ch_sp_count[int(msg["from"][6:])] = len(pks)
            else:
                if ok:
                    self.lv_verified = True
                    self.lv_verified_in = time.time() - self.t0

    def send_global_verdict(self, client):
        # If more than one third of the proofs are similar, aggregate them. Otherwise, create empty aggregated proof
        if self.similar_proof_count > self.n / 3:
            inter_agg_proof = PopSchemeMPL.aggregate([proof for proof in self.similar_ch_proofs.values()])
            ids = list(self.similar_ch_proofs.keys())
            data_hash = self.data_hash
            self.gv_verified = True
            self.gv_verified_in = time.time() - self.t0
        else:
            # Retrieve the data hashes from other cluster heads
            msg = json.dumps({"event": "get_data_hash", "from": f"SERVER{self.id}"})
            for ch_id in self.cluster_heads.values():
                if ch_id == self.id:
                    continue
                client.publish(f'SERVER{ch_id}', msg)
                # print(f'{self.get_current_time()} Published message on topic "SERVER{ch_id}": {msg}')
            while (time.time() - self.t0) < self.dt1 + self.dt2 + self.dt3 and len(self.data_hashes.keys()) < len(
                    self.clusters.keys()) / 2:
                time.sleep(0.001)
            # Get the mode of hash_d values.
            data_hashes = list(self.data_hashes.values())
            data_hash = max(set(data_hashes), key=data_hashes.count)
            # Verify the aggregated proofs of the cluster heads using data_hash
            ids = []
            sp_count = 0
            ch_proofs = self.similar_ch_proofs | self.distinct_ch_proofs
            for id, proof in ch_proofs.items():
                ok = proof and PopSchemeMPL.verify(self.public_keys[id], data_hash, proof)
                if ok:
                    ids.append(id)
                    sp_count += self.ch_sp_count.get(id, 0)
            if sp_count > self.n / 3:
                inter_agg_proof = PopSchemeMPL.aggregate([ch_proofs[id] for id in ids])
                self.gv_verified = True
                self.gv_verified_in = time.time() - self.t0
            else:
                inter_agg_proof = None
        # Send the agg_proof to cluster members as global verdict
        gv_msg = json.dumps(
            {"event": "verify_global_verdict", "from": f"SERVER{self.id}", "ids": ids,
             "agg_proof": bytes(inter_agg_proof).hex() if inter_agg_proof else inter_agg_proof,
             "data_hash": data_hash.hex()})
        for s_id in self.clusters[self.c_id]:
            if s_id == self.id:
                continue
            client.publish(f'SERVER{s_id}', gv_msg)
            # print(f'{self.get_current_time()} Published message on topic "SERVER{s_id}": {gv_msg}')

    def verify_global_verdict(self, msg):
        if (time.time() - self.t0) < self.dt1 + self.dt2 + self.dt3:
            pks = [self.public_keys[id] for id in msg["ids"]]
            if self.data_hash.hex() == msg["data_hash"]:
                ok = msg["agg_proof"] and PopSchemeMPL.fast_aggregate_verify(pks, self.data_hash, G2Element.from_bytes(
                    bytes.fromhex(msg["agg_proof"])))
            else:
                ok = PopSchemeMPL.fast_aggregate_verify(pks, bytes.fromhex(msg["data_hash"]),
                                                        G2Element.from_bytes(bytes.fromhex(msg["agg_proof"])))
            if ok:
                self.gv_verified = True
                self.gv_verified_in = time.time() - self.t0
            else:
                # If cluster head provided proof cannot be verified, ES contacts AV as the fallback mechanism
                self.gv_verified = True
                self.gv_verified_in = self.dt1 + self.dt2 + self.dt3 + 0.5
                self.debug_log = 'Cluster head provided proof cannot be verified'
                # print(f'{self.get_current_time()} Cluster head provided proof cannot be verified')
        else:
            # If cluster head is unable to provide a proof, then ES contacts AV as the fallback mechanism
            self.gv_verified = True
            self.gv_verified_in = self.dt1 + self.dt2 + self.dt3 + 0.5
            self.debug_log = 'Cluster head is unable to provide a proof'
            # print(f'{self.get_current_time()} Cluster head is unable to provide a proof')

    def get_data_hash(self, client, server):
        msg = json.dumps({"event": "set_data_hash", "data_hash": self.data_hash.hex(), "from": f"SERVER{self.id}"})
        client.publish(server, msg)
        # print(f'{self.get_current_time()} Published message on topic "{server}": {msg}')

    def set_data_hash(self, msg):
        self.data_hashes[int(msg["from"][6:])] = bytes.fromhex(msg["data_hash"])
