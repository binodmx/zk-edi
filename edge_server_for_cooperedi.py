import os
import json
import time
import threading
import random
import hashlib
import math


class EdgeServerForCOOPEREDI:
    def __init__(self):
        self.id = int(os.getenv("SERVER_ID"))
        print(f'{self.get_current_time()} SERVER{self.id} started')

    @staticmethod
    def get_current_time():
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))

    def process_message(self, client, message):
        try:
            parsed_msg = json.loads(message)
            if parsed_msg["event"] == "init":
                self.initialize_server(parsed_msg["init_config"])
            elif parsed_msg["event"] == "run":
                self.run(client)
            elif parsed_msg["event"] == "ground_truth_request":
                threading.Thread(target=self.ground_truth_response, args=(client, parsed_msg)).start()
            elif parsed_msg["event"] == "ground_truth_response":
                threading.Thread(target=self.ground_truth_consensus, args=(client, parsed_msg)).start()
            elif parsed_msg["event"] == "data_inspection":
                self.loc_corrupted_data_blocks(parsed_msg)
            elif parsed_msg["event"] == "get_info":
                self.get_info(client)
            else:
                print(f'{self.get_current_time()} Unknown task: {parsed_msg["event"]}')
        except (json.JSONDecodeError, KeyError) as e:
            print(f'{self.get_current_time()} Invalid input!')
            print(e)
            return
        except Exception as e:
            print(f'{self.get_current_time()} Encountered server error!')
            print(e)
            return

    def initialize_server(self, init_config):
        self.n = init_config["n"]
        self.data_equivalent = {}
        self.is_manager = False
        self.found_manager = False
        self.digest = None
        self.digests = []
        self.valid_state = {}
        self.verified = False
        self.verified_in = None
        self.block_size = init_config["block_size"]
        self.replica_size = init_config["replica_size"]
        self.is_corrupted = init_config['is_corrupted']
        self.replica_id = 0
        self.replica = b'\x00' * self.replica_size if self.is_corrupted else b'\x01' * self.replica_size
        self.dt1 = init_config["dt1"]
        self.dt2 = init_config["dt2"]
        print(f'{self.get_current_time()} SERVER{self.id} initialized')

    def get_info(self, client):
        msg = json.dumps(
            {"info": {"verified": self.verified, "verified_in": self.verified_in, "is_manager": self.is_manager, "is_corrupted": self.is_corrupted},
             "from": f"SERVER{self.id}"})
        client.publish("APP_VENDOR", msg)
        print(f'{self.get_current_time()} Published message on topic "APP_VENDOR": {msg}')

    def run(self, client):
        print(f"{self.get_current_time()} Started EDI verification")
        self.t0 = time.time()
        time.sleep(random.uniform(0, self.dt1))
        self.ground_truth_request(client)

    def ground_truth_request(self, client):
        self.digest = hashlib.sha256(self.replica).digest().hex()
        for i in range(self.n):
            if i != self.id:
                msg = json.dumps({"event": "ground_truth_request", "replica_id": self.replica_id,
                                  "digest": self.digest, "from": f"SERVER{self.id}"})
                threading.Thread(target=client.publish, args=(f'SERVER{i}', msg)).start()

    def ground_truth_response(self, client, request):
        if self.found_manager:
            return
        data_equivalent = self.digest == request["digest"]
        msg = json.dumps({"event": "ground_truth_response", "replica_id": request["replica_id"],
                          "data_equivalent": data_equivalent, "from": f"SERVER{self.id}"})
        client.publish(request["from"], msg)
        # print(f'{self.get_current_time()} Published message on topic "{request["from"]}": {msg}')

    def ground_truth_consensus(self, client, response):
        if self.found_manager:
            return
        if response["data_equivalent"]:
            self.data_equivalent[response["from"]] = True
        if len(self.data_equivalent) >= math.ceil((self.n + 1) / 2):
            self.is_manager = True
            self.verified = True
            self.verified_in = time.time() - self.t0
            self.gen_inspection(client)

    def gen_inspection(self, client):
        for i in range(self.n):
            if i == self.id:
                continue
            is_corrupted = not self.data_equivalent.get(f"SERVER{i}", False)
            if is_corrupted:
                if len(self.digests) == 0:
                    # data_blocks = [self.replica[x:x + self.block_size] for x in
                    #                range(0, self.replica_size, self.block_size)]
                    # for data_block in data_blocks:
                    #     self.digests.append(hashlib.sha256(data_block).digest().hex())
                    # Using indices for memory optimization
                    for x in range(int(self.replica_size/self.block_size)):
                        self.digests.append(hashlib.sha256(self.replica[x*self.block_size:x*self.block_size+self.block_size]).digest().hex())
                msg = json.dumps({"event": "data_inspection", "replica_id": self.replica_id,
                                "is_corrupted": is_corrupted, "digests": self.digests, "from": f"SERVER{self.id}"})
            else:
                msg = json.dumps({"event": "data_inspection", "replica_id": self.replica_id,
                                "is_corrupted": is_corrupted, "from": f"SERVER{self.id}"})
            threading.Thread(target=client.publish, args=(f'SERVER{i}', msg)).start()

    def loc_corrupted_data_blocks(self, message):
        if self.verified:
            return
        self.found_manager = True
        if message["is_corrupted"]:
            # data_blocks = [self.replica[x:x + self.block_size] for x in range(0, self.replica_size, self.block_size)]
            # for x, data_block in enumerate(data_blocks):
            #     self.valid_state[x] = hashlib.sha256(data_block).digest().hex() == message["digests"][x]
            # Using indices for memory optimization
            for x in range(int(self.replica_size/self.block_size)):
                self.valid_state[x] = hashlib.sha256(self.replica[x*self.block_size:x*self.block_size+self.block_size]).digest().hex() == message["digests"][x]
            self.verified = True
            self.verified_in = time.time() - self.t0
        else:
            self.verified = True
            self.verified_in = time.time() - self.t0
