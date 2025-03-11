import os
import json
import time
from ediv_utils import ProGen


class EdgeServerForEDIV:
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
                self.run(client, parsed_msg["request"])
            elif parsed_msg['event'] == 'get_info':
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
        self.replica_size = init_config["replica_size"]
        self.block_size = init_config["block_size"]
        self.is_corrupted = init_config['is_corrupted']
        self.data_replica = b'\x00' * self.replica_size if self.is_corrupted else b'\x01' * self.replica_size
        self.proof_generated_in = None
        print(f'{self.get_current_time()} SERVER{self.id} initialized')

    def get_info(self, client):
        msg = json.dumps({"info": {"proof_generated_in": self.proof_generated_in, "is_corrupted": self.is_corrupted}, "from": f"SERVER{self.id}"})
        client.publish('APP_VENDOR', msg)
        print(f'{self.get_current_time()} Published message on topic "APP_VENDOR": {msg}')

    def run(self, client, request):
        print(f"{self.get_current_time()} Started EDI verification")
        self.t0 = time.time()
        # D_i = [self.data_replica[x:x + self.block_size] for x in range(0, self.replica_size, self.block_size)]
        proof = ProGen(request, self.data_replica, self.block_size) # Passing data replica instead of D_i for memory optimization
        self.proof_generated_in = time.time() - self.t0
        msg = json.dumps({"proof": proof, "from": f"SERVER{self.id}"})
        client.publish("APP_VENDOR", msg)
        print(f'{self.get_current_time()} Published message on topic "APP_VENDOR": {msg}')
