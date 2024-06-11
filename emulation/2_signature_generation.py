import hashlib
import json
import random
import time
from blspy import AugSchemeMPL, PopSchemeMPL

seed = bytes([random.randint(0, 255) for _ in range(32)])
sk = AugSchemeMPL.key_gen(seed)
pk = sk.get_g1()
data = bytes([0]*1024)
data_hash = hashlib.sha256(data).digest()

signature_generation_times = []
for i in range(100):
    t = time.time()
    signature = PopSchemeMPL.sign(sk, data_hash)
    signature_generation_times.append(time.time() - t)

with open('2_signature_generation_times.json', 'w') as f:
    json.dump(signature_generation_times, f)