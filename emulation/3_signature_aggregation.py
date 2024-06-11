import hashlib
import json
import random
import time
from blspy import AugSchemeMPL, PopSchemeMPL

n = 100
signatures = []
data = bytes([0]*1024)
data_hash = hashlib.sha256(data).digest()
for i in range(n):
    seed = bytes([random.randint(0, 255) for _ in range(32)])
    sk = AugSchemeMPL.key_gen(seed)
    signatures.append(PopSchemeMPL.sign(sk, data_hash))

signature_aggregation_times = {}
for i in range(n):
    signature_aggregation_times[i+1] = []
    for j in range(100):
        t = time.time()
        agg_signature = PopSchemeMPL.aggregate(signatures[:i+1])
        signature_aggregation_times[i+1].append(time.time() - t)

with open('3_signature_aggregation_times.json', 'w') as f:
    json.dump(signature_aggregation_times, f)