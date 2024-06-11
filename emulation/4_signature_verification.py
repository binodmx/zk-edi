import hashlib
import json
import random
import time
from blspy import AugSchemeMPL, PopSchemeMPL

n = 100
pks = []
signatures = []
data = bytes([0]*1024)
data_hash = hashlib.sha256(data).digest()
for i in range(n):
    seed = bytes([random.randint(0, 255) for _ in range(32)])
    sk = AugSchemeMPL.key_gen(seed)
    pks.append(sk.get_g1())
    signatures.append(PopSchemeMPL.sign(sk, data_hash))

signature_verification_times = {}
for i in range(n):
    signature_verification_times[i+1] = []
    agg_signature = AugSchemeMPL.aggregate(signatures[:i+1])
    for j in range(100):
        t = time.time()
        ok = PopSchemeMPL.fast_aggregate_verify(pks[:i+1], data_hash, 
                                                agg_signature)
        signature_verification_times[i+1].append(time.time() - t)

with open('4_signature_verification_times.json', 'w') as f:
    json.dump(signature_verification_times, f)