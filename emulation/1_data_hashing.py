import hashlib
import json
import time

data_blocks = []
for i in range(16):
    data_blocks.append(bytes([i]*1024*1024*64))

data_hashing_times = {}
replica_sizes = [64, 128, 256, 512, 1024]
for replica_size in replica_sizes:
    data = b''.join(data_blocks[:replica_size//64])
    data_hashing_times[replica_size] = []
    for i in range(100):
        t = time.time()
        data_hash = hashlib.sha256(data).digest()
        data_hashing_times[replica_size].append(time.time() - t)

with open('1_data_hashing_times.json', 'w') as f:
    json.dump(data_hashing_times, f)