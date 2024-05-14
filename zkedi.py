from Simulator import Simulator
import time

# Parameter settings
n = [10, 20, 30, 40, 50]
replica_scale = [10, 20, 30, 40, 50]
data_replica_size = [10, 20, 30, 40, 50]
corruption_rate = [0.1, 0.2, 0.3, 0.4]

times = []
for i in range(1):
    start = time.time()
    simulator = Simulator(n=512, data_replica_size=1024, corruption_rate=0.1)
    simulator.run()
    end = time.time()
    times.append(end-start)
print(f"Average time taken: {sum(times)/len(times)} seconds")