from Simulator import Simulator
import json
import time

n_rounds = 100
n = 100
ncs = range(1, n+1)

l_times = {}
g_times = {}
l_verdicts = {}
g_verdicts = {}
for nc in ncs:
    l_times[nc] = []
    g_times[nc] = []
    l_verdicts[nc] = []
    g_verdicts[nc] = []
    start = time.time()
    for i in range(n_rounds):
        simulator = Simulator(edge_scale=n, n_clusters=nc)
        metrics = simulator.run()
        l_times[nc].append(metrics['duration']['l_times'])
        g_times[nc].append(metrics['duration']['g_times'])
        l_verdicts[nc].append(metrics['integrity']['l_verdicts'])
        g_verdicts[nc].append(metrics['integrity']['g_verdicts'])
    print(f"Time taken to run nc {nc} is {time.time() - start}s")

with open('eval/nclusters_vs_success_rate.json', 'w') as f:
    json.dump({'l_times': l_times, 
               'g_times': g_times, 
               'l_verdicts': l_verdicts, 
               'g_verdicts': g_verdicts}, f)