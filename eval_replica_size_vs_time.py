from Simulator import Simulator
import json

n_rounds = 100
rss = [64, 128, 256, 512, 1024]
dt1s = {64: 0.2, 128: 0.3, 256: 0.4, 512: 0.5, 1024: 1}

l_times = {}
g_times = {}
l_verdicts = {}
g_verdicts = {}
for rs in rss:
    l_times[rs] = []
    g_times[rs] = []
    l_verdicts[rs] = []
    g_verdicts[rs] = []
    for i in range(n_rounds):
        simulator = Simulator(replica_size=rs, dt1=dt1s[rs])
        metrics = simulator.run()
        l_times[rs].append(metrics['duration']['l_times'])
        g_times[rs].append(metrics['duration']['g_times'])
        l_verdicts[rs].append(metrics['integrity']['l_verdicts'])
        g_verdicts[rs].append(metrics['integrity']['g_verdicts'])

with open('eval/replica_size_vs_time.json', 'w') as f:
    json.dump({'l_times': l_times, 
               'g_times': g_times, 
               'l_verdicts': l_verdicts,
               'g_verdicts': g_verdicts}, f)