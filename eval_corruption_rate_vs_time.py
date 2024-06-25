from Simulator import Simulator
import json

n_rounds = 100
crs = [0, 0.05, 0.1, 0.15, 0.2]

l_times = {}
g_times = {}
l_verdicts = {}
g_verdicts = {}
for cr in crs:
    l_times[cr] = []
    g_times[cr] = []
    l_verdicts[cr] = []
    g_verdicts[cr] = []
    for i in range(n_rounds):
        simulator = Simulator(corruption_rate=cr)
        metrics = simulator.run()
        l_times[cr].append(metrics['duration']['l_times'])
        g_times[cr].append(metrics['duration']['g_times'])
        l_verdicts[cr].append(metrics['integrity']['l_verdicts'])
        g_verdicts[cr].append(metrics['integrity']['g_verdicts'])

with open('eval/corruption_rate_vs_time.json', 'w') as f:
    json.dump({'l_times': l_times, 
               'g_times': g_times, 
               'l_verdicts': l_verdicts, 
               'g_verdicts': g_verdicts}, f)