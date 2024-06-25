from Simulator import Simulator
import json

n_rounds = 100
ns = [10, 20, 50, 100, 200]
dt2s = {10: 0.1, 20: 0.2, 50: 0.3, 100: 0.4, 200: 0.5}

l_times = {}
g_times = {}
l_verdicts = {}
g_verdicts = {}
for n in ns:
    l_times[n] = []
    g_times[n] = []
    l_verdicts[n] = []
    g_verdicts[n] = []
    for i in range(n_rounds):
        simulator = Simulator(edge_scale=n, dt2=dt2s[n])
        metrics = simulator.run()
        l_times[n].append(metrics['duration']['l_times'])
        g_times[n].append(metrics['duration']['g_times'])
        l_verdicts[n].append(metrics['integrity']['l_verdicts'])
        g_verdicts[n].append(metrics['integrity']['g_verdicts'])

with open('eval/edge_scale_vs_time.json', 'w') as f:
    json.dump({'l_times': l_times, 
               'g_times': g_times, 
               'l_verdicts': l_verdicts, 
               'g_verdicts': g_verdicts}, f)
