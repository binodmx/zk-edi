from Simulator import Simulator
import json

n_rounds = 100

l_times = []
g_times = []
l_verdicts = []
g_verdicts = []
for i in range(n_rounds):
    simulator = Simulator()
    metrics = simulator.run()
    l_times.append(metrics['duration']['l_times'])
    g_times.append(metrics['duration']['g_times'])
    l_verdicts.append(metrics['integrity']['l_verdicts'])
    g_verdicts.append(metrics['integrity']['g_verdicts'])

with open('eval/local_global_time_comparison.json', 'w') as f:
    json.dump({'l_times': l_times, 
               'g_times': g_times, 
               'l_verdicts': l_verdicts, 
               'g_verdicts': g_verdicts}, f)
