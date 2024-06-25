from Simulator import Simulator
import json

n_rounds = 100
cms = ["RecursiveSpectralClustering", "SpectralClustering", "RandomClustering", "Broadcasting", "Unicasting"]

l_times = {}
g_times = {}
l_verdicts = {}
g_verdicts = {}
for cm in cms:
    l_times[cm] = []
    g_times[cm] = []
    l_verdicts[cm] = []
    g_verdicts[cm] = []
    for i in range(n_rounds):
        if cm == "Broadcasting":
            simulator = Simulator(n_clusters=100)
        elif cm == "Unicasting":
            simulator = Simulator(n_clusters=1)
        else:
            simulator = Simulator(cluster_method=cm)
        metrics = simulator.run()
        l_times[cm].append(metrics['duration']['l_times'])
        g_times[cm].append(metrics['duration']['g_times'])
        l_verdicts[cm].append(metrics['integrity']['l_verdicts'])
        g_verdicts[cm].append(metrics['integrity']['g_verdicts'])

with open('eval/cluster_method_vs_time.json', 'w') as f:
    json.dump({'l_times': l_times, 
               'g_times': g_times, 
               'l_verdicts': l_verdicts, 
               'g_verdicts': g_verdicts}, f)