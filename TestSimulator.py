from Simulator import Simulator

simulator = Simulator(n_servers=5)
similarity_matrix = simulator.get_similarity_matrix(100)
clusters = simulator.get_clusters(similarity_matrix, 5)
print(clusters)