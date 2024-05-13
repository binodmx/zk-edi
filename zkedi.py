from Simulator import Simulator

# Parameter settings
n = [10, 20, 30, 40, 50]
replica_scale = [10, 20, 30, 40, 50]
data_replica_size = [10, 20, 30, 40, 50]
corruption_rate = [0.1, 0.2, 0.3, 0.4]

simulator = Simulator(n=10,
                      data_replica_size=10, 
                      corruption_rate=0.1)

simulator.run()
