import random
import numpy as np
import math
from lib import Fuzzer
class PSO:
    #Each particle (or swarm) represents a list of probabilities for each function to be chosen
    def __init__(self, population, dimension, position_min, position_max, generation, fitness_function):
        self.population = population
        self.dimension = dimension
        self.position_min = position_min
        self.position_max = position_max
        self.generation = generation
        self.fitness_function = fitness_function 

    #particle: swarm position 
    #velocity: swarm velocity
    #pbest: local best
    #gbest: global best
    #w_min: minimum inertia
    #max: maximum inertia
    #c: cognitive and social influence (eg. how much pbest and gbest influence velocity)
    def update_velocity(self,particle, velocity, pbest, gbest, w_min=0.5, max=1.0, c=0.1):

        # Initialise new velocity array
        num_particle = len(particle)
        new_velocity = np.array([0.0 for i in range(num_particle)])
        # Randomly generate r1, r2 and inertia weight from normal distribution
        r1 = random.uniform(0,max)
        r2 = random.uniform(0,max)
        w = random.uniform(w_min,max)
        c1 = c
        c2 = c
        # Calculate new velocity
        for i in range(num_particle):
            new_velocity[i] = w*velocity[i] + c1*r1*(pbest[i]-particle[i])+c2*r2*(gbest[i]-particle[i])
        return new_velocity

    #updates position of particle after one unit of time
    def update_position(self,particle, velocity):
    # Move particles by adding velocity
        new_particle = particle + velocity
        return new_particle


    def run(self):
        # Initialisation
        # Population
        particles = [[random.uniform(self.position_min, self.position_max) for j in range(self.dimension)] for i in range(self.population)]
        
        # Particle's best position
        pbest_position = particles
        # Fitness
        pbest_fitness = [fitness_function(p) for p in particles]
        # Index of the best particle
        gbest_index = np.argmax(pbest_fitness)
        # Global best particle position
        self.gbest_position = pbest_position[gbest_index]
        # Velocity (starting from 0 speed)
        velocity = [[0.0 for j in range(self.dimension)] for i in range(self.population)]

        # Loop for the number of generation
        for t in range(self.generation):
        # Stop if the average fitness value reacpyted a predefined success criterion
            print("Current Generation: " + str(t))
            for n in range(self.population):
                # Update the velocity of each particle

                velocity[n] = self.update_velocity(particles[n], velocity[n], pbest_position[n], self.gbest_position)
                # Move the particles to new position
                particles[n] = self.update_position(particles[n], velocity[n])
            # Calculate the fitness value
            pbest_fitness = [fitness_function(p) for p in particles]
            # Find the index of the best particle
            gbest_index = np.argmax(pbest_fitness)
            # Update the position of the best particle
            gbest_position = pbest_position[gbest_index]
        print('Global Best Position: ', gbest_position)
        print('Best Fitness Value: ', min(pbest_fitness))
        print('Average Particle Best Fitness Value: ', np.average(pbest_fitness))
        print('Number of Generation: ', t)

#returns the swarm such that the sum of each probability adds to 1
def normalize(particle):
    total = 0
    for p in particle:
        total += p
    return [p/total for p in particle]

def fitness_function(particle):
    global pwd
    fuzzer = Fuzzer(
        pwd, seedFolder="./project_seed_q", defaultEpochs=1, runGetAesInput=True, p=normalize(particle)
    )
    fuzzer.mainLoop(1)
    return len(fuzzer.runner.pathQDict)

def shannon_diversity(species : dict):
    total = sum(dict.values())
    output = 0
    for key in species:
        p = species[key]/total
        output += math.log(p) * p
    return -output

def diversity_cost(particle):
    global pwd
    fuzzer = Fuzzer(
        pwd, seedFolder="./project_seed_q", defaultEpochs=1, runGetAesInput=True, p=normalize(particle)
    )
    fuzzer.pso_fuzz(1)
    pathDict = fuzzer.interestingMutatorSel
    return shannon_diversity(pathDict)

if __name__ == "__main__":
    import os
    pwd = os.path.dirname(os.path.abspath("LICENSE")) + "/project_testing"
    f = open("PSOLOGGER.txt", "w")
    import sys
    sys.stdout = f
    #Number of swarms to initialize
    population = 30
    #Dimensions = number of mutator functions
    dimension = 8
    #possible positions
    position_min = 1
    position_max = 100
    #iterations
    generation = 10
    #cost function taking in a swarm as input
    cost_function = diversity_cost
    
    pso = PSO(population, dimension, position_min, position_max, generation, cost_function)
    pso.run()

    print("Best Selection is " + str(normalize(pso.gbest_position)))
    f.close()

