import pandas as pd
import matplotlib.pyplot as plt

# read in the csv data as a Pandas DataFrame



df = pd.read_csv('project_testing/python/data_list.csv')

# extract the unix time and columns to plot
unix_time = df['unix_time']
cols_to_plot = ['failures', 'unique_paths', 'crashes' ,'iterations']

# plot each column in a separate subplot
fig, axes = plt.subplots(nrows=len(cols_to_plot), ncols=1, figsize=(10,10))
for i, col in enumerate(cols_to_plot):
    axes[i].plot(unix_time, df[col])
    axes[i].set_xlabel('Unix Time')
    axes[i].set_ylabel(col)
plt.savefig("project_testing/python/random_fuzzer.png")

