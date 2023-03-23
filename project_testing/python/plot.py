import pandas as pd
import matplotlib.pyplot as plt

# read in the csv data as a Pandas DataFrame



df = pd.read_csv('project_testing/python/data_list.csv')

# extract the unix time and columns to plot
unix_time = df['unix_time']
time = unix_time-unix_time[0]
cols_to_plot = ['failures', 'unique_paths', 'crashes' ,'iterations']
titles = ['failures', 'unique_paths', 'run_time_crashes' ,'fuzzed_inputs']
# plot each column in a separate subplot
fig, axes = plt.subplots(nrows=len(cols_to_plot), ncols=1, figsize=(10,10))
for i, col in enumerate(cols_to_plot):
    axes[i].plot(time, df[col])
    axes[i].set_xlabel('Time in s')
    axes[i].set_ylabel(col)
    axes[i].set_title(titles[i])
fig.tight_layout()
plt.savefig("project_testing/python/random_fuzzer.png")

