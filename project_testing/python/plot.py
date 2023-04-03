import pandas as pd
import matplotlib.pyplot as plt
import pandas as pd 
import os
import pickle

def getSnapshotCsv(dumpfile:str):
    with open(dumpfile, "rb") as f:
        inputs = pickle.load(f)
    hashList: list = inputs[0]
    seedQDict: dict = inputs[1]
    pathQDict: dict = inputs[2]
    pathFrequency: dict = inputs[3]
    failedPathHashLs: list = inputs[4]
    crashPathHashLs: list = inputs[5]
    seedQCov: dict = inputs[6]
    seedFreq: dict = inputs[7]
    # pprint.pprint(pathQDict)
    seedQLs = []
    pathQLs = []
    pathFrequencyLs = []
    seedCovLs = []
    seedFreqLs = []
    isFail = [] 
    isCrash = []
    for i in hashList:
        seedQLs.append(seedQDict[i])
        pathQLs.append(pathQDict[i])
        pathFrequencyLs.append(pathFrequency[i])
        seedCovLs.append(seedQCov[i])
        seedFreqLs.append(seedFreq[i])
        if i in failedPathHashLs:
            isFail.append(True)
        else: 
            isFail.append(False)
        if i in crashPathHashLs:
            isCrash.append(True)
        else:
            isCrash.append(False)
    df = pd.DataFrame([
        seedQLs,pathFrequencyLs,seedCovLs,seedFreqLs,isFail,isCrash
    ])
    df = df.transpose()
    # print(hashList)

    df.columns = [
        "Seed Input",
        "Path Frequency",
        "Path Code Coverage",
        "Seed Frequency",
        "Fail Path",
        "Crash Path"
    ]
    df.index = hashList
    df.to_csv("project_testing/python/dumpCrashBreakdown.csv")


def average_csv_files_s(file_paths,output_path):
    file_dfs = []
    for i in file_paths:
        file_dfs.append(pd.read_csv(i))
    
    columns = file_dfs[0].columns
    min_rows = []
    for i in file_dfs:
        # update unix time to s from start
        i['unix_time'] = i['unix_time'] - i['unix_time'][0]
        min_rows.append(i.shape[0])
    min_row_index = min(min_rows)
    
    


    averages_df = pd.DataFrame(
        columns=list(columns[1:])
    )
    print(averages_df);
    column_index_range = len(columns)
    for row_index in range(min_row_index):
        row_averages = []
        # Filter out the first 1 columns since we don't need to calculate average index
        for column_index in range(1, column_index_range):
            cells = []
            for df in file_dfs:
                cell_value = (
                    df.iloc[row_index, column_index]
                    if column_index < df.shape[1]
                    else 0
                )
                cells.append(cell_value)
            row_averages.append(sum(cells) / len(file_dfs))
        averages_df.loc[row_index] = row_averages
    print(averages_df.head())
    averages_df.to_csv(output_path, index=False)



if __name__ == '__main__':

    # read the dumpfile 
    getSnapshotCsv('project_testing/python/dumpCrash.pkl')



    # PREP PLOT DATA
    path = "project_testing/python/plot_data/"
    listop = os.listdir(path)
    for index,file in enumerate(listop):
        listop[index] = path+file 
    print(listop)
    average_csv_files_s(listop,"project_testing/python/data_list.csv")




    # USING PREP DATA to get the time to find first crash.
    df = pd.read_csv('project_testing/python/data_list.csv')
    unix_time = df['unix_time']
    for ind,i in enumerate(df['failures']):
        if i > 0:
            time_out = unix_time[ind]
            break
    with open("project_testing/python/time_to_first_crash",'w') as f:
        f.write(str(time_out))

    # PLOT
    # read in the csv data as a Pandas DataFrame
    df = pd.read_csv('project_testing/python/data_list.csv')

    # extract columns to plot
    cols_to_plot = ['failures', 'unique_paths', 'crashes' ,'iterations','code_coverage']
    titles = ['failures', 'unique_paths', 'run_time_crashes' ,'fuzzed_inputs','code_coverage']
    # plot each column in a separate subplot
    fig, axes = plt.subplots(nrows=len(cols_to_plot), ncols=1, figsize=(10,10))
    for i, col in enumerate(cols_to_plot):
        axes[i].plot(unix_time, df[col])
        axes[i].set_xlabel('Time in s')
        axes[i].set_ylabel(col)
        axes[i].set_title(titles[i])
    fig.tight_layout()
    plt.savefig("project_testing/python/random_fuzzer_ontime.png")

    iterations = df['iterations']
    cols_to_plot = ['failures', 'unique_paths', 'crashes' ,'unix_time','code_coverage']
    titles = ['failures', 'unique_paths', 'run_time_crashes' ,'time in s','code_coverage']
    # plot each column in a separate subplot
    fig, axes = plt.subplots(nrows=len(cols_to_plot), ncols=1, figsize=(10,10))
    for i, col in enumerate(cols_to_plot):
        axes[i].plot(iterations, df[col])
        axes[i].set_xlabel('# fuzzed inputs')
        axes[i].set_ylabel(col)
        axes[i].set_title(titles[i])
    fig.tight_layout()
    plt.savefig("project_testing/python/random_fuzzer_ontinputs.png")