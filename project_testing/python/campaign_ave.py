import pandas as pd 
import os

def average_csv_files_s(file_paths,output_path):
    file_dfs = []
    for i in file_paths:
        file_dfs.append(pd.read_csv(i))
    
    columns = file_dfs[0].columns
    min_rows = []
    for i in file_dfs:
        min_rows.append(i.shape[0])
    min_row_index = min(min_rows)
    
    averages_df = pd.DataFrame(
        columns=[columns[1]] + list(columns[2:])
    )
    # print(averages_df);
    column_index_range = len(columns)
    for row_index in range(min_row_index):
        row_averages = []
        # Filter out the first 2 columns since we don't need to calculate average index and unix_time
        for column_index in range(2, column_index_range):
            cells = []
            for df in file_dfs:
                cell_value = (
                    df.iloc[row_index, column_index]
                    if column_index < df.shape[1]
                    else 0
                )
                cells.append(cell_value)

            row_averages.append(sum(cells) / len(file_dfs))
        averages_df.loc[row_index] = [file_dfs[0].iloc[row_index, 1]] + row_averages
    print(averages_df.head())
    averages_df.to_csv(output_path, index=False)


if __name__ == '__main__':
    path = "project_testing/python/plot_data/"
    listop = os.listdir(path)
    for index,file in enumerate(listop):
        listop[index] = path+file 
    print(listop)
    average_csv_files_s(listop,"project_testing/python/data_list.csv")