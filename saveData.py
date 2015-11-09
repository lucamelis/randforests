#!/usr/bin/python
# -*- coding: utf-8 -*-

#comment
from util import *
import os

#first day of logs
start_day = dt.datetime(2015,02,13)

#where to put the .pkl
target_dir = "data/"

#big archive
archive = target_dir + "data.7z"

#do subsampling
sample = True

# number of consecutives time windows
num_tests = 10

train_window = 6
stats_list = [ ]
save_params = {
            "usecols": col_idx, #range(1,len(names)+1), 
            "names": names[col_idx], 
            "sep": '\t' 
            }

def subsample(df_logs):
    from collections import Counter
    import operator
    
    head_k = 10
    tail_k = 20
    
    logs_c = Counter(df_logs["target_ip"])    
    xs, freqs = zip( *sorted( logs_c.items(), key=operator.itemgetter(1), reverse=True) )

    return df_logs[ df_logs.target_ip.map(lambda x: x in xs[ head_k:-tail_k ]) ]


#extract raw logs files
#for i in range(0,15):
#    cur_day = start_day + dt.timedelta(days=i)
#    os.system(r"7za x {} {} {}".format(archive, "logs{}.txt".format( cur_day.date().isoformat() ) , target_dir) )

for i in range(0,num_tests):
    cur_day = start_day + dt.timedelta(days=i)
        
    df_logs = loadData(cur_day, save_params)

    if sample:
        df_logs = subsample(df_logs)
        fn = target_dir + "df_sample_" + cur_day.date().isoformat() +".pkl"
    else:
        fn = target_dir + "df_" + cur_day.date().isoformat() +".pkl"

    df_logs.to_pickle(fn)

    del df_logs

#delete all raw logs
#os.system( r"rm -rf {}df_*.txt".format(target_dir) )
