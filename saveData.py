#!/usr/bin/python
# -*- coding: utf-8 -*-

#comment
from util import *

do_feat_extraction = False
#time window
day = dt.datetime(2015,05,17)
num_tests = 1
train_window = 6

stats_list = [ ]
save_params = {
            "usecols": col_idx, #range(1,len(names)+1), 
            "names": names[col_idx], 
            "sep": '\t' 
            }

for i in range(0,num_tests):
    start_day = day + dt.timedelta(days=i)
    # df_logs = pd.read_csv(data_dir + "logs"+ start_day.date().isoformat()+".txt", **parser_params )
    # print start_day.date().isoformat()
        
    df_logs = loadData(start_day, save_params)

    df_logs.to_pickle(data_dir + "df_" + start_day.date().isoformat() +".pkl")

    del df_logs