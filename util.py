#!/usr/bin/python
# -*- coding: utf-8 -*-

import numpy as np
import scipy as sp
from scipy import sparse

import pandas as pd

import datetime as dt
import re
from itertools import combinations, product
from collections import Counter

from sklearn import ensemble, feature_extraction, preprocessing, cross_validation, metrics
from sklearn.neighbors import NearestNeighbors

from pybloom import BloomFilter

from joblib import Parallel, delayed  
import multiprocessing

def feedBloom(row):
    f = BloomFilter(capacity = 200 , error_rate = 0.6)
    f.add(row.src_ip) 
    f.add(row.src_ip[0:5])
    f.add(row.src_ip[5:8])
    f.add(row.target_ip)
    return np.array(f.bitarray.tolist(),dtype=np.int)

def toBloomfeatures(df):
    num_cores = multiprocessing.cpu_count()
    ip_space = len( set(df.src_ip) )            
    data = sparse.csr_matrix( Parallel(n_jobs=num_cores)( delayed(feedBloom)(row,ip_space) for _, row in df.iterrows() ) ) 
    return data    

def getPrediction(blacklist, whitelist, ground_truth):
    
    assert typeof(blacklist) is set
    assert typeof(whitelist) is set
    assert typeof(ground_truth) is set

    d = {}
    d["tp"] = len( blacklist & ground_truth )
    d["fp"] = len( blacklist - ground_truth )
    
    d["fn"] = len( whitelist & ground_truth )  
    d["tn"] = len( whitelist - ground_truth )
 
    d["len_whitelist"] = len(whitelist)
    d["len_blacklist"] = len(blacklist)
    d["n_attacks"] = len(ground_truth)

    return d

def cleanData(data):

    data = data.fillna("0")

    # Remove port numbers that do not exist
    data = data[data.src_prt <= 65535]
    data = data[data.src_prt != 0]    

    data = data[data.target_prt <= 65535]
    data = data[data.target_prt != 0]    
    
    # Remove IP addresses that do not make sense as adversaries (0, 10, 127, 192.168, 169.254, 172.16)
    ip_private_6 = ["169.254", "192.168","172.016", "172.017","172.018",
                    "172.019","172.020","172.021","172.022","172.023",
                    "172.024","172.025","172.026","172.027","172.028","172.029","172.030","172.031"]
    ip_private = ["010", "000", "127","224","225","226","227","228",
                  "229","230","231","232","233","234","235","236",
                  "237","238","239","240","241","242","243","244",
                  "245","246","247","248","249","250","251","252","253","254","255"]

    ip_pattern = "^\d{3}.\d{3}.\d{3}.\d{3}$"
    criterion = data['src_ip'].map( lambda x: re.match(ip_pattern,x) is not None )  
    data = data[criterion]

    criterion = data['src_ip'].map( lambda x: np.logical_not( (x[0:7] in ip_private_6) ) )
    data = data[criterion]

    #map to python dates objects
    data.D = data.D.map( lambda x: dt.date(*[ np.int(i) for i in x.split("-") ] ) )

    criterion = data['src_ip'].map( lambda x: np.logical_not( (x[0:3] in ip_private) ) )
    data = data[criterion]

    return data

def timeToSeconds(date):
    timesince = dt.datetime(*date) - dt.datetime(*date[0:3])
    return int(timesince.total_seconds())

def loadData(start_day,params):
    
    df_logs = pd.DataFrame([ ], columns=names[col_idx] )
    
    targets = []
    for j in range(0, train_window):
        cur_day = start_day + dt.timedelta(days=j)
        print cur_day.date().isoformat()
        df_logs = df_logs.append( 
            pd.read_csv( data_dir + "logs" + cur_day.date().isoformat() + ".txt", **params ), 
            ignore_index=True 
            )
        targets.append( set(df_logs["target_ip"]) ) 

    best_targets = targets[0]    
    for j in range(1, train_window):
        best_targets = best_targets & targets[j] 

    df_logs = cleanData(df_logs)

    days = np.unique(df_logs['D'])
    last_day = np.max(days)
    
    # GUB_targets = set(df_logs[df_logs.D < last_day]["target_ip"]) & set(df_logs[df_logs.D == last_day]["target_ip"])
    criterion = df_logs['target_ip'].map(lambda x: x in best_targets)
    df_logs = df_logs[criterion]

    # GUB_targets = set(df_logs[df_logs.D < last_day]["target_ip"]) & set(df_logs[df_logs.D == last_day]["target_ip"])
    # criterion = df_logs['target_ip'].map(lambda x: x in GUB_targets)
    # df_logs = df_logs[criterion]

    top_targets = [ k for k,v in Counter( df_logs[df_logs.D < last_day]["target_ip"].to_dense() ).most_common(100) ]
    
    criterion = df_logs['target_ip'].map(lambda x: x in top_targets)
    df_logs = df_logs[criterion]

    return df_logs    


encoder = feature_extraction.DictVectorizer()
labeller = preprocessing.LabelEncoder()

names = np.array(["ID","D","time","src_ip","src_prt","target_prt","prot","flag","target_ip"])
col_idx =[1,2,3,4,5,8]
#training features
# categorical = ["target_ip","flag", "prot", "src_prt","target_prt"]

#targets labels
label = ["label"]

data_dir = "data/"
parser_params = {
            "nrows": 2*10**5,
            "usecols": col_idx, #range(1,len(names)+1), 
            "names": names[col_idx], 
            "sep": '\t' 
            }

forest_params = { 
            'max_depth' : None,
            'min_samples_split' : 2,
            'criterion': 'mse',
            'n_estimators' : 100, 
            'n_jobs' : -1,
            }