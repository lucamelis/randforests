#!/usr/bin/python
# -*- coding: utf-8 -*-


import numpy as np
import scipy as sp
import pandas as pd

import datetime as dt
import re
from collections import Counter

from sklearn import ensemble, feature_extraction, preprocessing, cross_validation, metrics
from sklearn.decomposition import TruncatedSVD

def getPrediction(pred, true):
    test_size = float(true.shape[0])
    d = {}
    d["tp"] = sum( (pred == 1) & (true==1) )/test_size
    d["fp"] = sum( (pred == 1) & (true==0) )/test_size
    d["tn"] = sum( (pred == 0) & (true==0) )/test_size
    d["fn"] = sum( (pred == 0) & (true==1) )/test_size
    d["support"] = test_size

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
    criterion = data['src_ip'].map(lambda x: re.match(ip_pattern,x) is not None )  
    data = data[criterion]

    criterion = data['src_ip'].map(lambda x: np.logical_not( (x[0:7] in ip_private_6) )  )
    data = data[criterion]

    criterion = data['src_ip'].map(lambda x: np.logical_not( (x[0:3] in ip_private) )  )
    data = data[criterion]

    return data

def timeToSeconds(date):
    timesince = dt.datetime(*date) - dt.datetime(*date[0:3])
    return int(timesince.total_seconds())

encoder = feature_extraction.DictVectorizer()
labeller = preprocessing.LabelEncoder()


#time window
day = dt.datetime(2015,05,17)
num_tests = 10  
train_window = 6

names = np.array(["ID","Y","M","D","hh","mm","ss","src_ip","src_prt","target_prt","prot","flag","target_ip"])
col_idx =[3,7,8,9,12]
#training features
# categorical = ["target_ip","flag", "prot", "src_prt","target_prt"]

#targets labels
label = ["label"]

data_dir = "data/"
parser_params = { 
            "nrows": 10000, 
            "usecols": col_idx, #range(1,len(names)+1), 
            "names": names[col_idx], 
            "sep": '\t|-|:', 
            "engine": 'python'
            }


forest_params = { 
            'max_depth' : None,
            'min_samples_split' : 2,
            'criterion': 'entropy',
            'n_estimators' : 100, 
            'n_jobs' : -1,
            }

do_feat_extraction = False

stats_list = [ ]

for i in range(0,num_tests):
    start_day = day + dt.timedelta(days=i)
    df_logs = pd.read_csv(data_dir + "logs"+ start_day.date().isoformat()+".txt", **parser_params )
    print start_day.date().isoformat()
    for i in range(1, train_window):
        cur_day = start_day + dt.timedelta(days=i)
        print cur_day.date().isoformat()
        df_logs = df_logs.append( pd.read_csv(data_dir + "logs" + cur_day.date().isoformat() + ".txt", **parser_params ), ignore_index=True)

    df_logs = cleanData(df_logs)

    #extract 24/ subnets from IPs
    days = np.unique(df_logs['D'])
    first_day, max_day = np.min(days), np.max(days)

    df_logs.src_ip = df_logs.src_ip.map(lambda x: x[:11])
    df_logs.D = df_logs.D.map(lambda x: x - first_day)

    days = np.unique(df_logs['D'])
    first_day, last_day = np.min(days), np.max(days)

    #targetes who are both in train and test sets
    GUB = set(df_logs[df_logs.D < last_day]["target_ip"]) & set(df_logs[df_logs.D == last_day]["target_ip"])
    criterion = df_logs['target_ip'].map(lambda x: x in GUB)
    df_logs = df_logs[criterion]

    top_targets = [ k for k,v in Counter( df_logs["target_ip"].to_dense() ).most_common(100) ]

    criterion = df_logs['target_ip'].map(lambda x: x in top_targets)
    df_logs = df_logs[criterion]

    st_cols = ['src_ip','target_ip','D',"label"]
    grouped = df_logs.groupby( st_cols[0:2] )

    # attacks
    positives_logs = pd.DataFrame(
        [ [k[0],k[1],s,1] for k,v in grouped["D"] for s in set(np.unique(v)) ], columns = st_cols)
    #not attacks
    negatives_logs = pd.DataFrame(
        [ [k[0],k[1],s,0] for k,v in grouped["D"] for s in set(days) - set(np.unique(v)) ], columns = st_cols)
    
    #not-attacks equal-size sampling for each day 
    for i in days:
        positives_logs = positives_logs.append( negatives_logs[negatives_logs.D == i].sample(frac=0.20) , ignore_index=True)

    df_logs = positives_logs.sort("D") 
        

    n_samples = df_logs.shape[0]
    print "Dataset size:\t",n_samples

    #last day items for the test set
    test_size = df_logs.D[df_logs.D == last_day].shape[0]
    train_size = n_samples - test_size

    data = encoder.fit_transform( df_logs[st_cols[0:3]].T.to_dict().values() )

    if do_feat_extraction:
        n_features = 10
        svd = TruncatedSVD(n_components=n_features, random_state=42)
        #return dense array
        data = svd.fit_transform(data)

    # target_data = np.hstack( list([labeller.fit_transform( df_logs[label].to_dense() ).reshape(n_samples,1)  for label in labels] ) )
    # if len(labels)==1:
    target_data = labeller.fit_transform( df_logs["label"].to_dense() ).reshape(n_samples,1).ravel()

    # scaling data (mean=0, var=1)
    # data = preprocessing.scale(data)

    #train/test split
    X_train, Y_train = data[:train_size], target_data[:train_size]
    X_test, Y_test = data[X_train.shape[0]:], target_data[X_train.shape[0]:]

    # X_train, X_test, Y_train, Y_test = cross_validation.train_test_split(data, target_data, test_size=test_size, random_state=10)

    print "Train size:\t", X_train.shape[0]
    print "Test size:\t", X_test.shape[0]

    # print X_train.shape, Y_train.shape

    forest = ensemble.RandomForestClassifier( **forest_params )
    forest = forest.fit( X_train, Y_train )

    Y_pred = forest.predict(X_test)
    
    for target in top_targets:
        
        mask = np.array(df_logs[df_logs.D == last_day]["target_ip"] == target)
    
        stats = getPrediction(Y_pred[mask], Y_test[mask])
        stats["D"] = max_day 
        stats["target"] = target
        stats_list.append(stats)

    report = metrics.classification_report(Y_test, Y_pred ).splitlines()

df_stats = pd.DataFrame(stats_list)
df_stats.to_pickle("gub100.pkl")