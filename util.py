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

    data.D = data.D.map(lambda x: np.int( x.split("-")[-1] ) )

    criterion = data['src_ip'].map(lambda x: np.logical_not( (x[0:3] in ip_private) )  )
    data = data[criterion]

    return data

def timeToSeconds(date):
    timesince = dt.datetime(*date) - dt.datetime(*date[0:3])
    return int(timesince.total_seconds())

encoder = feature_extraction.DictVectorizer()
labeller = preprocessing.LabelEncoder()

#time window
day = dt.datetime(2015,06,06)
num_tests = 1
train_window = 6

names = np.array(["ID","D","time","src_ip","src_prt","target_prt","prot","flag","target_ip"])
col_idx =[1,3,4,5,8]
#training features
# categorical = ["target_ip","flag", "prot", "src_prt","target_prt"]

#targets labels
label = ["label"]

data_dir = "data/"
parser_params = {
            "nrows": 2*10**6,
            "usecols": col_idx, #range(1,len(names)+1), 
            "names": names[col_idx], 
            "sep": '\t' 
            }


forest_params = { 
            'max_depth' : None,
            'min_samples_split' : 2,
            'criterion': 'entropy',
            'n_estimators' : 100, 
            'n_jobs' : -1,
            }