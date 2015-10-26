#!/usr/bin/python
# -*- coding: utf-8 -*-

# file with utility variables & functions

import datetime as dt

# ewma degree of weight decrease (value closer to 1 give more weight to most recent trends)
alpha = 0.9

# threshold for blacklisting an ip
ewma_threshold = 0.5

# day offset
offset = 17

# data window length
window_len = 6

# compute blacklists based on local contributor logs
def local_prediction(top_targets, train_set, window):
    
    binary_mat = dict()
    prediction = dict()
    blacklist = dict()
    whitelist = dict()
    binary_mat = binary_matrix(top_targets, train_set, window)
    prediction = local_score_prediction(binary_mat)
    blacklist, whitelist = local_blacklist(prediction)
    
    return blacklist, whitelist

# compute the binary matrix required for EWMA
def binary_matrix(targets, train_set, window):

    # the binary matrix with keys of the form 'victim' contains a second dictionary with keys 
    # 'src_ip' and values the binary list for all days e.g. [1, 0, 0, 0, 0]
    binary_matrix = dict()
    
    for victim in targets:
        binary_matrix[victim] = dict()              
    
    c = train_set.groupby(['target_ip', 'src_ip'])
    
    # iterate through the groups
    for group, row in c:
        
        binary_matrix[group[0]][group[1]] = [0 for r in xrange(window_len - 1)]
        
        # get the days of attacks
        d = row['D']
        for day in d:
            binary_matrix[group[0]][group[1]][day.day - window - offset] = 1            
        del d
    
    del c
    
    return binary_matrix

# compute the ewma prediction for each contributor
def local_score_prediction(binary_matrix):
    
    predictions = dict()

    for target in binary_matrix:
        
        predictions[target] = dict()
        
        for attacker in binary_matrix[target]:
    
            predictions[target][attacker] = ts_score(window_len - 1, binary_matrix[target][attacker])        
                        
    return predictions

# generate the blacklist based on the ewma predictions    
def local_blacklist(predictions):
    
    local_blacklists = dict()
    local_whitelists = dict()
    
    # for every contributor
    for victim in predictions:
        
        # get those attackers that have scored above the threshold
        l = [(k, v) for k, v in predictions[victim].iteritems() if v >= ewma_threshold]
        local_blacklists[victim] = set([w[0] for w in l])
        m = [(k, v) for k, v in predictions[victim].iteritems() if v < ewma_threshold]
        local_whitelists[victim] = set([z[0] for z in m])
                        
    return local_blacklists, local_whitelists    

# ewma weight generation
def compute_weights(a, N):
    ws = list()
    for i in range(N - 1, -1, -1):
        w = a * ((1-a)**i)
        ws.append(w)
    
    return ws

# sum weighted data
def sum_weighted(data, ws):
    wt = list()
    for i, x in enumerate(data):
        wt.append(x*ws[i])
    
    return sum(wt)

# assign a ewma score
def ts_score(N, data):
    ws = compute_weights(alpha, N)
    pred = sum_weighted(data, ws)
    
    return pred    