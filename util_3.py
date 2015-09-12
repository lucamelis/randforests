#!/usr/bin/python
# -*- coding: utf-8 -*-

# file with utility variables & functions

import datetime as dt

from itertools import permutations

logs_start_day = dt.datetime.strptime("2015-05-17", '%Y-%m-%d')

num_tests = 1 # TODO: this should be 10 for the actual experiments
window_length = 6

data_dir = 'data/' # directory where the data are stored 

# get the gub prediction - i.e. blacklist is the union of blacklists for all contributors in the cluster
def gub_prediction(contributors, blacklists):
    
    gub_bl = set()
        
    for contributor in contributors:
            gub_bl = gub_bl | blacklists[contributor]
            
    return gub_bl        

# get the intersection of the training set attackers with the blacklist of the rest contributors in the cluster
# and the union with the local blacklist     
def intersection_prediction(contributors, blacklists, train_set_attackers):    
    
    int_bl = dict()
    
    # if the cluster has one contributor then the local blacklist is returned
    if len(contributors) == 1:
        for contributor in contributors:
            int_bl[contributor] = blacklists[contributor]
    
    else:
        pairs = permutations(contributors, 2)
    
        for pair in pairs:
            int_bl[pair[0]] = blacklists[pair[0]] | (train_set_attackers[pair[0]] & blacklists[pair[1]])
        
    return int_bl

# compute some prediction stats
def getPrediction(local_blacklist, gub_blacklist, int_blacklist, ground_truth):
    
    assert type(local_blacklist) is set
    assert type(gub_blacklist) is set
    assert type(int_blacklist) is set
    #assert typeof(whitelist) is set
    assert type(ground_truth) is set

    d = {}
    d["tp_local"] = len( local_blacklist & ground_truth )
    d["fp_local"] = len( local_blacklist - ground_truth )
    
    d["tp_gub"] = len( gub_blacklist & ground_truth )
    d["fp_gub"] = len( gub_blacklist - ground_truth )
    
    d["tp_int"] = len( int_blacklist & ground_truth )
    d["fp_int"] = len( int_blacklist - ground_truth )
    
    #d["fn"] = len( whitelist & ground_truth )  
    #d["tn"] = len( whitelist - ground_truth ) 
     
    #d["len_whitelist"] = len(whitelist)
    d["len_local_blacklist"] = len(local_blacklist)
    d["len_gub_blacklist"] = len(gub_blacklist)
    d["len_int_blacklist"] = len(int_blacklist)
    
    d["n_attacks"] = len(ground_truth)

    return d    

# compute the aggregated stats 
def compute_stats(stats):
    
    print 'Local TP: ', stats['tp_local'].sum()
    print 'Global TP: ', stats['tp_gub'].sum()
    print 'Int TP: ', stats['tp_int'].sum()
    print 'TP Improvement of global over local: ', (stats['tp_gub'].sum() - stats['tp_local'].sum()) / float(stats['tp_local'].sum())
    print 'TP Improvement of intersection over local: ', (stats['tp_int'].sum() - stats['tp_local'].sum()) / float(stats['tp_local'].sum())
    
    print('-------------------')
    print 'Local FP: ', stats['fp_local'].sum()
    print 'Global FP: ', stats['fp_gub'].sum()
    print 'Int FP: ', stats['fp_int'].sum()
    print 'FP Increase of global over local: ', (stats['fp_gub'].sum() - stats['fp_local'].sum()) / float(stats['fp_local'].sum())
    print 'FP Increase of intersection over local: ', (stats['fp_int'].sum() - stats['fp_local'].sum()) / float(stats['fp_local'].sum())
    
# compute jaccard similarity of two sets
def jaccard_similarity(x, y):
    
    intersection_size = len(x & y)
    union_size = len( x | y )
    
    return intersection_size / float(union_size)    