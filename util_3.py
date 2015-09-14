#!/usr/bin/python
# -*- coding: utf-8 -*-

# file with utility variables & functions

import datetime as dt
import numpy as np

from itertools import permutations, product

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

# for each contributor, get the intersection of the attackers in his training set with the blacklist 
# of the rest contributors in the cluster
# then, get the union with the local blacklist     
def intersection_prediction(contributor, contributors, blacklists, train_set_attackers):    
    
    int_bl = set()
    
    # if the cluster has one contributor then the local blacklist is returned
    if len(contributors) == 1:
        int_bl = blacklists[contributor]
    
    else:
        for cont in contributors:
            int_bl = (train_set_attackers[contributor] & blacklists[cont])
        
        int_bl = blacklists[contributor] | int_bl
        
    return int_bl

# blacklist according to ip2ip matrix - i.e. for each ip in the local blacklist, blacklist its nearest neighbors as well
def ip2ip_prediction(contributor, blacklists, corelated_ips):
    
    cor_ips = set()
    
    for ip in blacklists[contributor]:
        cor_ips = cor_ips | set(corelated_ips[ip])    
            
    ip2ip_bl = blacklists[contributor] | cor_ips
    
    return ip2ip_bl

# compute some prediction stats
def verify_prediction(local_blacklist, gub_blacklist, int_blacklist, ip2ip_blacklist, ground_truth):
    
    assert type(local_blacklist) is set
    assert type(gub_blacklist) is set
    assert type(int_blacklist) is set
    assert type(ip2ip_blacklist) is set
    #assert typeof(whitelist) is set
    assert type(ground_truth) is set

    d = {}
    d["tp_local"] = len( local_blacklist & ground_truth )
    d["fp_local"] = len( local_blacklist - ground_truth )
    
    d["tp_gub"] = len( gub_blacklist & ground_truth )
    d["fp_gub"] = len( gub_blacklist - ground_truth )
    
    d["tp_int"] = len( int_blacklist & ground_truth )
    d["fp_int"] = len( int_blacklist - ground_truth )
        
    d["tp_ip2ip"] = len( ip2ip_blacklist & ground_truth )
    d["fp_ip2ip"] = len( ip2ip_blacklist - ground_truth )
        
    #d["fn"] = len( whitelist & ground_truth )  
    #d["tn"] = len( whitelist - ground_truth ) 
     
    #d["len_whitelist"] = len(whitelist)
    d["len_local_blacklist"] = len(local_blacklist)
    d["len_gub_blacklist"] = len(gub_blacklist)
    d["len_int_blacklist"] = len(int_blacklist)
    d["len_ip2ip_blacklist"] = len(ip2ip_blacklist)
    
    d["n_attacks"] = len(ground_truth)

    return d    

# compute the aggregated stats 
def compute_stats(stats):
    
    for k in np.unique(stats["n_clusters"]):
        k_stats = stats[stats.n_clusters == k]
        print('********')
        print 'N_clusters: ', k
        print 'Local TP: ', k_stats['tp_local'].sum()
        print 'Global TP: ', k_stats['tp_gub'].sum()
        print 'Int TP: ', k_stats['tp_int'].sum()
        print 'Ip2ip TP: ', k_stats['tp_ip2ip'].sum()
        print 'TP Improvement of global over local: ', (k_stats['tp_gub'].sum() - k_stats['tp_local'].sum()) / float(k_stats['tp_local'].sum())
        print 'TP Improvement of intersection over local: ', (k_stats['tp_int'].sum() - k_stats['tp_local'].sum()) / float(k_stats['tp_local'].sum())
        print 'TP Improvement of ip2ip over local: ', (k_stats['tp_ip2ip'].sum() - k_stats['tp_local'].sum()) / float(k_stats['tp_local'].sum())
        
        print('-------------------')
        print 'Local FP: ', k_stats['fp_local'].sum()
        print 'Global FP: ', k_stats['fp_gub'].sum()
        print 'Int FP: ', k_stats['fp_int'].sum()
        print 'Ip2ip FP: ', k_stats['fp_ip2ip'].sum()
        print 'FP Increase of global over local: ', (k_stats['fp_gub'].sum() - k_stats['fp_local'].sum()) / float(k_stats['fp_local'].sum())
        print 'FP Increase of intersection over local: ', (k_stats['fp_int'].sum() - k_stats['fp_local'].sum()) / float(k_stats['fp_local'].sum())
        print 'FP Increase of ip2ip over local: ', (k_stats['fp_ip2ip'].sum() - k_stats['fp_local'].sum()) / float(k_stats['fp_local'].sum())
        
# compute jaccard similarity of two sets
def jaccard_similarity(x, y):
    
    intersection_size = len(x & y)
    union_size = len( x | y )
    
    return intersection_size / float(union_size)    