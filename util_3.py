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

def getHeavyHitters(attackers,tau):
    """
    Take the most frequent attackers which cover the tau \in (0,1) of the cdf
    """
    from collections import Counter
    import bisect
    import operator

    assert 0 < tau < 1 
    xs, freqs = zip( *sorted( Counter(attackers).items(), key=operator.itemgetter(1), reverse=True) )
    ps = np.cumsum(freqs, dtype=np.float)
    ps /= ps[-1]
    index = bisect.bisect_left(ps, tau)

    return np.array( xs[: index if index>0 else 1] )
    
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
            int_bl = int_bl | (train_set_attackers[contributor] & blacklists[cont])
        
        int_bl = blacklists[contributor] | int_bl
        
    return int_bl

# blacklist according to the (heavy attackers) ip2ip matrix - 
# i.e. for each ip in the local blacklist AND in the ip2ip matrix, 
# blacklist its nearest neighbors as well
def ip2ip_prediction(contributor, blacklists, corelated_ips, top_attackers):
    
    cor_ips = set()
    
    for ip in set(blacklists[contributor]) & set(top_attackers):
            cor_ips = cor_ips | set(corelated_ips[ip])    
            
    ip2ip_bl = blacklists[contributor] | cor_ips
    
    return ip2ip_bl

# compute some prediction stats
def verify_prediction(local_blacklist, gub_blacklist, int_blacklist, ip2ip_blacklist, ground_truth):

    assert type(local_blacklist) is set
    assert type(gub_blacklist) is set
    assert type(int_blacklist) is set
    assert type(ip2ip_blacklist) is set
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
    
    d["n_attacks"] = len(ground_truth)     
    d["len_local_blacklist"] = len(local_blacklist)
    d["len_gub_blacklist"] = len(gub_blacklist)
    d["len_int_blacklist"] = len(int_blacklist)
    d["len_ip2ip_blacklist"] = len(ip2ip_blacklist)
    
    try:
        d["tp_impr_gub"] = (d["tp_gub"] - d["tp_local"]) / float(d["tp_local"])
        d["tp_impr_int"] = (d["tp_int"] - d["tp_local"]) / float(d["tp_local"])
        d["tp_impr_ip2ip"] = (d["tp_ip2ip"] - d["tp_local"]) / float(d["tp_local"])
    except ZeroDivisionError:
        d["tp_impr_gub"] = 0.0
        d["tp_impr_int"] = 0.0
        d["tp_impr_ip2ip"] = 0.0
        
    try:    
        d["fp_incr_gub"] = (d["fp_gub"] - d["fp_local"]) / float(d["fp_local"])
        d["fp_incr_int"] = (d["fp_int"] - d["fp_local"]) / float(d["fp_local"])    
        d["fp_incr_ip2ip"] = (d["fp_ip2ip"] - d["fp_local"]) / float(d["fp_local"])
    except ZeroDivisionError:
        d["fp_incr_gub"] = 0.0
        d["fp_incr_int"] = 0.0
        d["fp_incr_ip2ip"] = 0.0
        
    return d    

# compute the aggregated stats 
def compute_stats(stats):
    
    for k in np.unique(stats["n_clusters"]):
        
        k_stats = stats[stats.n_clusters == k]
        
        print('*************************')
        print 'N_clusters: ', k
        print 'Local TP: ', k_stats['tp_local'].sum()
        print 'Global TP: ', k_stats['tp_gub'].sum()
        print 'Int TP: ', k_stats['tp_int'].sum()
        print 'Ip2ip TP: ', k_stats['tp_ip2ip'].sum()
        
        print 'TP Improvement of global over local: ', ( k_stats['tp_impr_gub'].sum() / len(k_stats['tp_impr_gub']) )
        print 'TP Improvement of intersection over local: ', ( k_stats['tp_impr_int'].sum() / len(k_stats['tp_impr_int']) )
        print 'TP Improvement of ip2ip over local: ', (k_stats['tp_impr_ip2ip'].sum() / len(k_stats['tp_impr_ip2ip']) )
        
        print('-----------------------')
        print 'Local FP: ', k_stats['fp_local'].sum()
        print 'Global FP: ', k_stats['fp_gub'].sum()
        print 'Int FP: ', k_stats['fp_int'].sum()
        print 'Ip2ip FP: ', k_stats['fp_ip2ip'].sum()
        
        print 'FP Increase of global over local: ', (k_stats['fp_incr_gub'].sum() / len(k_stats['fp_incr_gub']) )
        print 'FP Increase of intersection over local: ', (k_stats['fp_incr_int'].sum() / len(k_stats['fp_incr_int']) )
        print 'FP Increase of ip2ip over local: ', (k_stats['fp_incr_ip2ip'].sum() / len(k_stats['fp_incr_ip2ip']) )
        
# compute jaccard similarity of two sets
def jaccard_similarity(x, y):
    
    intersection_size = len(x & y)
    union_size = len( x | y )
    
    return intersection_size / float(union_size)    