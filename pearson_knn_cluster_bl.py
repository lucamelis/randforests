#!/usr/bin/python
# -*- coding: utf-8 -*-

from util_3 import *

import time_series as ts

import numpy as np
import pandas as pd

from itertools import combinations
from itertools import product

from sklearn.neighbors import NearestNeighbors
from timer import Timer

from scipy.sparse import lil_matrix

kNN_alg = ['auto', 'ball_tree', 'kd_tree', 'brute']
nn_orgs = [2, 4, 8, 10, 15]
nn_ips = 50

stats_list = []

for i in range(0, num_tests):

    print 'Window: ', i
    start_day = logs_start_day + dt.timedelta(days=i)

    # load the window data into a dataframe
    window_logs = pd.read_pickle(data_dir + "sample.pkl")
    #window_logs = pd.read_pickle(data_dir + "df_" + start_day.date().isoformat() + ".pkl")

    #extract /24 subnets from IPs # TODO: we should play around with /16, /8 as well
    window_logs.src_ip = window_logs.src_ip.map(lambda x: x[:11])

    # get the contributors of the window logs
    top_targets = np.unique( window_logs["target_ip"] )

    # get the days, as well as first day and last day
    days = np.unique(window_logs['D'])
    first_day, last_day = np.min(days), np.max(days)

    # split training set and testing set
    date_list = [start_day.date() + dt.timedelta(days=x) for x in range(0, window_length - 1)]    
    train_set = window_logs[window_logs.D.isin(date_list)] 
    test_set = window_logs[window_logs.D == last_day]

    print 'Training set size: ', train_set.shape[0]
    print 'Test set size: ', test_set.shape[0]

    del window_logs
    
    # get the pairs between organizations 
    target_pairs = combinations(top_targets, 2)

    # dictionary holding the indices of the contributors
    ind_orgs = dict( zip(top_targets, range(top_targets.size) ) )
    reverse_ind_orgs = dict( zip(ind_orgs.values(), ind_orgs.keys()) )

    # organization to organization matrix
    o2o = np.zeros((top_targets.size, top_targets.size))

    # create a dictionary where each contributors stores his attacker set over all the training window
    print 'creating attacker set dictionary...'
    victim_set = dict()
    for target in top_targets:
        victim_set[target] = set( train_set[ (train_set.target_ip == target) ].src_ip )

    print 'creating daily attacker dictionary for pearson...'
    victim_daily_set = dict()
    for target in top_targets:
        victim_daily_set[target] = train_set[ (train_set.target_ip == target) ].src_ip
    
    print 'Creating Pearson o2o matrix...'            
    for pair in target_pairs:
        o2o[ ind_orgs[pair[0]], ind_orgs[pair[1]]] = compute_pearson( victim_daily_set[pair[0]], victim_daily_set[pair[1]])
        o2o[ ind_orgs[pair[1]], ind_orgs[pair[0]]] = o2o[ind_orgs[pair[0]], ind_orgs[pair[1]]]
    
    # o2o might contain nan values - knn complains
    o2o = np.nan_to_num(o2o)
            
    # local prediction and blacklist generation part - this dictionary holds each contributor's local blacklist
    print 'Computing local predictions...'
    l_blacklists = dict()
    l_blacklists = ts.local_prediction(top_targets, train_set, i)
    
    # clustering part - kNN on organisations    
    for k in nn_orgs:
    
        print 'Kvalue :', k
        
        # compute nearest neighbors based on the ip2ip matrix
        neighbors = NearestNeighbors(n_neighbors = k, algorithm = kNN_alg[1]).fit( o2o )
        _, indices = neighbors.kneighbors( o2o )

        # dictionary storing for each contributor a list with its nearest neighbors
        org_neighbors = dict()
        for idx, x in enumerate(indices):
            #org_neighbors[reverse_ind_orgs[idx]] = [reverse_ind_orgs[y] for y in x ]
            # select the neighbors that have positive pearson correlation
            org_neighbors[reverse_ind_orgs[idx]] = [reverse_ind_orgs[y] for y in x if o2o[idx][y] > 0.0]
            
        # global blacklist - this dictionary holds each contributor's global blacklist (i.e. the one generated from his cluster)
        gub_blacklists = dict()

        # intersection blacklist - this dictionary holds each contributor's intersection blacklist (i.e. the ips on his training set intersected 
        # with the blacklists of the contributors in his cluster)
        int_blacklists = dict()

        # ip2ip corelation blacklist
        ip2ip_blacklists = dict()    
    
        # combined ip2ip and intersection blacklist
        int_ip2ip_blacklists = dict()
        
        # what happens in the cluster stays in the cluster     
        for contributor in org_neighbors:
           
            # get the cluster's contributors
            c_contributors = org_neighbors[contributor] + [contributor]
    
            # create the ip2ip matrix for the cluster
            criterion = train_set.target_ip.map(lambda x: x in c_contributors)
            logs = train_set[criterion].copy()

            top_attackers = getHeavyHitters( logs["src_ip"] ,0.9 )
            
            # limit the attacker to top1000
            top_attackers = top_attackers[:1000]
            print 'Top attacks : ', top_attackers.size            
            
            ind_ips = dict( zip(top_attackers, range(top_attackers.size) ) )
            reverse_ind_ips = dict( zip(ind_ips.values(), ind_ips.keys()) )

            criterion = logs.src_ip.map(lambda x: x in top_attackers)
            logs = logs[criterion]
            logs.src_ip = logs.src_ip.map(lambda x : ind_ips[x])

            df_gr = logs.groupby("D").apply(lambda x: np.bincount( x["src_ip"], minlength=top_attackers.size) )
            
            ip2ip = lil_matrix(np.zeros( top_attackers.size**2, dtype=np.uint32))

            print 'computing ip2ip matrix...'
            for l, v in df_gr.iteritems():
                ip2ip += np.array([np.uint32(min(f)) for f in product(v,v)])
            
            del df_gr
            
            # compute nearest neighbors based on the ip2ip matrix
            nbrs = NearestNeighbors(n_neighbors= min(nn_ips, top_attackers.size), algorithm= kNN_alg[1]).fit( ip2ip.toarray().reshape(top_attackers.size, top_attackers.size) )
            _, indic = nbrs.kneighbors(ip2ip.toarray().reshape(top_attackers.size, top_attackers.size))

            del ip2ip; del top_attackers
            
            # for each attacker ip store the k corelated ips
            corelated_ips = dict()

            for idx, x in enumerate(indic):
                corelated_ips[reverse_ind_ips[idx]] = [reverse_ind_ips[y] for y in x]
    
            # compute gub blacklist
            gub = set()
            gub = gub_prediction(c_contributors, l_blacklists)        
            gub_blacklists[contributor] = gub
            del gub
            
            # compute intersection blacklists
            int_set = set()
            int_set = intersection_prediction(contributor, c_contributors, l_blacklists, victim_set)
            int_blacklists[contributor] = int_set
            del int_set
                                                            
            # make ip2ip corelation prediction
            ip2ip_set = set()
            ip2ip_set = ip2ip_prediction(contributor, l_blacklists, corelated_ips)
            ip2ip_blacklists[contributor] = ip2ip_set
            del ip2ip_set
            
            # make combined ip2ip and intersection prediction
            int_ip2ip_set = set()
            int_ip2ip_set = combined_int_ip2ip_prediction(int_blacklists[contributor], ip2ip_blacklists[contributor])
            int_ip2ip_blacklists[contributor] = int_ip2ip_set
            del int_ip2ip_set
            
            del corelated_ips; 
            
        # predictions verification part
        for target in top_targets:

            stats = verify_prediction(l_blacklists[target], gub_blacklists[target], int_blacklists[target], ip2ip_blacklists[target], int_ip2ip_blacklists[target], set( test_set[ (test_set.target_ip == target) ].src_ip ) )
                
            stats["D"] = last_day
            stats["n_clusters"] = k
            stats["target"] = target

            stats_list.append(stats)    

        del gub_blacklists; del int_blacklists; del ip2ip_blacklists; del int_ip2ip_blacklists

    del train_set; del test_set; del l_blacklists

df_stats = pd.DataFrame(stats_list)

# print out some stats
compute_stats('pearson', df_stats)

# save the df for later processing
df_stats.to_pickle("pearson_k_nn_stats.pkl")