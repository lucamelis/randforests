#!/usr/bin/python
# -*- coding: utf-8 -*-

from util_3 import *

import time_series as ts

import numpy as np
import pandas as pd

from itertools import combinations
from itertools import product

from sklearn.cluster import KMeans
from sklearn.neighbors import NearestNeighbors

from scipy.stats import itemfreq

stats_list = []
clusters_values = [20]#, 4, 5, 10, 20]

kNN_alg = ['auto', 'ball_tree', 'kd_tree', 'brute']

for i in range(0, num_tests):
    
    print 'Window: ', i
    start_day = logs_start_day + dt.timedelta(days=i)
    
    # load the window data into a dataframe
    window_logs = pd.read_pickle(data_dir + "sample.pkl")
    # window_logs = pd.read_pickle(data_dir + "df_" + start_day.date().isoformat() + ".pkl")

    #extract /24 subnets from IPs # TODO: we should play around with /16, /8 as well
    window_logs.src_ip = window_logs.src_ip.map(lambda x: x[:7])
    
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

    # get the pairs between organizations 
    target_pairs = combinations(top_targets, 2)

    # dictionary holding the indices of the contributors
    ind_dic = dict( zip(top_targets, range(top_targets.size) ) )

    # organization to organization matrix
    o2o = np.zeros((top_targets.size, top_targets.size, days.size) )

    # create a dictionary where each contributors stores his attacker set over all the training window
    print 'creating attacker set dictionary...'
    victim_set = dict()
    for target in top_targets:
        victim_set[target] = set( train_set[ (train_set.target_ip == target) ].src_ip )     
    
    # create a dictionary where each contributor stores his attacker set for each day 
    print 'Creating daily attacker set dictionary...'
    victim_daily_set = dict()
    for target in top_targets:
        victim_daily_set[target] = dict()
        for idx, day in enumerate(days):
            victim_daily_set[target][idx] = set( train_set[ (train_set.target_ip == target) & (train_set.D == day) ].src_ip)     

    # create the organisation to organisation matrix with 
    # TODO: compute some other form of similarity e.g. Jaccard, Cosine
    print 'Creating o2o matrix...'
    for pair in target_pairs:
        for idx, day in enumerate(days):
            o2o[ ind_dic[pair[0]], ind_dic[pair[1]], idx] = len( victim_daily_set[pair[0]][idx] & victim_daily_set[pair[1]][idx])
            o2o[ ind_dic[pair[1]], ind_dic[pair[0]], idx] = o2o[ind_dic[pair[0]], ind_dic[pair[1]], idx]

    # clustering part 
    # TODO: play with kmeans, DBSCAN, KNN - also play with n_clusters parameter
    
    # top_targets = top_targets[np.unique(D_mat.ravel())]

    # top_labels = np.array([labels[idx] for idx in D_mat ])

    # clusters = [ top_targets[labels == k] for k in range(n_clusters)]

    kNN_alg = ['auto', 'ball_tree', 'kd_tree', 'brute']
    NN_IPs = 5

    # local prediction and blacklist generation part - this dictionary holds each contributor's local blacklist
   
    print 'Computing local predictions...'
    l_blacklists = dict()
    l_blacklists = ts.local_prediction(top_targets, train_set, i)      
    
    # clustering part 
    # TODO: play with kmeans, DBSCAN, KNN - also play with n_clusters parameter
    from collections import Counter
    for n_clusters in clusters_values:
        
        print 'Kvalue: ', n_clusters
        estimator = KMeans(n_clusters=n_clusters)
        X_train = o2o.sum(axis=2)
        labels = estimator.fit( X_train ).labels_ 

        #only the top 10% contributors per cluster is selected
        k_near = np.ceil((top_targets.size/n_clusters)*0.2)
        D_mat = estimator.transform(X_train).T.argsort(axis=1)[:,:int(k_near)]
        clusters = [ top_targets[idx] for idx in D_mat ]
        # global blacklist - this dictionary holds each contributor's global blacklist (i.e. the one generated from his cluster)
        gub_blacklists = dict()
    
        # intersection blacklist - this dictionary holds each contributor's intersection blacklist (i.e. the ips on his training set intersected 
        # with the blacklists of the contributors in his cluster)
        int_blacklists = dict()
    
        # ip2ip corelation blacklist
        ip2ip_blacklists = dict()
        
        # what happens in the cluster stays in the cluster     
        for subset in clusters:
            
            criterion = train_set.target_ip.map(lambda x: x in subset)
            logs = train_set[criterion].copy()
            top_attackers = getHeavyHitters( logs["src_ip"] ,0.9 )
            ind_ips = dict( zip(top_attackers, range(top_attackers.size) ) )
            reverse_ind_ips = dict( zip(ind_ips.values(), ind_ips.keys()) )

            criterion = logs.src_ip.map(lambda x: x in top_attackers)
            logs = logs[criterion]
            logs.src_ip = logs.src_ip.map(lambda x : ind_ips[x])

            df_gr = logs.groupby("D").apply(lambda x: np.bincount( x["src_ip"], minlength=top_attackers.size) )

            ip2ip = np.zeros( top_attackers.size**2, dtype=np.uint32)
            # create the ip2ip matrix for the cluster
            print 'computing ip2ip matrix...'
            for k, v in df_gr.iteritems():
                ip2ip += [np.uint32(min(f)) for f in product(v,v)]

            ip2ip = ip2ip.reshape(top_attackers.size, -1)
            # compute nearest neighbors based on the ip2ip matrix
            nbrs = NearestNeighbors(n_neighbors= min(NN_IPs,top_attackers.size), algorithm= kNN_alg[1]).fit( ip2ip )
            _, indices = nbrs.kneighbors(ip2ip)

            # for each attacker ip store the k corelated ips
            corelated_ips = dict()

            for idx, x in enumerate(indices):
                corelated_ips[reverse_ind_ips[idx]] = [reverse_ind_ips[y] for y in x]
        
            # get the cluster's contributors
            c_contributors = [x for x in subset]

            # compute the gub set for the cluster
            gub = set()
            gub = gub_prediction(c_contributors, l_blacklists)
            
            for contributor in c_contributors:
            
                gub_blacklists[contributor] = gub   
        
                # compute intersection blacklists
                int_set = set()
                int_set = intersection_prediction(contributor, c_contributors, l_blacklists, victim_set)
                int_blacklists[contributor] = int_set
                                        
                # make ip2ip corelation prediction
                ip2ip_set = set()
                ip2ip_set = ip2ip_prediction(contributor, l_blacklists, corelated_ips, top_attackers)
                ip2ip_blacklists[contributor] = ip2ip_set
                
           # del corelated_ips; del df_gr; del ip2ip; del top_attackers;
            
        # predictions verification part
        for target in top_targets:
            if target in np.unique(clusters):
                stats = verify_prediction(l_blacklists[target], gub_blacklists[target], int_blacklists[target], ip2ip_blacklists[target], set( test_set[ (test_set.target_ip == target) ].src_ip ) )
                stats["n_clusters"] = n_clusters
            else:
                #no sharing contribs
                stats = verify_prediction(l_blacklists[target], l_blacklists[target], l_blacklists[target], l_blacklists[target], set( test_set[ (test_set.target_ip == target) ].src_ip ) )
                stats["n_clusters"] = 0
            #stats = verify_prediction(l_blacklists[target], gub_blacklists[target], int_blacklists[target], set( test_set[ (test_set.target_ip == target) ].src_ip ) )

            stats["D"] = last_day
            stats["target"] = target

            stats_list.append(stats)    
    
        #del gub_blacklists; del int_blacklists; del ip2ip_blacklists
    
    #del train_set; del test_set; del window_logs; del l_blacklists
    
df_stats = pd.DataFrame(stats_list)

# print out some stats
compute_stats(df_stats)

# save the df for later processing
df_stats.to_pickle("k_means_stats.pkl")
