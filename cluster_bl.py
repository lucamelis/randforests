#!/usr/bin/python
# -*- coding: utf-8 -*-

from util import *
from itertools import combinations

from sklearn.cluster import KMeans
from scipy.stats import itemfreq


do_feat_extraction = False

stats_list = [ ]

for i in range(0,num_tests):
    start_day = day + dt.timedelta(days=i)
    # df_logs = loadData(start_day, parser_params)
    
    # df_logs = pd.read_csv(data_dir + "logs"+ start_day.date().isoformat()+".txt", **parser_params )
    # print start_day.date().isoformat()
    
    #extract 24/ subnets from IPs
    df_logs.src_ip = df_logs.src_ip.map(lambda x: x[:11])

    top_targets = np.unique( df_logs["target_ip"] )

    days = np.unique(df_logs['D'])
    first_day, last_day = np.min(days), np.max(days)

    target_pairs = combinations(top_targets,2)

    ind_dic = dict( zip(top_targets, range(top_targets.size) ) )

    obs_mat = np.zeros((top_targets.size, top_targets.size, days.size))

    for pair in target_pairs:
        for day in days:
            obs_mat[ind_dic[pair[0]],ind_dic[pair[1]], day] = len( set( df_logs[df.logs.target_ip == k && df.logs.D == day].src_ip) 
                     & set( df_logs[df.logs.target_ip == v && df.logs.D == day].src_ip) )
            obs_mat[ind_dic[pair[1]],ind_dic[pair[0]], day] = obs_mat[ind_dic[pair[0]], ind_dic[pair[1]], day]        


    # X = obs_mat.(top_targets.size, top_targets.size * days.size )

    ##O2O clustering: kmeans, DBSCAN, KNN
    ## play with n_clusters parameter
    n_clusters = 10
    estimator = KMeans(n_clusters=n_clusters)
    
    labels = estimator.fit( obs_mat.sum(axis=2) ).labels_ 
    
    clusters = [ top_targets[labels == i] for i in range(n_clusters) ]

    topIP_clusters = []
    kNN_alg = ['auto', 'ball_tree', 'kd_tree', 'brute']
    NN_IPs = 2

    for subset in clusters:
        criterion = df_logs.target_ip.map(lambda x: x in subset)
        logs = df_logs[criterion]

        attackers = np.unique(logs["src_ip"])

        ind_ips = dict( zip(attackers, range(attackers.size) ) )
        logs.src_ip = logs.src_ip.map(lambda x : ind_ips[x])

        df_gr = logs.groupby("D").apply(lambda x: np.bincount( x["src_ip"], minlength=attackers.size) )

        IP_IP = np.zeros(attackers.size**2 )
        for k,v in df_gr.itemfreq():
            IP_IP += [min(i) for i in product(v,v)]

        IP_IP = IP_IP.reshape(attackers.size,-1)

        nbrs = NearestNeighbors(n_neighbors= NN_IPs, algorithm= kNN_alg[1] ).fit( IP_IP )
        _, indices = nbrs.kneighbors(IP_IP)

        np.append(topIP_clusters, attackers[indices] )       

    for target in top_targets:    
        stats = getPrediction( blacklist, whitelist, test_attackers[target] )
        
        stats["D"] = last_day   
        stats["target"] = target        

        stats["whitelist"] = whitelist
        stats["blacklist"] = blacklist
        stats["attacks"] = test_attackers
                        
        stats_list.append(stats)
        

df_stats = pd.DataFrame(stats_list)
df_stats.to_pickle("gub100.pkl")