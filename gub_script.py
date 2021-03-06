#!/usr/bin/python
# -*- coding: utf-8 -*-

from util import *

do_feat_extraction = False

stats_list = [ ]

for i in range(0,num_tests):
    start_day = day + dt.timedelta(days=i)
    # df_logs = pd.read_csv(data_dir + "logs"+ start_day.date().isoformat()+".txt", **parser_params )
    # print start_day.date().isoformat()

    st_cols = ['src_ip','target_ip','D',"label"]

    # df_logs = pd.read_pickle(data_dir + "df_" + start_day.date().isoformat() + ".pkl")
    # print "..predicting ",start_day.date().isoformat() 

    df_logs = loadData(start_day, parser_params)

    
    #extract 24/ subnets from IPs
    df_logs.src_ip = df_logs.src_ip.map(lambda x: x[:11])

    top_targets = np.unique( df_logs["target_ip"] )

    days = np.unique(df_logs['D'])
    first_day, last_day = np.min(days), np.max(days)
    
    df_gr = df_logs.groupby( st_cols[0:2] ).apply(lambda x: np.bincount( np.unique(x["D"]), minlength=len(days) ) )

    #assinging labels to attacks/not attacks
    grouped = df_logs.groupby( st_cols[0:2] )

    # attacks
    positives_logs = pd.DataFrame(
        [ [k[0], k[1], s, 1] for k,v in grouped["D"] for s in set(np.unique(v)) ], columns = st_cols)
    #not attacks
    negatives_logs = pd.DataFrame(
        [ [k[0], k[1], s, 0] for k,v in grouped["D"] for s in set(days) - set(np.unique(v)) ], columns = st_cols)
    
    #not-attacks equal-size sampling for each day 
    for i in days:
        day_logs = positives_logs[positives_logs.D == i].shape[0]
        positives_logs = positives_logs.append( negatives_logs[negatives_logs.D == i].sample(n=day_logs) , ignore_index=True)

    df_logs = positives_logs.sort("D") 
    
    train_logs = df_logs[df_logs.D < last_day]

    #for each victim
    test_attackers = { }
    for target in top_targets:
        test_attackers[target] = set( df_logs[ (df_logs.target_ip == target) & (df_logs.D == last_day) & (df_logs.label == 1)].src_ip.to_dense() )  

    train_src_ips = np.unique( df_logs[ (df_logs.D < last_day) & (df_logs.label == 1) ].src_ip )

    test_logs = pd.DataFrame([ [src_ip, target, last_day, 1 ] for src_ip in train_src_ips ], columns = st_cols)

    df_logs = train_logs.append(test_logs, ignore_index=True)

    n_samples = df_logs.shape[0]
    print "Victim Dataset size:\t",n_samples

        #last day items for the test set
    test_size = df_logs.D[df_logs.D == last_day].shape[0] 
    train_size = n_samples - test_size

    time_feat = labeller.fit_transform( df_logs['D'] )#.map( lambda x: ( x - first_day ).days )

    print "Bloom filtering.."
    data = toBloomfeatures( df_logs[ st_cols[0:2] ] )
    data = sparse.hstack( (data, time_feat.as_matrix().reshape(n_samples,1) ) ) 
    print "Feature space size:", data.shape[1]
    target_data = labeller.fit_transform( df_logs["label"].to_dense() ).reshape(n_samples,1).ravel()

    #train/test split
    X_train, Y_train = data.A[:train_size], target_data[:train_size]
    X_test, Y_test = data.A[X_train.shape[0]:], target_data[X_train.shape[0]:]

    print "Train size:\t", X_train.shape[0]
    print "Test size:\t", X_test.shape[0]

    forest = ensemble.RandomForestRegressor( **forest_params )
    forest = forest.fit( X_train, Y_train )
        
    Y_train = np.round( forest.predict(X_train) )

    Y_pred = np.round( forest.predict(X_test) )
              
    blacklist = set( df_logs.src_ip[X_train.shape[0]:][Y_pred == 1] )
    whitelist = set( df_logs.src_ip[X_train.shape[0]:][Y_pred == 0] )
    
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