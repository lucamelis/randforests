#!/usr/bin/python
# -*- coding: utf-8 -*-

from util import *

from itertools import combinations
import operator

do_feat_extraction = True

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
    df_logs.src_ip = df_logs.src_ip.map(lambda x: x[:11])

    #extract 24/ subnets from IPs
    days = np.unique(df_logs['D'])
    first_day, max_day = np.min(days), np.max(days)

    df_logs.D = df_logs.D.map(lambda x: x - first_day)

    days = np.unique(df_logs['D'])
    first_day, last_day = np.min(days), np.max(days)

    #targetes who are both in train and test set
    # GUB = set(df_logs[df_logs.D < last_day]["src_ip"]) & set(df_logs[df_logs.D == last_day]["src_ip"])
    # criterion = df_logs['src_ip'].map(lambda x: x in GUB)
    # df_logs = df_logs[criterion]
    
    GUB_targets = set(df_logs[df_logs.D < last_day]["target_ip"]) & set(df_logs[df_logs.D == last_day]["target_ip"])
    criterion = df_logs['target_ip'].map(lambda x: x in GUB_targets)
    df_logs = df_logs[criterion]

    top_targets = [ k for k,v in Counter( df_logs[df_logs.D < last_day]["target_ip"].to_dense() ).most_common(100) ]
    
    target_pairs = combinations(top_targets,2)

    criterion = df_logs['target_ip'].map(lambda x: x in top_targets)
    df_logs = df_logs[criterion]    
    
    st_cols = ['src_ip','target_ip','D',"label"]

    #assinging labels to attacks/not attacks
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
        
    dictionary = {}   
    for pair in target_pairs:
        #pair victim logs
        A = set(df_logs[df_logs.target_ip == pair[0]].src_ip)
        B = set(df_logs[df_logs.target_ip == pair[1]].src_ip)
        dictionary[pair] = len(A & B)
    
    contrib_sorted = sorted(dictionary.items(), key=operator.itemgetter(1), reverse=True)
    
    collaborator_dict = {}
    for i in top_targets:
        s = [target[1] for target,numb in contrib_sorted[0:50] if target[0] == i]
        if len(s) > 0:
            collaborator_dict[i] = s

    # for pair,n_contrib in contrib_sorted[0:50]:  
    for collaborator in collaborator_dict:        
        criterion = df_logs["target_ip"].map(lambda x: x in collaborator_dict[collaborator])
        pair_logs = df_logs[criterion] 
        
        n_samples = pair_logs.shape[0]
        print "Victim Dataset size:\t",n_samples

        #last day items for the test set
        test_size = pair_logs.D[pair_logs.D == last_day].shape[0] 
        train_size = n_samples - test_size

        data = encoder.fit_transform( pair_logs[["src_ip","D"]].T.to_dict().values() )
        
        if do_feat_extraction:
            n_features = int( np.sqrt(data.shape[1]) )
            svd = TruncatedSVD(n_components=n_features, random_state=42)
            #return dense array
            data = svd.fit_transform(data)

        # scaling data (mean=0, var=1)
        # data = preprocessing.scale(data)

        target_data = labeller.fit_transform( pair_logs["label"].to_dense() ).reshape(n_samples,1).ravel()

        #train/test split
        X_train, Y_train = data[:train_size], target_data[:train_size]
        X_test, Y_test = data[X_train.shape[0]:], target_data[X_train.shape[0]:]

        print "Train size:\t", X_train.shape[0]
        print "Test size:\t", X_test.shape[0]

        forest = ensemble.RandomForestClassifier( **forest_params )
        forest = forest.fit( X_train, Y_train )

        Y_pred = forest.predict(X_test)
                    
        stats = getPrediction(Y_pred, Y_test)
        stats["D"] = max_day   
        stats["buddy"] = collaborator
        # stats["buddy2"] = pair[1]
        # stats["inter_size"] = n_contrib
        stats_list.append(stats)

df_stats = pd.DataFrame(stats_list)
df_stats.to_pickle("share100new.pkl")
