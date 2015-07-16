#!/usr/bin/python
# -*- coding: utf-8 -*-

from util import *

do_feat_extraction = False

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
    days = np.unique(df_logs['D'])
    first_day, max_day = np.min(days), np.max(days)

    df_logs.src_ip = df_logs.src_ip.map(lambda x: x[:11])
    df_logs.D = df_logs.D.map(lambda x: x - first_day)

    days = np.unique(df_logs['D'])
    first_day, last_day = np.min(days), np.max(days)

    #sources/targets who are both in train and test sets
    # GUB = set(df_logs[df_logs.D < last_day]["src_ip"]) & set(df_logs[df_logs.D == last_day]["src_ip"])
    # criterion = df_logs['src_ip'].map(lambda x: x in GUB)
    # df_logs = df_logs[criterion]
    
    GUB_targets = set(df_logs[df_logs.D < last_day]["target_ip"]) & set(df_logs[df_logs.D == last_day]["target_ip"])
    criterion = df_logs['target_ip'].map(lambda x: x in GUB_targets)
    df_logs = df_logs[criterion]


    top_targets = [ k for k,v in Counter( df_logs[df_logs.D < last_day]["target_ip"].to_dense() ).most_common(100) ]

    criterion = df_logs['target_ip'].map(lambda x: x in top_targets)
    df_logs = df_logs[criterion]

    st_cols = ['src_ip','target_ip','D',"label"]
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
        
    n_samples = df_logs.shape[0]
    print "Dataset size:\t",n_samples

    #last day items for the test set
    test_size = df_logs.D[df_logs.D == last_day].shape[0]
    train_size = n_samples - test_size

    print "Bloom filtering.."
    data = toBloomfeatures( df_logs[st_cols[0:2]] )
    data = np.hstack( (data, df_logs[st_cols[3]].as_matrix().reshape(n_samples,1) ) ) 
    print "feature space size", data.shape[1]

    # if do_feat_extraction:
    #     # data = encoder.fit_transform( df_logs[st_cols[0:3]].T.to_dict().values() )
    #     n_features = 3000 #int( np.sqrt(data.shape[1]) )
    #     svd = TruncatedSVD(n_components=n_features, random_state=42)
    #     #return dense array
    #     data = svd.fit_transform(data)
    #     print "std", data.std()**2

    # target_data = np.hstack( list([labeller.fit_transform( df_logs[label].to_dense() ).reshape(n_samples,1)  for label in labels] ) )
    # if len(labels)==1:
    target_data = labeller.fit_transform( df_logs["label"].to_dense() ).reshape(n_samples,1).ravel()

    # scaling data (mean=0, var=1)
    # data = preprocessing.scale(data)

    #train/test split
    X_train, Y_train = data[:train_size], target_data[:train_size]
    X_test, Y_test = data[X_train.shape[0]:], target_data[X_train.shape[0]:]

    # X_train, X_test, Y_train, Y_test = cross_validation.train_test_split(data, target_data, test_size=test_size, random_state=10)

    print "Train size:\t", X_train.shape[0]
    print "Test size:\t", X_test.shape[0]

    # print X_train.shape, Y_train.shape

    forest = ensemble.RandomForestClassifier( **forest_params )
    forest = forest.fit( X_train, Y_train )

    Y_pred = forest.predict(X_test)
    
    for target in top_targets:
        
        mask = np.array(df_logs[df_logs.D == last_day]["target_ip"] == target)
    
        stats = getPrediction(Y_pred[mask], Y_test[mask])
        stats["D"] = max_day 
        stats["target"] = target
        stats_list.append(stats)

    report = metrics.classification_report(Y_test, Y_pred ).splitlines()

df_stats = pd.DataFrame(stats_list)
df_stats.to_pickle("gub100.pkl")