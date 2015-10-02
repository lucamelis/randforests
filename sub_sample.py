#!/usr/bin/python
# -*- coding: utf-8 -*-

from util import *
from collections import Counter
import operator
from pylab import *

day = dt.datetime(2015,05,17)
num_tests = 10
head_k = 10
tail_k = 20

for i in range(0,num_tests):
    start_day = day + dt.timedelta(days=i)
    fn = data_dir + "df_" + start_day.date().isoformat() +".pkl"
    
    print "file {}".format(fn)
    
    df_logs = pd.read_pickle(fn)
    logs_c = Counter(df_logs["target_ip"])    
    xs, freqs = zip( *sorted( logs_c.items(), key=operator.itemgetter(1), reverse=True) )

    sample_fn = data_dir + "df_sample_" + start_day.date().isoformat() +".pkl"
    
    df_logs[ df_logs.target_ip.map(lambda x: x in xs[ head_k:-tail_k ]) ].to_pickle(sample_fn)

    # subplot(5,2,i+1)
    # tight_layout()  
    # bar(range(len(xs)), freqs)
    # xlabel('contributors')
    # ylabel('#logs')
    # grid(True)

    del df_logs


# savefig("fig.png")

