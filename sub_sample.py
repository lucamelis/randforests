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

from matplotlib import ticker

def my_formatter_fun(x, p):
    return "%.2f" % (x * (10 ** scale_pow))

for i in range(0,num_tests):
    start_day = day + dt.timedelta(days=i)
    fn = data_dir + "df_" + start_day.date().isoformat() +".pkl"
    end_day = start_day + dt.timedelta(days=6)
    print "file {}".format(fn)
    
    df_logs = pd.read_pickle(fn)
    logs_c = Counter(df_logs["target_ip"])    
    xs, freqs = zip( *sorted( logs_c.items(), key=operator.itemgetter(1), reverse=True) )

    sample_fn = data_dir + "df_sample_" + start_day.date().isoformat() +".pkl"
    
    df_logs[ df_logs.target_ip.map(lambda x: x in xs[ head_k:-tail_k ]) ].to_pickle(sample_fn)

    plt = subplot(5,2,i+1)
    plt.ticklabel_format(axis='y', style='sci', scilimits=(-2,2))
    plt.set_title("Time window {}".format(i+1) )
    plt.yaxis.set_ticks(np.arange(0, 1.5*10**6 + 1, 1*10**6))    
    bar(range(len(xs)), freqs)
    xlabel('contributors')
    ylabel('#logs')
    tight_layout()  
    grid(True)
    del df_logs


savefig("fig2.png")

