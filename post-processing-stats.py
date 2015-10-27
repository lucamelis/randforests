#!/usr/bin/python
# -*- coding: utf-8 -*-

# file with utility variables & functions

import pandas as pd
import numpy as np 
import sys
import matplotlib.pyplot as plt

# compute the aggregated stats 
def compute_file_stats(method, stats):
    
    fi = open(method +'_overall_stats.txt', 'w')
    
    for k in np.unique(stats["n_clusters"]):
        
        k_stats = stats[stats.n_clusters == k]
        
        fi.write('*********************************')
        fi.write('\n')
        fi.write('N_clusters: ' + str(k))
        fi.write('\n')
        fi.write('Average Cluster Size: ' + str(k_stats['avg_cluster_size'].mean()))
        fi.write('*********************************')
        fi.write('\n')
        fi.write('---------------------TP---------------')
        fi.write('\n')
        fi.write('Local TP: ' + str(k_stats['tp_local'].sum()))
        fi.write('\n')
        fi.write('Global TP: ' + str(k_stats['tp_gub'].sum()))
        fi.write('\n')
        fi.write('Int TP: ' + str(k_stats['tp_int'].sum()))
        fi.write('\n')
        fi.write('Ip2ip TP: ' + str(k_stats['tp_ip2ip'].sum()))
        fi.write('\n')
        fi.write('Int Ip2ip TP: ' + str(k_stats['tp_int_ip2ip'].sum()))
        fi.write('\n')
        
        fi.write('-----------Stats----------')
        fi.write('\n')        
        fi.write('TP Improvement of global over local: Mean | Std | Max | Min ' + str( k_stats['tp_impr_gub'].mean() ) + '|' + str( k_stats['tp_impr_gub'].std() ) + '|' 
        + str( k_stats['tp_impr_gub'].max() ) + '|' + str( k_stats['tp_impr_gub'].min() ))
        fi.write('\n')
        
        fi.write('-----------------------------')    
        fi.write('\n')    
        fi.write('TP Improvement of intersection over local: Mean | Std | Max | Min ' + str( k_stats['tp_impr_int'].mean()) + '|' + str( k_stats['tp_impr_int'].std() ) 
        + '|' + str( k_stats['tp_impr_int'].max() ) + '|' + str( k_stats['tp_impr_int'].min() ))
        fi.write('\n')
        
        fi.write('-----------------------------')  
        fi.write('\n')      
        fi.write('TP Improvement of ip2ip over local: Mean | Std | Max | Min ' + str(k_stats['tp_impr_ip2ip'].mean()) + '|' + str(k_stats['tp_impr_ip2ip'].std())
        + '|' + str(k_stats['tp_impr_ip2ip'].max()) + '|' + str(k_stats['tp_impr_ip2ip'].min()))
        fi.write('\n')
        
        fi.write('-----------------------------')        
        fi.write('\n')
        fi.write('TP Improvement of int ip2ip over local: Mean | Std | Max | Min ' + str(k_stats['tp_impr_int_ip2ip'].mean() ) + '|' + str(k_stats['tp_impr_int_ip2ip'].std() )
        + '|' + str(k_stats['tp_impr_int_ip2ip'].max() ) + '|' + str(k_stats['tp_impr_int_ip2ip'].min() ))
        fi.write('\n')
        
        fi.write('-------------FP----------')
        fi.write('\n')
        
        fi.write('Local FP: ' + str(k_stats['fp_local'].sum()))
        fi.write('\n')
        fi.write('Global FP: ' + str(k_stats['fp_gub'].sum()))
        fi.write('\n')
        fi.write('Int FP: ' + str(k_stats['fp_int'].sum()))
        fi.write('\n')
        fi.write('Ip2ip FP: ' + str(k_stats['fp_ip2ip'].sum()))
        fi.write('\n')
        fi.write('Int Ip2ip FP: ' + str(k_stats['fp_int_ip2ip'].sum()))
        fi.write('\n')
        
        fi.write('-------------------------')
        fi.write('\n')
        fi.write('FP Increase of global over local: Mean | Std | Max | Min '  + str( k_stats['fp_incr_gub'].mean() ) + '|' + str( k_stats['fp_incr_gub'].std() ) + 
        '|' + str( k_stats['fp_incr_gub'].max() ) + '|' + str( k_stats['fp_incr_gub'].min() ))
        fi.write('\n')
        
        fi.write('-------------------------')
        fi.write('\n')
        fi.write('Avg FP Increase of intersection over local: Mean | Std | Max | Min ' + str(k_stats['fp_incr_int'].mean()) + '|' + str(k_stats['fp_incr_int'].std()) + '|' + 
        str(k_stats['fp_incr_int'].max()) + '|' + str(k_stats['fp_incr_int'].min()))
        fi.write('\n')
        
        fi.write('-------------------------')
        fi.write('\n')
        fi.write('Avg FP Increase of ip2ip over local: Mean | Std | Max | Min ' + str(k_stats['fp_incr_ip2ip'].mean() ) + '|' + str(k_stats['fp_incr_ip2ip'].std() ) + '|' +
        str(k_stats['fp_incr_ip2ip'].max() ) + '|' + str(k_stats['fp_incr_ip2ip'].min() ))
        fi.write('\n')
        
        fi.write('-------------------------')
        fi.write('\n')
        fi.write('Avg FP Increase of int ip2ip over local: Mean | Std | Max | Min ' + str(k_stats['fp_incr_int_ip2ip'].mean()) + '|' + str(k_stats['fp_incr_int_ip2ip'].std() ) +
         '|' + str(k_stats['fp_incr_int_ip2ip'].max()) + '|' + str(k_stats['fp_incr_int_ip2ip'].min()))
        fi.write('\n')
        
    fi.close()

# compute true positive rate and false positive rate for each k and log sharing method
def compute_tpr_fpr(method, stats):
    
    fi = open(method +'_tpr_fpr_stats.txt', 'w')
    
    for k in np.unique(stats["n_clusters"]):
        
        k_stats = stats[stats.n_clusters == k]
        
        fi.write('*********************************')
        fi.write('\n')
        fi.write('N_clusters: ' + str(k))
        fi.write('\n')
        fi.write('---------------------TPR---------------')
        fi.write('\n')
        fi.write('Local TPR: ' + str( k_stats['tp_local'].sum() / float(k_stats['tp_local'].sum() + k_stats['fn_local'].sum()) ))
        fi.write('\n')
        fi.write('Global TPR: ' + str( k_stats['tp_gub'].sum() / float(k_stats['tp_gub'].sum() + k_stats['fn_local'].sum()) ))
        fi.write('\n')
        fi.write('Int TPR: ' + str( k_stats['tp_int'].sum() / float(k_stats['tp_int'].sum() + k_stats['fn_local'].sum()) ))
        fi.write('\n')
        fi.write('Ip2ip TPR: ' + str( k_stats['tp_ip2ip'].sum() / float(k_stats['tp_ip2ip'].sum() + k_stats['fn_local'].sum()) ))
        fi.write('\n')
        fi.write('Int Ip2ip TPR: ' + str( k_stats['tp_int_ip2ip'].sum() / float(k_stats['tp_int_ip2ip'].sum() + k_stats['fn_local'].sum()) ))
        fi.write('\n')
            
        fi.write('-------------FPR----------')
        fi.write('\n')
        
        fi.write('Local FPR: ' + str(k_stats['fp_local'].sum() / float(k_stats['fp_local'].sum() + k_stats['tn_local'].sum()) ))
        fi.write('\n')
        fi.write('Global FPR: ' + str(k_stats['fp_gub'].sum() / float(k_stats['fp_gub'].sum() + k_stats['tn_local'].sum()) ))
        fi.write('\n')
        fi.write('Int FPR: ' + str(k_stats['fp_int'].sum() / float(k_stats['fp_int'].sum() + k_stats['tn_local'].sum()) ))
        fi.write('\n')
        fi.write('Ip2ip FPR: ' + str(k_stats['fp_ip2ip'].sum() / float(k_stats['fp_ip2ip'].sum() + k_stats['tn_local'].sum()) ))
        fi.write('\n')
        fi.write('Int Ip2ip FPR: ' + str(k_stats['fp_int_ip2ip'].sum() / float(k_stats['fp_int_ip2ip'].sum() + k_stats['tn_local'].sum()) ))
        fi.write('\n')
                
    fi.close()
    
def plot_tpr(method, stats):
    
    k_values = []
    local_tpr = []; gub_tpr = []; int_tpr = []; ip2ip_tpr = []; int_ip2ip_tpr = []
    
    for k in np.unique(stats["n_clusters"]):
        if k!=0:
            k_stats = stats[stats.n_clusters == k]
            k_values.append(k)
            local_tpr.append(k_stats['tp_local'].sum() / float(k_stats['tp_local'].sum() + k_stats['fn_local'].sum())) 
            gub_tpr.append(k_stats['tp_gub'].sum() / float(k_stats['tp_gub'].sum() + k_stats['fn_local'].sum()))
            int_tpr.append(k_stats['tp_int'].sum() / float(k_stats['tp_int'].sum() + k_stats['fn_local'].sum()))
            ip2ip_tpr.append(k_stats['tp_ip2ip'].sum() / float(k_stats['tp_ip2ip'].sum() + k_stats['fn_local'].sum()))
            int_ip2ip_tpr.append(k_stats['tp_int_ip2ip'].sum() / float(k_stats['tp_int_ip2ip'].sum() + k_stats['fn_local'].sum()))
            
    plt.xlabel(method + ' k')
    plt.ylabel('True Positive Rate (TPR)')

    plt.plot(k_values, local_tpr, 'm', label='Local', marker = 's')
    plt.plot(k_values, gub_tpr, 'r', label='Global', marker = '*')
    plt.plot(k_values, int_tpr, 'g', label='Intersection', marker = '.')
    plt.plot(k_values, ip2ip_tpr, 'y', label='Ip2Ip', marker = '+')
    plt.plot(k_values, int_ip2ip_tpr, 'b', label='Ip2Ip + Intersection', marker = 'o')

    legend = plt.legend(loc='upper right', fontsize='x-small') 

    #plt.show()
    plt.savefig(method + '-TPR.pdf')
    plt.close()        

def plot_fpr(method, stats):            
    
    k_values = []
    local_fpr = []; gub_fpr = []; int_fpr = []; ip2ip_fpr = []; int_ip2ip_fpr = []
    
    for k in np.unique(stats["n_clusters"]):
        if k!=0:
            k_stats = stats[stats.n_clusters == k]
            k_values.append(k)
            local_fpr.append(k_stats['fp_local'].sum() / float(k_stats['fp_local'].sum() + k_stats['tn_local'].sum())) 
            gub_fpr.append(k_stats['fp_gub'].sum() / float(k_stats['fp_gub'].sum() + k_stats['tn_local'].sum()))
            int_fpr.append(k_stats['fp_int'].sum() / float(k_stats['fp_int'].sum() + k_stats['tn_local'].sum()))
            ip2ip_fpr.append(k_stats['fp_ip2ip'].sum() / float(k_stats['fp_ip2ip'].sum() + k_stats['tn_local'].sum()))
            int_ip2ip_fpr.append(k_stats['fp_int_ip2ip'].sum() / float(k_stats['fp_int_ip2ip'].sum() + k_stats['tn_local'].sum()))
            
    plt.xlabel(method + ' k')
    plt.ylabel('False Positive Rate (FPR)')

    plt.plot(k_values, local_fpr, 'm', label='Local', marker = 's')
    plt.plot(k_values, gub_fpr, 'r', label='Global', marker = '*')
    plt.plot(k_values, int_fpr, 'g', label='Intersection', marker = '.')
    plt.plot(k_values, ip2ip_fpr, 'y', label='Ip2Ip', marker = '+')
    plt.plot(k_values, int_ip2ip_fpr, 'b', label='Ip2Ip + Intersection', marker = 'o')

    legend = plt.legend(loc='upper right', fontsize='x-small') 

    plt.savefig(method + '-FPR.pdf')
    plt.close()

def plot_precision(method, stats):
    k_values = []
    local_pr = []; gub_pr = []; int_pr = []; ip2ip_pr = []; int_ip2ip_pr = []
    
    for k in np.unique(stats["n_clusters"]):
        if k!=0:
            k_stats = stats[stats.n_clusters == k]
            k_values.append(k)
            local_pr.append(k_stats['tp_local'].sum() / float(k_stats['tp_local'].sum() + k_stats['fp_local'].sum())) 
            gub_pr.append(k_stats['tp_gub'].sum() / float(k_stats['tp_gub'].sum() + k_stats['fp_gub'].sum()))
            int_pr.append(k_stats['tp_int'].sum() / float(k_stats['tp_int'].sum() + k_stats['fp_int'].sum()))
            ip2ip_pr.append(k_stats['tp_ip2ip'].sum() / float(k_stats['tp_ip2ip'].sum() + k_stats['fp_ip2ip'].sum()))
            int_ip2ip_pr.append(k_stats['tp_int_ip2ip'].sum() / float(k_stats['tp_int_ip2ip'].sum() + k_stats['fp_int_ip2ip'].sum()))
            
    plt.xlabel(method + ' k')
    plt.ylabel('Precision (PPV)')

    plt.plot(k_values, local_pr, 'm', label='Local', marker = 's')
    plt.plot(k_values, gub_pr, 'r', label='Global', marker = '*')
    plt.plot(k_values, int_pr, 'g', label='Intersection', marker = '.')
    plt.plot(k_values, ip2ip_pr, 'y', label='Ip2Ip', marker = '+')
    plt.plot(k_values, int_ip2ip_pr, 'b', label='Ip2Ip + Intersection', marker = 'o')

    legend = plt.legend(loc='upper right', fontsize='x-small') 

    plt.savefig(method + '-PPV.pdf')
    plt.close()
            
def plot_avg_cluster_size(method, stats):
    
    k_values=[]
    avg_cluster_size = []
    
    for k in np.unique(stats["n_clusters"]):
        if k!= 0:
            k_values.append(k)
            k_stats = stats[stats.n_clusters == k]
            avg_cluster_size.append(k_stats['avg_cluster_size'].mean())
        
    #ax = [k_values[0], k_values[-1], min(min(local_tp), min(gub_tp), min(int_tp), min(ip2ip_tp), min(int_ip2ip_tp), max(max(gub_tp), max())]

    plt.xlabel(method + ' k')
    plt.ylabel('Average Size of clusters')

    #plt.axis(ax)

    plt.plot(k_values, avg_cluster_size, 'm', marker = 's')

    #legend = plt.legend(loc='upper right', fontsize='x-small') 

    #plt.show()
    plt.savefig(method + '-avg-size-of-clusters.pdf')
    plt.close()
    
# compute the aggregated stats 
def plot_true_positives(method, stats):
    
    k_values = []; 
    local_tp = []; gub_tp = []; int_tp = []; ip2ip_tp = []; int_ip2ip_tp = []
    
    for k in np.unique(stats["n_clusters"]):
        if k!= 0:
            k_values.append(k)
            k_stats = stats[stats.n_clusters == k]
            local_tp.append(k_stats['tp_local'].sum())
            gub_tp.append(k_stats['tp_gub'].sum())
            int_tp.append(k_stats['tp_int'].sum())
            ip2ip_tp.append(k_stats['tp_ip2ip'].sum())
            int_ip2ip_tp.append(k_stats['tp_int_ip2ip'].sum())
        
    #ax = [k_values[0], k_values[-1], min(min(local_tp), min(gub_tp), min(int_tp), min(ip2ip_tp), min(int_ip2ip_tp), max(max(gub_tp), max())]

    plt.xlabel(method + ' k')
    plt.ylabel('# of True Positives (TP)')

    #plt.axis(ax)

    plt.plot(k_values, local_tp, 'm', label='Local', marker = 's')
    plt.plot(k_values, gub_tp, 'r', label='Global', marker = '*')
    plt.plot(k_values, int_tp, 'g', label='Intersection', marker = '.')
    plt.plot(k_values, ip2ip_tp, 'y', label='Ip2Ip', marker = '+')
    plt.plot(k_values, int_ip2ip_tp, 'b', label='Ip2Ip + Intersection', marker = 'o')

    legend = plt.legend(loc='lower right', fontsize='x-small') 

    #plt.show()
    plt.savefig(method + '-tp.pdf')
    plt.close()

def plot_false_positives(method, stats):
        
    k_values = []
    local_fp = []; gub_fp = []; int_fp = []; ip2ip_fp = []; int_ip2ip_fp = []
    
    for k in np.unique(stats["n_clusters"]):
        if k!= 0:
            k_values.append(k)
            k_stats = stats[stats.n_clusters == k]
            local_fp.append(k_stats['fp_local'].sum())
            gub_fp.append(k_stats['fp_gub'].sum())
            int_fp.append(k_stats['fp_int'].sum())
            ip2ip_fp.append(k_stats['fp_ip2ip'].sum())
            int_ip2ip_fp.append(k_stats['fp_int_ip2ip'].sum())
        
#    ax = [k_values[0], k_values[-1], min(local_fp), max(gub_fp)]

    plt.xlabel(method + ' k')
    plt.ylabel('# of False Positives (FP)')

 #   plt.axis(ax)

    plt.plot(k_values, local_fp, 'm', label='Local', marker = 's')
    plt.plot(k_values, gub_fp, 'r', label='Global', marker = '*')
    plt.plot(k_values, int_fp, 'g', label='Intersection', marker = '.')
    plt.plot(k_values, ip2ip_fp, 'y', label='Ip2Ip', marker = '+')
    plt.plot(k_values, int_ip2ip_fp, 'b', label='Ip2Ip + Intersection', marker = 'o')

    legend = plt.legend(loc='upper right', fontsize='x-small') 

    #plt.show()
    plt.savefig(method + '-fp.pdf')    
    plt.close()    
    
def plot_tp_improvement(method, stats):
    
    k_values = []
    gub_tp_impr = []; int_tp_impr = []; ip2ip_tp_impr = []; int_ip2ip_tp_impr = []
    
    for k in np.unique(stats["n_clusters"]):
        if k!= 0 :
            k_values.append(k)
            k_stats = stats[stats.n_clusters == k]
            gub_tp_impr.append(k_stats['tp_impr_gub'].mean())
            int_tp_impr.append(k_stats['tp_impr_int'].mean())
            ip2ip_tp_impr.append(k_stats['tp_impr_ip2ip'].mean())
            int_ip2ip_tp_impr.append(k_stats['tp_impr_int_ip2ip'].mean())
    
    plt.xlabel(method + ' k')
    plt.ylabel('Average Improvement of True Positives (TP)')

    #   plt.axis(ax)

    plt.plot(k_values, gub_tp_impr, 'r', label='Global', marker = '*')
    plt.plot(k_values, int_tp_impr, 'g', label='Intersection', marker = '.')
    plt.plot(k_values, ip2ip_tp_impr, 'y', label='Ip2Ip', marker = '+')
    plt.plot(k_values, int_ip2ip_tp_impr, 'b', label='Ip2Ip + Intersection', marker = 'o')

    legend = plt.legend(loc='upper right', fontsize='x-small') 

    #plt.show()
    plt.savefig(method + '-avg-tp-impr.pdf')    
    plt.close()                    

def plot_fp_increase(method, stats):
    
    k_values = []
    gub_fp_impr = []; int_fp_impr = []; ip2ip_fp_impr = []; int_ip2ip_fp_impr = []
    
    for k in np.unique(stats["n_clusters"]):
        if k!= 0 :
            k_values.append(k)
            k_stats = stats[stats.n_clusters == k]
            gub_fp_impr.append(k_stats['fp_incr_gub'].mean())
            int_fp_impr.append(k_stats['fp_incr_int'].mean())
            ip2ip_fp_impr.append(k_stats['fp_incr_ip2ip'].mean())
            int_ip2ip_fp_impr.append(k_stats['fp_incr_int_ip2ip'].mean())
    
    plt.xlabel(method + ' k')
    plt.ylabel('Average Increase of False Positives (FP)')

    #   plt.axis(ax)

    plt.plot(k_values, gub_fp_impr, 'r', label='Global', marker = '*')
    plt.plot(k_values, int_fp_impr, 'g', label='Intersection', marker = '.')
    plt.plot(k_values, ip2ip_fp_impr, 'y', label='Ip2Ip', marker = '+')
    plt.plot(k_values, int_ip2ip_fp_impr, 'b', label='Ip2Ip + Intersection', marker = 'o')

    legend = plt.legend(loc='upper right', fontsize='x-small') 

    #plt.show()
    plt.savefig(method + '-avg-fp-impr.pdf')    
    plt.close()
              
print 'Argument List:', str(sys.argv)
data_dir = sys.argv[1] 
df = pd.read_pickle(data_dir)

alg = 'KMeans'

compute_file_stats(alg, df)
compute_tpr_fpr(alg, df)
plot_avg_cluster_size(alg, df)
plot_true_positives(alg, df)
plot_false_positives(alg, df)
plot_tp_improvement(alg, df)
plot_fp_increase(alg, df)
plot_tpr(alg, df)
plot_fpr(alg, df)
plot_precision(alg, df)