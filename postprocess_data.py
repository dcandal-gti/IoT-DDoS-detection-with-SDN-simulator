# -*- coding: utf-8 -*-
"""
Created on Tue Aug 18 18:51:59 2020

@author: david
"""
import json
import sys, getopt
import numpy as np
from scipy import stats
import fcntl


def load_json(results_file):
    result = None
    if results_file:
        with open(results_file, 'r') as f:
            result = json.load(f)
    return result

def compute_confidence_interval(data, confidence=0.95):
    if (min(data) == max(data)):
        h = 0
    else:
        a = 1.0*np.array(data)
        n = len(a)
        se = stats.sem(a)
        h = se * stats.t._ppf((1+confidence)/2., n-1)
    return h


def postprocessing(results_file, matlab_script_file, var1_name, var2_name):
    data = load_json(results_file)
    malicious_quarantined = {}
    malicious_quarantined_errorbars = {}
    legitimate_quarantined = {}
    legitimate_quarantined_errorbars = {}
    var1_array = []
    var2_array = []
    
    for entry in data:
        var1 = entry[var1_name]
        var2 = entry[var2_name]
        if var1 not in var1_array:
            var1_array.append(var1)
        if var2 not in var2_array:
            var2_array.append(var2)
        
        malicious_quarantined_array = entry["malicious_quarantined_array"]
        malicious_array = entry["malicious_array"]
        acc = []
        for quarantined,total in zip(malicious_quarantined_array,malicious_array):
            if total != 0:
                acc.append(quarantined/total)
        malicious_quarantined[(var1, var2)] = np.mean(acc) if acc else None
        malicious_quarantined_errorbars[(var1, var2)] = compute_confidence_interval(acc) if acc else None
        
        legitimate_quarantined_array = entry["legitimate_quarantined_array"]
        legitimate_array = entry["legitimate_array"]
        acc = []
        for legitimate,total in zip(legitimate_quarantined_array,legitimate_array):
            if total != 0:
                acc.append(legitimate/total)
        legitimate_quarantined[(var1, var2)] = np.mean(acc) if acc else None
        legitimate_quarantined_errorbars[(var1, var2)] = compute_confidence_interval(acc) if acc else None

    # Custom sort
    var1_array = list(np.sort(var1_array))
    var2_array = list(np.sort(var2_array))
    results_m = []; results_m_error = []
    results_l = []; results_l_error = []
    for var2 in var2_array:
        results_mdp_m = []; results_mdp_m_error = []
        results_mdp_l = []; results_mdp_l_error = []
        for var1 in var1_array:
            results_mdp_m.append(malicious_quarantined[(var1, var2)])
            results_mdp_l.append(legitimate_quarantined[(var1, var2)])
            results_mdp_m_error.append(malicious_quarantined_errorbars[(var1, var2)])
            results_mdp_l_error.append(legitimate_quarantined_errorbars[(var1, var2)])
        results_m.append(results_mdp_m)
        results_l.append(results_mdp_l)
        results_m_error.append(results_mdp_m_error)
        results_l_error.append(results_mdp_l_error)
        
    # Conversion to Matlab script
    nl = "\n"
    tab = "\t"
    script = f"""{var1_name} = {var1_array};{nl}{var2_name} = {var2_array};
{nl}malicious_quarantined = {str(results_m).replace("None","nan").replace("[[",f"[{nl}{tab}[").replace("], [", f"],{nl}{tab}[").replace("]]",f"]{nl}]")};
{nl}malicious_quarantined_errorbars = {str(results_m_error).replace("None","nan").replace("[[",f"[{nl}{tab}[").replace("], [", f"],{nl}{tab}[").replace("]]",f"]{nl}]")};
{nl}legitimate_quarantined = {str(results_l).replace("None","nan").replace("[[",f"[{nl}{tab}[").replace("], [", f"],{nl}{tab}[").replace("]]",f"]{nl}]")};
{nl}legitimate_quarantined_errorbars = {str(results_l_error).replace("None","nan").replace("[[",f"[{nl}{tab}[").replace("], [", f"],{nl}{tab}[").replace("]]",f"]{nl}]")};"""
    # Write script in file
    with open(matlab_script_file, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(script)
        fcntl.flock(f, fcntl.LOCK_UN)


def main(argv):
    # Read input arguments
    try:
        opts, args = getopt.getopt(argv,"",["figure="])
    except getopt.GetoptError:
        print('usage: postprocess_data.py --figure=<FIGURE_ID>')
        sys.exit(2)
    
    # Args provided -> Specific scenario
    for opt, arg in opts:
        if opt == '-h':
            print('usage: postprocess_data.py --figure=<FIGURE_ID>')
            sys.exit()
        elif opt in ("--figure"):
            figure_number = int(arg)
            if figure_number == 2:
                postprocessing("results/results_figure2.json", "matlab/simulation_data_figure2.m", "malicious_devices_prop", "devices_per_cluster")
            elif figure_number == 3:
                postprocessing("results/results_figure3.json", "matlab/simulation_data_figure3.m", "threshold_ratio", "malicious_devices_prop")
            elif figure_number == 4:
                postprocessing("results/results_figure4.json", "matlab/simulation_data_figure4.m", "malicious_frequency_multiplier", "malicious_devices_prop")
            elif figure_number == 5:
                postprocessing("results/results_figure5.json", "matlab/simulation_data_figure5.m", "eval_time", "devices_per_cluster")
            elif figure_number == 6:
                postprocessing("results/results_figure6.json", "matlab/simulation_data_figure6.m", "threshold_ratio", "eval_time")
            else:
                print("No such figure")
            return
    
    
if __name__ == "__main__":
    main(sys.argv[1:])
