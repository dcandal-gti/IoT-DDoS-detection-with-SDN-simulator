# -*- coding: utf-8 -*-
"""
Created on Mon Jul 20 13:35:11 2020

@author: david
"""
from random import randint as random_int, seed as rseed
from numpy.random import binomial, normal, seed as nseed, uniform
from collections import Counter
import tqdm
import sys, getopt
from time import sleep
import json
import fcntl
from multiprocessing import Pool, cpu_count, Value, Lock
from ctypes import c_int32
import os

# Setting random seeds
rseed(0); nseed(0)
# Variable for regitering progress bar status
counter = Value(c_int32)
counter_lock = Lock()


class IoTDevice:
    def __init__(self, malicious, eval_time, periodicity_error, malicious_frequency_multiplier):
        self.malicious = malicious
        if malicious:
            self.period = self.legacy_period / malicious_frequency_multiplier

class ManufacturingCell(IoTDevice):
    period = legacy_period = 50
    data_burst = 15*8

class MachineTools(IoTDevice):
    period = legacy_period = 0.5
    data_burst = 50*8

class PrintingMachines(IoTDevice):
    period = legacy_period = 2
    data_burst = 30*8

class PackagingMachines(IoTDevice):
    period = legacy_period = 5
    data_burst = 15*8

device_classes = [ManufacturingCell, MachineTools, PrintingMachines, PackagingMachines]
def get_class_from_type_id(type_id):
    return device_classes[type_id]


# Evaluates a simulation scenario, characterized by the number of devices per aggregated flow, the detection threshold
# (in terms of maximum expected throughput measured in b/s), the probability of a device to be malicious, the ratio
# between the transmission frequencies of malicious and legitimate devices and the SDN application sampling period.
def evaluation(silent, simulation_rounds, malicious_devices_prop, devices_per_cluster, eval_time,
               malicious_frequency_multiplier, threshold_ratio, periodicity_error, results_file):
    global counter_lock, counter
    
    show_pbar = not silent and counter_lock is not None and counter is not None
    
    aggregated_data_sent_array = []
    data_sent_threshold_array = []
    num_malicious_array = []
    for i in range(simulation_rounds):
        # Updating progress bar
        if show_pbar:
            with counter_lock:
                counter.value += 1
        
        # Creating the cluster (devices in a flow)
        iot_devices = []
        distribution_device_classes = [random_int(0,len(device_classes)-1) for _ in range(devices_per_cluster)]
        distribution_malicious = binomial(1, malicious_devices_prop, devices_per_cluster)
        for type_id, is_malicious in zip(distribution_device_classes,distribution_malicious):
            iot_devices.append(device_classes[type_id](is_malicious, eval_time, periodicity_error, malicious_frequency_multiplier))
        
        # Preloading random arrays
        uniform_first_tx = list(uniform(0,1,devices_per_cluster))
        gaussian_jitter = list(normal(0,1,devices_per_cluster))
        
        # Computing estimated throughput (data sent within an evaluation period)
        data_sent_threshold = 0
        distribution_devices_counter=dict(Counter(distribution_device_classes))
        for device_type_id, device_type_count in distribution_devices_counter.items():
            data_sent_threshold += device_type_count * threshold_ratio * (eval_time/get_class_from_type_id(device_type_id).legacy_period) * (get_class_from_type_id(device_type_id).data_burst)
        
        # Simulation
        aggregated_data_sent = 0
        for device in iot_devices:
            # First tranmsission in U(0, tx_period)
            # Assuming tx_period < eval_time
            accumulated_time = uniform_first_tx.pop() * device.period
            # [2,n-1] transmissions
            num_txs = 1 + int((eval_time - accumulated_time) / device.period)
            remainder = (eval_time - accumulated_time) % device.period
            # Last transmission (with jitter)
            standard_deviation = device.period * (periodicity_error/2) / 2
            last_transmission_time = standard_deviation * gaussian_jitter.pop() + device.period
            if(last_transmission_time < remainder):
                num_txs += 1
            # Adding the data of this device to the aggregated data sent in this period
            aggregated_data_sent += num_txs * device.data_burst
        
        aggregated_data_sent_array.append(aggregated_data_sent)
        data_sent_threshold_array.append(data_sent_threshold)
        num_malicious_array.append(sum(distribution_malicious))
    
    # Results
    result = {
        "eval_time" : eval_time,
        "malicious_devices_prop" : malicious_devices_prop,
        "devices_per_cluster" : devices_per_cluster,
        "malicious_frequency_multiplier" : malicious_frequency_multiplier,
        "threshold_ratio" : threshold_ratio,
        "periodicity_error" : periodicity_error,
        "simulation_rounds" : simulation_rounds,
        "aggregated_data_sent_array" : aggregated_data_sent_array,
        "data_sent_threshold_array" : data_sent_threshold_array,
        "malicious_quarantined_array": [int(num_malicious)
                                if (aggregated_data_sent > data_sent_threshold) else 0
                                for aggregated_data_sent, data_sent_threshold, num_malicious in
                                zip(aggregated_data_sent_array,data_sent_threshold_array,num_malicious_array)],
        "malicious_array" : [int(x) for x in num_malicious_array],
        "legitimate_quarantined_array": [int(devices_per_cluster-num_malicious)
                                if (aggregated_data_sent > data_sent_threshold) else 0
                                for aggregated_data_sent, data_sent_threshold, num_malicious in
                                zip(aggregated_data_sent_array,data_sent_threshold_array,num_malicious_array)],
        "legitimate_array" : [devices_per_cluster-int(x) for x in num_malicious_array]
        }
    return result


def write_json(result, results_file):
    result_json = json.dumps(result, indent=4)
    if not os.path.exists(os.path.dirname(os.path.abspath(results_file))):
        os.makedirs(os.path.dirname(os.path.abspath(results_file)))
    with open(results_file, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(result_json)
        fcntl.flock(f, fcntl.LOCK_UN)


## Functions used to generate the figures
## They sweep over two of the parameters that define the scenarios to obtain the impact of that parameter on the quarantining of malicious and legitimate devices
### malicious_devices_prop and devices_per_cluster vs quarantining
def figure2(silent):
    eval_time = 1000
    malicious_frequency_multiplier = 100
    threshold_ratio = 1.01
    periodicity_error = 0.1
    simulation_rounds = 10000
    results_file = "results/results_figure2.json"

    devices_per_cluster_array = [50,100,150,200,250]
    malicious_devices_prop_array = [0.001*x for x in range(10)] + [0.01+0.0025*x for x in range(7)]

    pbar = tqdm.tqdm(range(simulation_rounds * len(devices_per_cluster_array) * len(malicious_devices_prop_array)))
    with pbar:
        with Pool(cpu_count()-1) as pool:
            sm = pool.starmap_async(evaluation, [(silent, simulation_rounds, malicious_devices_prop, devices_per_cluster, eval_time,
                    malicious_frequency_multiplier, threshold_ratio, periodicity_error, results_file)
                   for malicious_devices_prop in malicious_devices_prop_array
                   for devices_per_cluster in devices_per_cluster_array])
            while not sm.ready():
                if counter.value != 0:
                    with counter_lock:
                        increment = counter.value
                        counter.value = 0
                    pbar.update(n=increment)
                sleep(0.5)
            write_json(sm.get(), results_file)

### threshold_ratio and malicious_devices_prop vs quarantining
def figure3(silent):
    devices_per_cluster = 100
    eval_time = 1000
    malicious_frequency_multiplier = 100
    periodicity_error = 0.1
    simulation_rounds = 10000
    results_file = "results/results_figure3.json"
    threshold_ratio_array = [1+(x/10000) for x in range(0,700,35)] + [1+(x/10000) for x in range(700,1550,50)]
    malicious_devices_prop_array = [0.005, 0.010, 0.015, 0.020, 0.025]

    pbar = tqdm.tqdm(range(simulation_rounds * len(threshold_ratio_array) * len(malicious_devices_prop_array)))
    with pbar:
        with Pool(cpu_count()-1) as pool:
            sm = pool.starmap_async(evaluation, [(silent, simulation_rounds, malicious_devices_prop, devices_per_cluster, eval_time,
                    malicious_frequency_multiplier, threshold_ratio, periodicity_error, results_file)
                   for threshold_ratio in threshold_ratio_array
                   for malicious_devices_prop in malicious_devices_prop_array])
            while not sm.ready():
                if counter.value != 0:
                    with counter_lock:
                        increment = counter.value
                        counter.value = 0
                    pbar.update(n=increment)
                sleep(0.5)
            write_json(sm.get(), results_file)

### malicious_frequency_multiplier and malicious_devices_prop vs quarantining
def figure4(silent):
    devices_per_cluster = 100
    eval_time = 1000
    periodicity_error = 0.1
    simulation_rounds = 10000
    results_file = "results/results_figure4.json"
    threshold_ratio = 1.01
    malicious_frequency_multiplier_array = list(range(1,10)) + list(range(10,100,10)) + [100, 125, 150, 200, 250]
    malicious_devices_prop_array = [0.005, 0.010, 0.015, 0.020, 0.025]

    pbar = tqdm.tqdm(range(simulation_rounds * len(malicious_frequency_multiplier_array) * len(malicious_devices_prop_array)))
    with pbar:
        with Pool(cpu_count()-1) as pool:
            sm = pool.starmap_async(evaluation, [(silent, simulation_rounds, malicious_devices_prop, devices_per_cluster, eval_time,
                    malicious_frequency_multiplier, threshold_ratio, periodicity_error, results_file)
                   for malicious_frequency_multiplier in malicious_frequency_multiplier_array
                   for malicious_devices_prop in malicious_devices_prop_array])
            while not sm.ready():
                if counter.value != 0:
                    with counter_lock:
                        increment = counter.value
                        counter.value = 0
                    pbar.update(n=increment)
                sleep(0.5)
            write_json(sm.get(), results_file)

### eval_time and devices_per_cluster vs quarantining
def figure5(silent):
    malicious_frequency_multiplier = 100
    threshold_ratio = 1.01
    periodicity_error = 0.1
    simulation_rounds = 10000
    malicious_devices_prop = 0.01
    results_file = "results/results_figure5.json"

    eval_time_array = list(range(200,2000,50))
    devices_per_cluster_array = [50,100,150,200,250]

    pbar = tqdm.tqdm(range(simulation_rounds * len(devices_per_cluster_array) * len(eval_time_array)))
    with pbar:
        with Pool(cpu_count()-1) as pool:
            sm = pool.starmap_async(evaluation, [(silent, simulation_rounds, malicious_devices_prop, devices_per_cluster, eval_time,
                    malicious_frequency_multiplier, threshold_ratio, periodicity_error, results_file)
                   for eval_time in eval_time_array
                   for devices_per_cluster in devices_per_cluster_array])
            while not sm.ready():
                if counter.value != 0:
                    with counter_lock:
                        increment = counter.value
                        counter.value = 0
                    pbar.update(n=increment)
                sleep(0.5)
            write_json(sm.get(), results_file)

### threshold_ratio and eval_time vs quarantining
def figure6(silent):
    devices_per_cluster = 100
    malicious_frequency_multiplier = 100
    periodicity_error = 0.1
    simulation_rounds = 10000
    malicious_devices_prop = 0.01
    results_file = "results/results_figure6.json"
    threshold_ratio_array = [1+(x/10000) for x in range(0,255,5)]
    eval_time_array = [100,250,500,1000]

    pbar = tqdm.tqdm(range(simulation_rounds * len(threshold_ratio_array) * len(eval_time_array)))
    with pbar:
        with Pool(cpu_count()-1) as pool:
            sm = pool.starmap_async(evaluation, [(silent, simulation_rounds, malicious_devices_prop, devices_per_cluster, eval_time,
                    malicious_frequency_multiplier, threshold_ratio, periodicity_error, results_file)
                   for threshold_ratio in threshold_ratio_array
                   for eval_time in eval_time_array])
            while not sm.ready():
                if counter.value != 0:
                    with counter_lock:
                        increment = counter.value
                        counter.value = 0
                    pbar.update(n=increment)
                sleep(0.5)
            write_json(sm.get(), results_file)
## End of Functions used to generate the figures


def print_help():
    print("""usage: python3 detection_simulator.py [--malicious_devices_prop=<val>] [--devices_per_cluster=<val>]
               [--eval_time=<val>] [--malicious_frequency_multiplier=<val>] [--threshold_ratio=<val>]
               [--periodicity_error=<val>] [--figure=<val>]

 --malicious_devices_prob <PROB>           Specifies the probability of a device being malicious.
                                           [default: 0.01].
 --devices_per_cluster <NUM_DEVICES>       Specifies the aggregated flow size.
                                           [default: 200].
 --eval_time <MS>                          Specifies the SDN application sample period, in ms.
                                           [default: 1000].
 --malicious_frequency_multiplier <RATIO>  Specifies the ratio between the transmission frequency of malicios and
                                           legitimate devices. [default: 100].
 --threshold_ratio <RATIO>                 Specifies the threshold ratio above which flows are tagged as suspicious.
                                           [default: 1.01].

 --figure <FIGURE_ID>                      Specifies a set of scenarios to evaluate among a predefined collection.
                                           All other input parameters will be overwritten.
                                           Available figures:
                                               2.- malicious_devices_prob and devices_per_cluster vs quarantining
                                               3.- threshold_ratio and malicious_devices_prop vs quarantining
                                               4.- malicious_frequency_multiplier and malicious_devices_prop vs quarantining
                                               5.- eval_time and devices_per_cluster vs quarantining
                                               6.- threshold_ratio and eval_time vs quarantining
                                           [default: None].
          """)

# Users can demand the evaluation of an specific scenario by providing the values of the parameters that characterize it, or
# choose among the predefined figure functions that swap over two of the parameters to analyze what is its impact on the results.
def main(argv):
    global counter_lock, counter
    # Default values
    malicious_devices_prop = 0.01
    devices_per_cluster = 200
    eval_time = 1000
    malicious_frequency_multiplier = 100
    threshold_ratio = 1.01
    periodicity_error = 0.1
    simulation_rounds = 10000
    results_file = "./results.json"
    silent=False

    # Read input arguments
    try:
        opts, args = getopt.getopt(argv,"hsw",["malicious_devices_prob=","devices_per_cluster=","eval_time=","malicious_frequency_multiplier=","threshold_ratio=","periodicity_error=","figure="])
    except getopt.GetoptError:
        print_help()
        sys.exit(2)
    
    # Args provided -> Specific scenario
    for opt, arg in opts:
        if opt == '-h':
            print_help()
            sys.exit()
        if opt == '-s':
            silent=True
        # if opt == '-w':
        #     wr=True

        elif opt in ("--figure"):
            figure_number = int(arg)
            if figure_number == 2:
                figure2(silent)
            elif figure_number == 3:
                figure3(silent)
            elif figure_number == 4:
                figure4(silent)
            elif figure_number == 5:
                figure5(silent)
            elif figure_number == 6:
                figure6(silent)
            else:
                print("No such figure")
            return

        elif opt in ("--malicious_devices_prob"):
            malicious_devices_prop = float(arg.replace(',','.'))
        elif opt in ("--devices_per_cluster"):
            devices_per_cluster = int(arg)
        elif opt in ("--eval_time"):
            eval_time = int(arg)
        elif opt in ("--malicious_frequency_multiplier"):
            malicious_frequency_multiplier = int(arg)
        elif opt in ("--threshold_ratio"):
            threshold_ratio = float(arg.replace(',','.'))
        elif opt in ("--periodicity_error"):
            periodicity_error = float(arg.replace(',','.'))
    
    print(evaluation(silent, simulation_rounds, malicious_devices_prop, devices_per_cluster, eval_time,
           malicious_frequency_multiplier, threshold_ratio, periodicity_error, results_file))


if __name__ == "__main__":
    main(sys.argv[1:])