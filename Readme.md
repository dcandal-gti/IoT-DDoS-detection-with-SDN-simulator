# IoT-DDoS-detection-with-SDN-simulator

## Description

This simulator evaluates the performance of the IoT DDoS attack detector based in SDN proposed at "Quarantining malicious IoT devices in intelligent sliced mobile networks".

## Execution

Use the script "detection_simulator.py" to simulate the scenarios you want to evaluate.

This script same preset collections of scenarios with the aim of generating data to plot the impact of two specific parameters on the detection:

1. Change to the root directory of this project.
2. Run the script "detection_simulator.py" including the option "figure":  python3 detection_simulator.py --figure=<FIGURE_ID>
3. A .csv file will be created in a folder named "results" at PWD. Run the "postprocess_data.py" script to parse the .csv and compute the data required to plot the results:  python3 postprocess_data.py --figure=<FIGURE_ID>
4. A .m file, including the data to represent, sill be created at "./matlab/". Run the corresponding Matlab script to plot the data.

## Usage

    usage: python3 detection_simulator.py [--malicious_devices_prop=<val>] [--devices_per_cluster=<val>]
                   [--eval_time=<val>] [--malicious_frequency_multiplier=<val>] [--threshold_ratio=<val>]
                   [--periodicity_error=<val>] [--figure=<val>]
    
     --malicious_devices_prob <PROB>           Specifies the probability of a device being malicious.
                                               [default: 0.01].
     --devices_per_cluster <NUM_DEVICES>       Specifies the aggregated flow size.
                                               [default: 200].
     --eval_time <MS>                          Specifies the SDN application sample period, in ms.
                                               [default: 1000].
     --malicious_frequency_multiplier <RATIO>  Specifies the ratio between the transmission frequency of
                                               malicious and legitimate devices. [default: 100].
     --threshold_ratio <RATIO>                 Specifies the threshold ratio above which flows are tagged
                                               as suspicious. [default: 1.01].
    
     --figure <FIGURE_ID>                      Specifies a set of scenarios to evaluate among a predefined
                                               collection. All other input parameters will be overwritten.
                                               Available figures:
                                                   2. malicious_devices_prob and devices_per_cluster
                                                       vs quarantining
                                                   3. threshold_ratio and malicious_devices_prop
                                                       vs quarantining
                                                   4. malicious_frequency_multiplier and malicious_devices_prop
                                                       vs quarantining
                                                   5. eval_time and devices_per_cluster vs quarantining
                                                   6. threshold_ratio and eval_time vs quarantining
                                               [default: None].

    usage: postprocess_data.py --figure=<FIGURE_ID>


## Copyright

Copyright ⓒ 2020 David Candal Ventureira <dcandal@gti.uvigo.es>.

This simulator is licensed under the GNU General Public License, version 3 (GPL-3.0). For more information see LICENSE.txt