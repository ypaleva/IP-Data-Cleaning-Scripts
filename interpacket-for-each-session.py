import csv
import pandas as pd
from scapy.all import *
import glob
import statistics
import os
import numpy as np
from scapy.layers.inet import TCP, IP

files = glob.glob('/home/yoanapaleva/PycharmProjects/networking-data-prep/deauth_1-demultiplexed/*.pcap')

with open('Test_CSV', 'w') as csvfile:
    csv_writer = csv.writer(csvfile, delimiter=',')
    # quoting=csv.QUOTE_ALL)
    csv_writer.writerow(
        ['inter_arrival_time_mean', 'inter_arrival_time_variance ', 'inter_arrival_time_st_dev', 'payload_size_mean',
         'payload_size_variance', 'payload_size_st_dev'])

    for file in files:

        print(file)

        filename = os.path.basename(file).split('.')[0] + '.csv'
        packets = rdpcap(file)

        arrival_times = []
        payload_sizes = []

        for packet in packets:
            if packet.haslayer(TCP):
                arrival_times.append(packet.time)
                payload_sizes.append(len(packet[TCP].payload))

        inter_times = [(b - a) * 1000 for a, b in zip(arrival_times, arrival_times[1:])]

        if len(arrival_times) > 2:
            inter_arrival_time_mean = statistics.mean(inter_times)
            inter_arrival_time_variance = statistics.variance(inter_times)
            inter_arrival_time_st_dev = statistics.stdev(inter_times)

            payload_size_mean = statistics.mean(payload_sizes)
            payload_size_variance = statistics.variance(payload_sizes)
            payload_size_st_dev = statistics.stdev(payload_sizes)

        elif len(arrival_times) == 1:
            inter_arrival_time_mean = 0.0
            inter_arrival_time_variance = 0.0
            inter_arrival_time_st_dev = 0.0

            payload_size_mean = payload_sizes[0]
            payload_size_variance = 0.0
            payload_size_st_dev = 0.0

        else:
            inter_arrival_time_mean = 0.0
            inter_arrival_time_variance = 0.0
            inter_arrival_time_st_dev = 0.0

            payload_size_mean = 0.0
            payload_size_variance = 0.0
            payload_size_st_dev = 0.0


        csv_writer.writerow([inter_arrival_time_mean, inter_arrival_time_variance, inter_arrival_time_st_dev,
                             payload_size_mean, payload_size_variance, payload_size_st_dev])
