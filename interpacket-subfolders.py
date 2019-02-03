import csv
import statistics

from scapy.all import *
import glob
import os
import numpy as np
from scapy.layers.inet import TCP, IP

dir_path = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Active-Demultiplexed'
directory = dir_path

print('Directory: ', directory)
folders = os.listdir(directory)
folders[:] = [d for d in folders if not d[0] == '.']
print('All subfolders in directory: ', folders.__len__())
arr = []
for folder in folders:
    print('Folder: ', folder)

    folder_path = directory + folder + '/'
    os.chdir(folder_path)
    files = glob.glob(folder_path + '*.pcap')

    filename = os.path.basename(folder).split('-')[0] + '.csv'
    csv_path = directory + folder + '/' + filename
    print('New CSV file: ', csv_path)

    with open(csv_path, 'w') as csv_file:
        csv_writer = csv.writer(csv_file, delimiter=',')
        # quoting=csv.QUOTE_ALL)
        csv_writer.writerow(
            ['inter_arrival_time_mean', 'inter_arrival_time_variance ', 'inter_arrival_time_st_dev',
             'payload_size_mean',
             'payload_size_variance', 'payload_size_st_dev'])

        for file in files:
            packets = rdpcap(file)

            arrival_times = []
            payload_sizes = []

            for packet in packets:
                if packet.haslayer(TCP):
                    arrival_times.append(packet.time)
                    payload_sizes.append(len(packet[TCP].payload))

            inter_times = [(b - a) for a, b in zip(arrival_times, arrival_times[1:])]

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
