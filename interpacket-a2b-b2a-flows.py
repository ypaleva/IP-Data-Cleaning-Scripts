import csv
import glob
import os
import statistics
from scapy.layers.inet import TCP, IP
from scapy.utils import rdpcap

dir_path = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Minimal-Demultiplexed-Interpacket/Minimal_Malicious-Demultiplexed'
directory = dir_path + '/'

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
            ['inter_arrival_time_mean_a2b', 'inter_arrival_time_variance_a2b', 'inter_arrival_time_st_dev_a2b',
             'payload_size_mean_a2b', 'payload_size_variance_a2b', 'payload_size_st_dev_a2b',
             'inter_arrival_time_mean_b2a', 'inter_arrival_time_variance_b2a', 'inter_arrival_time_st_dev_b2a',
             'payload_size_mean_b2a', 'payload_size_variance_b2a', 'payload_size_st_dev_b2a'])

        for file in files:

            filename = os.path.basename(file)
            # print('Filename: ', filename)
            str = filename
            str = str.replace('.pcap', '')
            split = str.split('-')
            # print(split)

            first_IP_and_port = split[1]
            second_IP_and_port = split[2]

            first_IP = first_IP_and_port.split(':')[0]
            second_IP = second_IP_and_port.split(':')[0]

            # print(first_IP)
            # print(second_IP)

            packets = rdpcap(file)

            arrival_times_a2b = []
            arrival_times_b2a = []
            payload_sizes_a2b = []
            payload_sizes_b2a = []

            for packet in packets:
                if packet.haslayer(TCP):
                    if IP in packet:
                        ip_src = packet[IP].src
                        ip_dst = packet[IP].dst

                        if packet[IP].src == first_IP:
                            # print('First packet src: ', packet[IP].src, 'first_IP: ', first_IP)
                            arrival_times_a2b.append(packet.time)
                            payload_sizes_a2b.append(len(packet[TCP].payload))
                        elif packet[IP].src == second_IP:
                            # print('Second packet src: ', packet[IP].src, 'second_IP: ', second_IP)
                            arrival_times_b2a.append(packet.time)
                            payload_sizes_b2a.append(len(packet[TCP].payload))

            inter_times_a2b = [(b - a) for a, b in zip(arrival_times_a2b, arrival_times_a2b[1:])]
            inter_times_b2a = [(b - a) for a, b in zip(arrival_times_b2a, arrival_times_b2a[1:])]

            if len(arrival_times_a2b) > 2:
                inter_arrival_time_mean_a2b = statistics.mean(inter_times_a2b)
                inter_arrival_time_variance_a2b = statistics.variance(inter_times_a2b)
                inter_arrival_time_st_dev_a2b = statistics.stdev(inter_times_a2b)

                payload_size_mean_a2b = statistics.mean(payload_sizes_a2b)
                payload_size_variance_a2b = statistics.variance(payload_sizes_a2b)
                payload_size_st_dev_a2b = statistics.stdev(payload_sizes_a2b)

            elif len(arrival_times_a2b) == 1:
                inter_arrival_time_mean_a2b = 0.0
                inter_arrival_time_variance_a2b = 0.0
                inter_arrival_time_st_dev_a2b = 0.0

                payload_size_mean_a2b = payload_sizes_a2b[0]
                payload_size_variance_a2b = 0.0
                payload_size_st_dev_a2b = 0.0

            else:
                inter_arrival_time_mean_a2b = 0.0
                inter_arrival_time_variance_a2b = 0.0
                inter_arrival_time_st_dev_a2b = 0.0

                payload_size_mean_a2b = 0.0
                payload_size_variance_a2b = 0.0
                payload_size_st_dev_a2b = 0.0

            if len(arrival_times_b2a) > 2:
                inter_arrival_time_mean_b2a = statistics.mean(inter_times_b2a)
                inter_arrival_time_variance_b2a = statistics.variance(inter_times_b2a)
                inter_arrival_time_st_dev_b2a = statistics.stdev(inter_times_b2a)

                payload_size_mean_b2a = statistics.mean(payload_sizes_b2a)
                payload_size_variance_b2a = statistics.variance(payload_sizes_b2a)
                payload_size_st_dev_b2a = statistics.stdev(payload_sizes_b2a)

            elif len(arrival_times_b2a) == 1:
                inter_arrival_time_mean_b2a = 0.0
                inter_arrival_time_variance_b2a = 0.0
                inter_arrival_time_st_dev_b2a = 0.0

                payload_size_mean_b2a = payload_sizes_b2a[0]
                payload_size_variance_b2a = 0.0
                payload_size_st_dev_b2a = 0.0

            else:
                inter_arrival_time_mean_b2a = 0.0
                inter_arrival_time_variance_b2a = 0.0
                inter_arrival_time_st_dev_b2a = 0.0

                payload_size_mean_b2a = 0.0
                payload_size_variance_b2a = 0.0
                payload_size_st_dev_b2a = 0.0

            csv_writer.writerow(
                [inter_arrival_time_mean_a2b, inter_arrival_time_variance_a2b, inter_arrival_time_st_dev_a2b,
                 payload_size_mean_a2b, payload_size_variance_a2b, payload_size_st_dev_a2b,
                 inter_arrival_time_mean_b2a, inter_arrival_time_variance_b2a, inter_arrival_time_st_dev_b2a,
                 payload_size_mean_b2a, payload_size_variance_b2a, payload_size_st_dev_b2a])
