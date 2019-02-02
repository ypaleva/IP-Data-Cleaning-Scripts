import csv
from scapy.all import *
import glob
import os
import numpy as np
from scapy.layers.inet import TCP, IP

dir_path = '/home/yoanapaleva/PycharmProjects/networking-data-prep/'
directory = dir_path + 'test/'

print('Directory: ', directory)
folders = os.listdir(directory)
print('All subfolders in directory: ', folders)
arr = []
for folder in folders:

    print('Folder: ', folder)

    folder_path = directory + folder + '/'
    os.chdir(folder_path)
    files = glob.glob(folder_path + '*.pcap')

    for file in files:
        print('File: ', file)
        filename = os.path.basename(file).split('.')[0] + '.csv'
        # with open(filename, 'w') as csvfile:
        #     csv_writer = csv.writer(csvfile, delimiter=',')
        #                             #quoting=csv.QUOTE_ALL)
        #     csv_writer.writerow(['src_ip', 'src_port', 'dst_ip', 'dst_port', 'payload_size', 'time'])

        packets = rdpcap(file)
        print(packets.__len__())

        for packet in packets:
            if packet.haslayer(TCP):
                arr.append(packet.time)
        #    csv_writer.writerow([packet[IP].src, packet[TCP].sport, packet[IP].dst,
        #         packet[TCP].dport, len(packet[TCP].payload), packet.time])
print(np.mean(arr))