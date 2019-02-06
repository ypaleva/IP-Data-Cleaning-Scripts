import csv
import glob
import os
import statistics
from scapy.layers.inet import TCP, IP
from scapy.utils import rdpcap

dir_path = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Active-Demultiplexed-Interflow'
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

    filename = os.path.basename(folder).split('-')[0] + '-interflow.csv'
    csv_path = directory + folder + '/' + filename
    # print('New CSV file: ', csv_path)

    for file in files:
        filename = os.path.basename(file)
        print(filename)
        val = filename
        val = val.replace('.pcap', '')
        split = val.split('-')
        # print(split)

        first_IP_and_port = split[1]
        second_IP_and_port = split[2]

        packets = rdpcap(file)


