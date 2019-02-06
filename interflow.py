import csv
import glob
import math
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
        first_packet = packets[0]
        last_packet = packets[-1]

        session_duration = (last_packet.time - first_packet.time)
        print('Session duration: ', session_duration, ' millisecs')

        last_value = last_packet[IP].src + last_packet[IP].dst
        last_value_unique = last_packet[IP].src + last_packet[IP].dst + str(last_packet[IP].dport)

        total_packets_a2b = 0
        total_packets_b2a = 0
        a2b_IPs = last_packet[IP].src + last_packet[IP].dst
        b2a_IPs = last_packet[IP].dst + last_packet[IP].src

        counter_for_100_any_port = 1
        counter_for_100_same_server_port = 1
        counter_for_500_any_port = 1
        counter_for_500_same_server_port = 1

        time_100 = 0.0
        time_500 = 0.0

        last_pkt = packets[-1]
        for packet in reversed(packets):

            delta = last_pkt.time - packet.time
            print('Delta time of packet: ', delta)

            if packet[IP].src + packet[IP].dst == a2b_IPs:
                total_packets_a2b += 1
            else:
                total_packets_b2a += 1

            current_value = packet[IP].src + packet[IP].dst
            current_value_unique = packet[IP].src + packet[IP].dst + str(packet[IP].dport)
            print('Matching ports: ... ', last_value_unique, ' ', current_value_unique)
            if time_500 < 500.0:
                print('Packet is in the last 500 ms: ', delta)
                time_500 += delta

                if current_value != last_value:
                    counter_for_500_any_port += 1

                if current_value_unique != last_value_unique:
                    counter_for_500_same_server_port += 1

                if time_100 < 100.0:
                    print('Packet is in the last 100 ms: ', delta)
                    time_100 += delta

                    if current_value != last_value:
                        counter_for_100_any_port += 1

                    if current_value_unique != last_value_unique:
                        counter_for_100_same_server_port += 1

            last_pkt = packet
            last_value = packet[IP].src + packet[IP].dst
            # last_value_unique = packet[IP].src + packet[IP].dst + str(packet[IP].dport)

        print()
        print('Session duration: ', session_duration)
        print()
        print('Total connections in last 100 ms on any port: ', math.ceil(counter_for_100_any_port / 2))
        print('Total connections in last 500 ms on any port: ', math.ceil(counter_for_500_any_port / 2))
        print()
        print('Total connections in last 100 ms on same server port: ', counter_for_100_same_server_port)
        print('Total connections in last 500 ms on same server port: ', counter_for_500_same_server_port)
        print()
        print('Total packets a2b: ', total_packets_a2b)
        print('Total packets b2a: ', total_packets_b2a)
        print()
