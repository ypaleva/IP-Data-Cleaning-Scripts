import csv
import glob
import math
import os
import statistics
from collections import defaultdict

from scapy.layers.inet import TCP, IP
from scapy.utils import rdpcap

dir_path = '/home/yoanapaleva/Desktop/folder'
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
        print('Session duration: ', session_duration, ' ms')

        last_value = last_packet[IP].src + last_packet[IP].dst
        last_value_unique = last_packet[IP].src + last_packet[IP].dst + str(last_packet[IP].dport)
        last_server = last_packet[IP].src + last_packet[IP].dst + str(last_packet[IP].dport)
        print('Last server: ', last_server)

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

        frequency_map_100 = defaultdict(int)
        frequency_map_500 = defaultdict(int)

        frequency_map_100[last_server] = 1
        frequency_map_500[last_server] = 1

        unique_ports = defaultdict(int)
        unique_ports[str(last_pkt[IP].dport)] = 0

        for packet in reversed(packets):

            print('packet src_ip: ', packet[IP].src, ', dst_ip: ', packet[IP].dst, ' , dst_port: ', packet[IP].dport)
            unique_ports[str(packet[IP].dport)] += 1

            delta = last_pkt.time - packet.time
            # print('Delta time of packet: ', delta)

            if packet[IP].src + packet[IP].dst == a2b_IPs:
                total_packets_a2b += 1
            else:
                total_packets_b2a += 1

            current_value = packet[IP].src + packet[IP].dst
            current_value_unique = packet[IP].src + packet[IP].dst + str(packet[IP].dport)

            if time_500 < 500.0:
                print('Packet is in the last 500 ms')
                time_500 += delta

                if current_value != last_value:
                    counter_for_500_any_port += 1

                if current_value_unique != last_value_unique:
                    frequency_map_500[current_value_unique] += 1
                    print('Updated frequency for: ', current_value_unique, ' to: ',
                          frequency_map_500[current_value_unique])

                if time_100 < 100.0:
                    print('Packet is in the last 100 ms')
                    time_100 += delta

                    if current_value != last_value:
                        counter_for_100_any_port += 1

                    if current_value_unique != last_value_unique:
                        frequency_map_100[current_value_unique] += 1
                        print('Updated frequency for: ', current_value_unique, ' to: ',
                              frequency_map_100[current_value_unique])

            last_pkt = packet
            last_value = last_pkt[IP].src + last_pkt[IP].dst
            last_value_unique = last_pkt[IP].src + last_pkt[IP].dst + str(last_pkt[IP].dport)
            print()

        print()
        print('Session duration: ', session_duration)
        print()
        print('Total connections in last 100 ms on any port: ', math.ceil(counter_for_100_any_port / 2))
        print('Total connections in last 500 ms on any port: ', math.ceil(counter_for_500_any_port / 2))
        print()
        print('Total connections in last 100 ms on same server port: ', frequency_map_100[last_server])
        print('Total connections in last 500 ms on same server port: ', frequency_map_500[last_server])
        print()
        print('Total packets a2b: ', total_packets_a2b)
        print('Total packets b2a: ', total_packets_b2a)
        print()
        print('Unique ports: ', unique_ports)
        print()
