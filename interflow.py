import csv
import glob
import math
import os
import statistics
from collections import defaultdict

from scapy.layers.inet import TCP, IP
from scapy.utils import rdpcap

dir_path = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interflow-based/Full-Demultiplexed-Interflow/Full_Malicious/new'
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
            ['session_duration', 'total_conns_100ms_anyport', 'total_conns_500ms_anyport', 'total_conns_1000ms_anyport',
             'total_conns_100ms_sameServerPort', 'total_conns_500ms_sameServerPort',
             'total_conns_1000ms_sameServerPort', 'total_packets_a2b_100ms', 'total_packets_a2b_500ms',
             'total_packets_a2b_1000ms', 'total_packets_b2a_100ms', 'total_packets_b2a_500ms',
             'total_packets_b2a_1000ms'])

        for file in files:
            filename = os.path.basename(file)
            # print(filename)
            val = filename
            val = val.replace('.pcap', '')
            split = val.split('-')
            # print(split)

            first_IP_and_port = split[1]
            second_IP_and_port = split[2]

            packets = rdpcap(file)
            first_packet = ''
            last_packet = ''

            # print('Session duration: ', session_duration, ' ms')

            last_value = ''
            last_value_unique = ''
            last_server = ''
            for packet in reversed(packets):
                if hasattr(packet, 'dport'):
                    last_packet = packet
                    last_value = last_packet[IP].src + last_packet[IP].dst
                    last_value_unique = last_packet[IP].src + last_packet[IP].dst + str(last_packet[IP].dport)
                    last_server = last_packet[IP].src + last_packet[IP].dst + str(last_packet[IP].dport)
                    break
                else:
                    continue

            for packet in packets:
                if hasattr(packet, 'dport'):
                    first_packet = packet
                    break
                else:
                    continue

            # print('Last server: ', last_server)
            session_duration = (last_packet.time - first_packet.time)

            total_packets_a2b_100ms = 0
            total_packets_b2a_100ms = 0

            total_packets_a2b_500ms = 0
            total_packets_b2a_500ms = 0

            total_packets_a2b_1000ms = 0
            total_packets_b2a_1000ms = 0

            a2b_IPs = last_packet[IP].src + last_packet[IP].dst
            b2a_IPs = last_packet[IP].dst + last_packet[IP].src

            counter_for_100_any_port = 1
            counter_for_100_same_server_port = 1

            counter_for_500_any_port = 1
            counter_for_500_same_server_port = 1

            counter_for_1000_any_port = 1
            counter_for_1000_same_server_port = 1

            time_100 = 0.0
            time_500 = 0.0
            time_1000 = 0.0

            last_pkt = last_packet

            frequency_map_100 = defaultdict(int)
            frequency_map_500 = defaultdict(int)
            frequency_map_1000 = defaultdict(int)

            frequency_map_100[last_server] = 1
            frequency_map_500[last_server] = 1
            frequency_map_1000[last_server] = 1

            unique_ports = defaultdict(int)
            unique_ports[str(last_pkt[IP].dport)] = 0

            for packet in reversed(packets):
                if hasattr(packet, 'dport'):
                    # print('packet src_ip: ', packet[IP].src, ', dst_ip: ', packet[IP].dst, ' , dst_port: ', packet[IP].dport)
                    unique_ports[str(packet[IP].dport)] += 1

                    delta = last_pkt.time - packet.time
                    # print('Delta time of packet: ', delta)

                    current_value = packet[IP].src + packet[IP].dst
                    current_value_unique = packet[IP].src + packet[IP].dst + str(packet[IP].dport)

                    if time_1000 < 1000.0:

                        # print('Packet is in the last 1000 ms')
                        time_1000 += delta

                        if packet[IP].src + packet[IP].dst == a2b_IPs:
                            total_packets_a2b_1000ms += 1
                        else:
                            total_packets_b2a_1000ms += 1

                        if current_value != last_value:
                            counter_for_1000_any_port += 1

                        if current_value_unique != last_value_unique:
                            frequency_map_1000[current_value_unique] += 1
                            # print('Updated frequency for: ', current_value_unique, ' to: ', frequency_map_1000[current_value_unique])

                        if time_500 < 500.0:
                            # print('Packet is in the last 500 ms')
                            time_500 += delta

                            if packet[IP].src + packet[IP].dst == a2b_IPs:
                                total_packets_a2b_500ms += 1
                            else:
                                total_packets_b2a_500ms += 1

                            if current_value != last_value:
                                counter_for_500_any_port += 1

                            if current_value_unique != last_value_unique:
                                frequency_map_500[current_value_unique] += 1
                                # print('Updated frequency for: ', current_value_unique, ' to: ', frequency_map_500[current_value_unique])

                            if time_100 < 100.0:
                                # print('Packet is in the last 100 ms')
                                time_100 += delta

                                if packet[IP].src + packet[IP].dst == a2b_IPs:
                                    total_packets_a2b_100ms += 1
                                else:
                                    total_packets_b2a_100ms += 1

                                if current_value != last_value:
                                    counter_for_100_any_port += 1

                                if current_value_unique != last_value_unique:
                                    frequency_map_100[current_value_unique] += 1
                                    # print('Updated frequency for: ', current_value_unique, ' to: ', frequency_map_100[current_value_unique])

                    last_pkt = packet
                    last_value = last_pkt[IP].src + last_pkt[IP].dst
                    last_value_unique = last_pkt[IP].src + last_pkt[IP].dst + str(last_pkt[IP].dport)

            conns_100ms_anyport = math.ceil(counter_for_100_any_port / 2)
            conns_500ms_anyport = math.ceil(counter_for_500_any_port / 2)
            conns_1000ms_anyport = math.ceil(counter_for_1000_any_port / 2)
            conns_100ms_sameServerPort = frequency_map_100[last_server]
            conns_500ms_sameServerPort = frequency_map_500[last_server]
            conns_1000ms_sameServerPort = frequency_map_1000[last_server]
            csv_writer.writerow(
                [session_duration, conns_100ms_anyport, conns_500ms_anyport, conns_1000ms_anyport,
                 conns_100ms_sameServerPort, conns_500ms_sameServerPort, conns_1000ms_sameServerPort,
                 total_packets_a2b_100ms, total_packets_a2b_500ms, total_packets_a2b_1000ms,
                 total_packets_b2a_100ms, total_packets_b2a_500ms, total_packets_b2a_1000ms])
