import glob
import os
import timeit
import pandas as pd

path_active_normal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Header-based/Normal_CSVs_Cropped/active-cropped.csv'
path_full_random_normal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Header-based/Normal_CSVs_Cropped/full-benign-random-cropped.csv'
path_full_structured_normal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Header-based/Normal_CSVs_Cropped/full-benign-structured-cropped.csv'
path_minimal_normal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Header-based/Normal_CSVs_Cropped/minimal-benign-cropped.csv'
path_reduced_normal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Header-based/Normal_CSVs_Cropped/reduced-benign-cropped.csv'

path_minimal_dos = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Header-based/Minimal_Attacks/dos/'
path_reduced_dos = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Header-based/Reduced_Attacks/dos/'

df_active_normal = pd.read_csv(path_active_normal)
df_active_normal = df_active_normal[
    ['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
     'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
     'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
     'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b', 'pushed_data_pkts_a2b',
     'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a', 'initial_window_bytes_a2b',
     'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
     'missed_data_a2b', 'missed_data_b2a']]
print("Active normal shape: ", df_active_normal.shape)
df_full_random_normal = pd.read_csv(path_full_random_normal)
df_full_random_normal = df_full_random_normal[
    ['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
     'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
     'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
     'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b', 'pushed_data_pkts_a2b',
     'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a', 'initial_window_bytes_a2b',
     'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
     'missed_data_a2b', 'missed_data_b2a']]

print("Full random normal shape: ", df_full_random_normal.shape)
df_full_structured_normal = pd.read_csv(path_full_structured_normal)
df_full_structured_normal = df_full_structured_normal[
    ['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
     'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
     'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
     'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b', 'pushed_data_pkts_a2b',
     'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a', 'initial_window_bytes_a2b',
     'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
     'missed_data_a2b', 'missed_data_b2a']]

print("Full structured normal shape: ", df_full_structured_normal.shape)
df_minimal_normal = pd.read_csv(path_minimal_normal)
df_minimal_normal = df_minimal_normal[
    ['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
     'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
     'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
     'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b', 'pushed_data_pkts_a2b',
     'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a', 'initial_window_bytes_a2b',
     'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
     'missed_data_a2b', 'missed_data_b2a']]

print("Minimal normal shape: ", df_minimal_normal.shape)
df_reduced_normal = pd.read_csv(path_reduced_normal)
df_reduced_normal = df_reduced_normal[
    ['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
     'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
     'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
     'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b', 'pushed_data_pkts_a2b',
     'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a', 'initial_window_bytes_a2b',
     'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
     'missed_data_a2b', 'missed_data_b2a']]

print("Reduced normal shape: ", df_reduced_normal.shape)
print()
df_minimal_dos = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(path_minimal_dos + '*.csv')],
                           ignore_index=True)
df_minimal_dos = df_minimal_dos[
    ['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
     'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
     'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
     'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b', 'pushed_data_pkts_a2b',
     'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a', 'initial_window_bytes_a2b',
     'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
     'missed_data_a2b', 'missed_data_b2a']]

print("Minimal DOS shape: ", df_minimal_dos.shape)
df_reduced_dos = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(path_reduced_dos + '*.csv')],
                           ignore_index=True)
df_reduced_dos = df_reduced_dos[
    ['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
     'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
     'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
     'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b', 'pushed_data_pkts_a2b',
     'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a', 'initial_window_bytes_a2b',
     'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
     'missed_data_a2b', 'missed_data_b2a']]

print("Reduced DOS shape: ", df_reduced_dos.shape)
