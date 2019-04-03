import glob
import timeit

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, f1_score, auc, accuracy_score
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.utils import shuffle
from sklearn.naive_bayes import MultinomialNB, GaussianNB

normal_path = "/home/yoanapaleva/PycharmProjects/networking-data-prep/Header-based/Normal_CSVs_Cropped/"
# FLOOD
full_flood_path = "/home/yoanapaleva/PycharmProjects/networking-data-prep/Header-based/Full_Attacks/flood/"
# DOS
minimal_dos_path = "/home/yoanapaleva/PycharmProjects/networking-data-prep/Header-based/Minimal_Attacks/dos/"
reduced_dos_path = "/home/yoanapaleva/PycharmProjects/networking-data-prep/Header-based/Reduced_Attacks/dos/"
# SCAN
full_scan_path = "/home/yoanapaleva/PycharmProjects/networking-data-prep/Header-based/Full_Attacks/scan/"
minimal_scan_path = "/home/yoanapaleva/PycharmProjects/networking-data-prep/Header-based/Minimal_Attacks/scan/"
reduced_scan_path = "/home/yoanapaleva/PycharmProjects/networking-data-prep/Header-based/Reduced_Attacks/scan/"

df_normal = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(normal_path + '*.csv')],
                      ignore_index=True)
df_normal = df_normal[['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
                       'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
                       'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
                       'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b',
                       'pushed_data_pkts_a2b',
                       'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a',
                       'initial_window_bytes_a2b',
                       'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
                       'missed_data_a2b', 'missed_data_b2a']]
df_full_flood = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(full_flood_path + '*.csv')],
                          ignore_index=True)
df_full_flood = df_full_flood[
    ['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
     'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
     'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
     'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b',
     'pushed_data_pkts_a2b',
     'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a',
     'initial_window_bytes_a2b',
     'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
     'missed_data_a2b', 'missed_data_b2a']]
df_minimal_dos = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(minimal_dos_path + '*.csv')],
                           ignore_index=True)
df_minimal_dos = df_minimal_dos[
    ['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
     'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
     'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
     'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b',
     'pushed_data_pkts_a2b',
     'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a',
     'initial_window_bytes_a2b',
     'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
     'missed_data_a2b', 'missed_data_b2a']]
df_reduced_dos = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(reduced_dos_path + '*.csv')],
                           ignore_index=True)
df_reduced_dos = df_reduced_dos[
    ['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
     'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
     'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
     'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b',
     'pushed_data_pkts_a2b',
     'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a',
     'initial_window_bytes_a2b',
     'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
     'missed_data_a2b', 'missed_data_b2a']]
df_full_scan = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(full_scan_path + '*.csv')],
                         ignore_index=True)
df_full_scan = df_full_scan[['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
                             'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b',
                             'rexmt_data_bytes_b2a',
                             'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
                             'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b',
                             'pushed_data_pkts_a2b',
                             'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a',
                             'initial_window_bytes_a2b',
                             'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
                             'missed_data_a2b', 'missed_data_b2a']]
df_minimal_scan = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(minimal_scan_path + '*.csv')],
                            ignore_index=True)
df_minimal_scan = df_minimal_scan[
    ['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
     'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
     'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
     'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b',
     'pushed_data_pkts_a2b',
     'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a',
     'initial_window_bytes_a2b',
     'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
     'missed_data_a2b', 'missed_data_b2a']]
df_reduced_scan = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(reduced_scan_path + '*.csv')],
                            ignore_index=True)
df_reduced_scan = df_reduced_scan[['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
                       'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
                       'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
                       'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b',
                       'pushed_data_pkts_a2b',
                       'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a',
                       'initial_window_bytes_a2b',
                       'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
                       'missed_data_a2b',
                       'missed_data_b2a']]

print("NORMAL: ", df_normal.shape)
print("FLOOD: ", df_full_flood.shape)
all_dos = [df_minimal_dos, df_reduced_dos]
dos = pd.concat(all_dos)
dos = shuffle(dos)
print("DOS: ", dos.shape)
all_scan = [df_full_scan, df_minimal_scan, df_reduced_scan]
scan = pd.concat(all_scan)
scan = shuffle(scan)
print("SCAN: ", scan.shape)

normal_sample = df_normal.sample(3000, random_state=42)
normal_sample['Target'] = 1
flood_sample = df_full_flood.sample(3000, random_state=42)
flood_sample['Target'] = 2
dos_sample = dos.sample(3000, random_state=42)
dos_sample['Target'] = 3
scan_sample = scan.sample(3000, random_state=42)
scan_sample['Target'] = 4

final_set = [normal_sample, flood_sample, dos_sample, scan_sample]
final = pd.concat(final_set)
final = shuffle(final)

target = final.iloc[:, -1]
final.drop(['Target'], inplace=True, axis=1)

# print(final)
# print(target)
X_train, X_test, y_train, y_test = train_test_split(final, target, test_size=0.2, random_state=42)

sc = StandardScaler()
final = sc.fit_transform(final)

clf = SVC(kernel='rbf')
grid = {'C': [1, 5, 10, 25, 50, 100, 250, 500, 1000], 'gamma': [0.01, 0.001, 0.0001]}
clf_cv = GridSearchCV(clf, grid, cv=5, n_jobs=-1, verbose=2)
clf_cv.fit(final, target)
print(clf_cv.best_params_)
print(clf_cv.best_score_)

# X_train = sc.fit_transform(X_train)
# X_test = sc.transform(X_test)
# print("Scaling done...")
# start = timeit.default_timer()
# clf = LogisticRegression(multi_class='multinomial', penalty='l1', solver='saga')
# # clf = SVC(kernel='rbf')
# # clf = GaussianNB()
#
# clf.fit(X_train, y_train)
# print("Training done...")
# predicted = clf.predict(X_test)
# print(classification_report(y_test, predicted))
# print("Confusion matrix: ", confusion_matrix(y_test, predicted))
# print("Accuracy score: ", accuracy_score(y_test, predicted))
#
# end = timeit.default_timer()
# print('Runtime: ', end - start)
