import glob
import pandas as pd
import glob
import timeit
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import GridSearchCV, train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.utils import shuffle
from sklearn.model_selection import GridSearchCV
from sklearn.svm import SVC
from sklearn.utils import shuffle

path_active_normal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interflow-based/Active-Demultiplexed-Interflow/Active-Interflow-CSVs/'
path_full_random_normal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interflow-based/Full-Demultiplexed-Interflow/ALL-Full-CSVs/Full_Benign_Random-Interflow-CSVs/'
path_full_structured_normal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interflow-based/Full-Demultiplexed-Interflow/ALL-Full-CSVs/Full_Benign_Structured-Interflow-CSVs/'
path_minimal_normal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interflow-based/Minimal-Demultiplexed-Interflow/ALL-Minimal-CSVs/Minimal_Benign-Interflow-CSVs/'
path_reduced_normal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interflow-based/Reduced-Demultiplexed-Interflow/ALL-Reduced-CSVs/Reduced_Benign-Interflow-CSVs/'

path_full_scan = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interflow-based/Full_Attacks/scan/'
path_minimal_scan = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interflow-based/Minimal_Attacks/scan/'
path_reduced_scan = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interflow-based/Reduced_Attacks/scan/'

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

df_full_scan = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(path_full_scan + '*.csv')],
                         ignore_index=True)
df_full_scan = df_full_scan[
    ['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
     'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
     'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
     'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b', 'pushed_data_pkts_a2b',
     'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a', 'initial_window_bytes_a2b',
     'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
     'missed_data_a2b', 'missed_data_b2a']]

print("Full scan shape: ", df_full_scan.shape)

df_minimal_scan = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(path_minimal_scan + '*.csv')],
                            ignore_index=True)
df_minimal_scan = df_minimal_scan[
    ['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
     'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
     'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
     'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b', 'pushed_data_pkts_a2b',
     'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a', 'initial_window_bytes_a2b',
     'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
     'missed_data_a2b', 'missed_data_b2a']]

print("Minimal scan shape: ", df_minimal_scan.shape)
df_reduced_scan = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(path_reduced_scan + '*.csv')],
                            ignore_index=True)
df_reduced_scan = df_reduced_scan[
    ['total_packets_a2b', 'total_packets_b2a', 'unique_bytes_sent_a2b', 'unique_bytes_sent_b2a',
     'actual_data_bytes_a2b', 'actual_data_bytes_b2a', 'rexmt_data_bytes_a2b', 'rexmt_data_bytes_b2a',
     'idletime_max_a2b', 'idletime_max_b2a', 'ttl_stream_length_a2b', 'ttl_stream_length_b2a',
     'max_segm_size_a2b', 'max_segm_size_b2a', 'ack_pkts_sent_a2b', 'resets_sent_a2b', 'pushed_data_pkts_a2b',
     'SYN_pkts_sent_a2b', 'FIN_pkts_sent_a2b', 'SYN_pkts_sent_b2a', 'FIN_pkts_sent_b2a', 'initial_window_bytes_a2b',
     'initial_window_bytes_b2a', 'throughput_a2b', 'throughput_b2a', 'max_retr_time_a2b',
     'missed_data_a2b', 'missed_data_b2a']]
print("Reduced scan shape: ", df_reduced_scan.shape)

active_normal_sample = df_active_normal.sample(3000, random_state=42)
active_normal_sample['Target'] = 0
full_random_normal_sample = df_full_random_normal.sample(5000, random_state=42)
full_random_normal_sample['Target'] = 0
full_structured_normal_sample = df_full_structured_normal.sample(4000, random_state=42)
full_structured_normal_sample['Target'] = 0
minimal_normal_sample = df_minimal_normal.sample(3000, random_state=42)
minimal_normal_sample['Target'] = 0
reduced_normal_sample = df_reduced_normal.sample(5000, random_state=42)
reduced_normal_sample['Target'] = 0

full_scan_sample = df_full_scan.sample(20000, random_state=42)
full_scan_sample['Target'] = 1
minimal_scan_sample = df_minimal_scan.sample(10000, random_state=42)
minimal_scan_sample['Target'] = 1
reduced_scan_sample = df_reduced_scan.sample(10000, random_state=42)
reduced_scan_sample['Target'] = 1

final_set = [active_normal_sample, full_random_normal_sample, full_structured_normal_sample, minimal_normal_sample,
             reduced_normal_sample, full_scan_sample, minimal_scan_sample, reduced_scan_sample]

final = pd.concat(final_set)
final = shuffle(final)

target = final.iloc[:, -1]
final.drop(['Target'], inplace=True, axis=1)

X_train, X_test, y_train, y_test = train_test_split(final, target, test_size=0.2, random_state=42)

sc = StandardScaler()
X_train = sc.fit_transform(X_train)
X_test = sc.transform(X_test)

start = timeit.default_timer()

clf = SVC(kernel='rbf')
clf.fit(X_train, y_train)

predicted = clf.predict(X_test)
print(classification_report(y_test, predicted))
# final_scaled = sc.fit_transform(final)
# scores = cross_val_score(clf, final_scaled, target, cv=5, scoring='roc_auc')
# print("Accuracy: %0.2f (+/- %0.2f)" % (scores.mean(), scores.std() * 2))
print()
print("Confusion matrix: ", confusion_matrix(y_test, predicted))
tn, fp, fn, tp = confusion_matrix(y_test, predicted).ravel()
print("TP: ", tp, ", TN: ", tn, "FP: ", fp, "FN: ", fn)
print("ROC AUC: ", roc_auc_score(y_test, predicted))
end = timeit.default_timer()
print('Runtime: ', end - start)
