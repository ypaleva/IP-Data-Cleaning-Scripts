import glob
import os
import timeit

import pandas as pd
import psutil
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.naive_bayes import GaussianNB, MultinomialNB, ComplementNB
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
import numpy as np
from sklearn.utils import shuffle
import warnings

warnings.filterwarnings("ignore", category=FutureWarning)

path_active_normal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interpacket-based/Active-Demultiplexed-Interpacket/Active-Interpacket-CSVs/'
path_full_random_normal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interpacket-based/Full-Demultiplexed/Full_Benign_Random-Demultiplexed/Full_Benign_Random-Interpacket-CSVs/'
path_full_structured_normal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interpacket-based/Full-Demultiplexed/Full_Benign_Structured-Demultiplexed/Full_Benign_Structured-Interpacket-CSVs/'
path_minimal_normal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interpacket-based/Minimal-Demultiplexed-Interpacket/Minimal_Benign-Demultiplexed/Minimal_Benign-Interpacket-CSVs/'
path_reduced_normal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interpacket-based/Reduced-Demultiplexed/Reduced_Benign-Demultiplexed/Reduced_Benign-Interpacket-CSVs/'

path_full_malicious = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interpacket-based/Full-Demultiplexed/Full_Malicious-Demultiplexed/Full_Malicious-Interpacket-CSVs/'
path_minimal_malicious = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interpacket-based/Minimal-Demultiplexed-Interpacket/Minimal_Malicious-Demultiplexed/Reduced_Malicious-Interpacket-CSVs/'
path_reduced_malicious = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interpacket-based/Reduced-Demultiplexed/Reduced_Malicious-Demultiplexed/Reduced_Malicious-Interpacket-CSVs/'

df_active_normal = pd.concat([pd.read_csv(f) for f in glob.glob(path_active_normal + '*.csv')], ignore_index=True)
print('Active set size: ', len(df_active_normal.index))
df_full_random_normal = pd.concat([pd.read_csv(f) for f in glob.glob(path_full_random_normal + '*.csv')],
                                  ignore_index=True)
print('Full random normal set size: ', len(df_full_random_normal.index))
df_full_structured_normal = pd.concat([pd.read_csv(f) for f in glob.glob(path_full_structured_normal + '*.csv')],
                                      ignore_index=True)
print('Full structured normal set size: ', len(df_full_structured_normal.index))
df_minimal_normal = pd.concat([pd.read_csv(f) for f in glob.glob(path_minimal_normal + '*.csv')], ignore_index=True)
print('Minimal normal set size: ', len(df_minimal_normal.index))
df_reduced_normal = pd.concat([pd.read_csv(f) for f in glob.glob(path_reduced_normal + '*.csv')], ignore_index=True)
print('Reduced normal set size: ', len(df_reduced_normal.index))
df_full_malicious = pd.concat([pd.read_csv(f) for f in glob.glob(path_full_malicious + '*.csv')], ignore_index=True)
print('Full malicious set size: ', len(df_full_malicious.index))
df_minimal_malicious = pd.concat([pd.read_csv(f) for f in glob.glob(path_minimal_malicious + '*.csv')],
                                 ignore_index=True)
print('Minimal malicious set size: ', len(df_minimal_malicious.index))
df_reduced_malicious = pd.concat([pd.read_csv(f) for f in glob.glob(path_reduced_malicious + '*.csv')],
                                 ignore_index=True)
print('Reduced malicious set size: ', len(df_reduced_malicious.index))

# active_normal_sample = df_active_normal.sample(3000, random_state=42)
# active_normal_sample['Target'] = 0
# full_random_normal_sample = df_full_random_normal.sample(3000, random_state=42)
# full_random_normal_sample['Target'] = 0
# full_structured_normal_sample = df_full_structured_normal.sample(3000, random_state=42)
# full_structured_normal_sample['Target'] = 0
# minimal_normal_sample = df_minimal_normal.sample(3000, random_state=42)
# minimal_normal_sample['Target'] = 0
# reduced_normal_sample = df_reduced_normal.sample(3000, random_state=42)
# reduced_normal_sample['Target'] = 0
#
# full_malicious_sample = df_full_malicious.sample(5000, random_state=42)
# full_malicious_sample['Target'] = 1
# minimal_malicious_sample = df_minimal_malicious.sample(5000, random_state=42)
# minimal_malicious_sample['Target'] = 1
# reduced_malicious_sample = df_reduced_malicious.sample(5000, random_state=42)
# reduced_malicious_sample['Target'] = 1
#
# final_set = [active_normal_sample, full_random_normal_sample, full_structured_normal_sample, minimal_normal_sample,
#              reduced_normal_sample, full_malicious_sample, minimal_malicious_sample, reduced_malicious_sample]
#
# final = pd.concat(final_set)
# final = shuffle(final)
#
# final = shuffle(final)
#
# target = final.iloc[:, -1]
# final.drop(['Target'], inplace=True, axis=1)
#
# sc = StandardScaler()
# sc.fit_transform(final)
#
# clf = SVC()
# grid = {'kernel': ('rbf', 'poly'), 'C': [1, 5, 10, 25, 50, 100, 250, 500, 1000], 'gamma': [0.01, 0.001, 0.0001]}
# clf_cv = GridSearchCV(clf, grid, scoring='roc_auc', n_jobs=-1)
# clf.fit(final, target)
# print('Best score:', clf_cv.best_score_)
# print('Best params:', clf_cv.best_params_)
