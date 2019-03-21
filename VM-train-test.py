import glob
import timeit
import warnings

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.utils import shuffle

path_active_normal = './Active-Interflow-CSVs/'
path_full_random_normal = './Full-Interflow-CSVs/Full_Benign_Random-Interflow-CSVs/'
path_full_structured_normal = './Full-Interflow-CSVs/Full_Benign_Structured-Interflow-CSVs/'
path_minimal_normal = './Minimal-Interflow-CSVs/Minimal_Benign-Interflow-CSVs/'
path_reduced_normal = './Reduced-Interflow-CSVs/Reduced_Benign-Interflow-CSVs/'

path_full_malicious = './Full-Interflow-CSVs/Full_Malicious-Interflow-CSVs/'
path_minimal_malicious = './Minimal-Interflow-CSVs/Minimal_Malicious-Interflow-CSVs/'
path_reduced_malicious = './Reduced-Interflow-CSVs/Reduced_Malicious-Interflow-CSVs/'

df_active_normal = pd.concat([pd.read_csv(f) for f in glob.glob(path_active_normal + '*.csv')], ignore_index=True)
print("Active normal set size: ", len(df_active_normal.index))
# print("Active normal shape: ", df_active_normal.shape)
df_full_random_normal = pd.concat([pd.read_csv(f) for f in glob.glob(path_full_random_normal + '*.csv')],
                                  ignore_index=True)
print("Full random normal set size: ", len(df_full_random_normal.index))
# print("Full random normal shape: ", df_full_random_normal.shape)
df_full_structured_normal = pd.concat([pd.read_csv(f) for f in glob.glob(path_full_structured_normal + '*.csv')],
                                      ignore_index=True)
print("Full structured normal set size: ", len(df_full_structured_normal.index))
# print("Full structured normal shape: ", df_full_structured_normal.shape)
df_minimal_normal = pd.concat([pd.read_csv(f) for f in glob.glob(path_minimal_normal + '*.csv')], ignore_index=True)
print("Minimal normal set size: ", len(df_minimal_normal.index))
# print("Minimal normal shape: ", df_minimal_normal.shape)
df_reduced_normal = pd.concat([pd.read_csv(f) for f in glob.glob(path_reduced_normal + '*.csv')], ignore_index=True)
print("Reduced normal set size: ", len(df_reduced_normal.index))
# print("Reduced normal shape: ", df_reduced_normal.shape)
df_full_malicious = pd.concat([pd.read_csv(f) for f in glob.glob(path_full_malicious + '*.csv')], ignore_index=True)
print("Full malicious set size: ", len(df_full_malicious.index))
# print("Full malicious shape: ", df_full_malicious.shape)
df_minimal_malicious = pd.concat([pd.read_csv(f) for f in glob.glob(path_minimal_malicious + '*.csv')],
                                 ignore_index=True)
print("Minimal malicious set size: ", len(df_minimal_malicious.index))
# print("Minimal malicious shape: ", df_minimal_malicious.shape)
df_reduced_malicious = pd.concat([pd.read_csv(f) for f in glob.glob(path_reduced_malicious + '*.csv')],
                                 ignore_index=True)
print("Reduced malicious set size: ", len(df_reduced_malicious.index))
# print("Reduced malicious shape: ", df_reduced_malicious.shape)

# 20+20+20+20+20 normal + 30+30+40 malicious

active_normal_sample = df_active_normal.sample(20, random_state=42)
active_normal_sample['Target'] = 0
full_random_normal_sample = df_full_random_normal.sample(20, random_state=42)
full_random_normal_sample['Target'] = 0
full_structured_normal_sample = df_full_structured_normal.sample(20, random_state=42)
full_structured_normal_sample['Target'] = 0
minimal_normal_sample = df_minimal_normal.sample(20, random_state=42)
minimal_normal_sample['Target'] = 0
reduced_normal_sample = df_reduced_normal.sample(20, random_state=42)
reduced_normal_sample['Target'] = 0

full_malicious_sample = df_full_malicious.sample(30, random_state=42)
full_malicious_sample['Target'] = 1
minimal_malicious_sample = df_minimal_malicious.sample(30, random_state=42)
minimal_malicious_sample['Target'] = 1
reduced_malicious_sample = df_reduced_malicious.sample(40, random_state=42)
reduced_malicious_sample['Target'] = 1

final_set = [active_normal_sample, full_random_normal_sample, full_structured_normal_sample, minimal_normal_sample,
             reduced_normal_sample, full_malicious_sample, minimal_malicious_sample, reduced_malicious_sample]

final = pd.concat(final_set)
final = shuffle(final)

target = final.iloc[:, -1]
final.drop(['Target'], inplace=True, axis=1)

X_train, X_test, y_train, y_test = train_test_split(final, target, test_size=0.2, random_state=42)

start = timeit.default_timer()
clf = SVC(kernel='rbf', C=5, gamma=0.001)
clf.fit(X_train, y_train)

predicted = clf.predict(X_test)
print(classification_report(y_test, predicted))
scores = cross_val_score(clf, final, target, cv=5, scoring='roc_auc')
print("Accuracy: %0.2f (+/- %0.2f)" % (scores.mean(), scores.std() * 2))
print()
print("Confusion matrix: ", confusion_matrix(y_test, predicted))
tn, fp, fn, tp = confusion_matrix(y_test, predicted).ravel()
print("TP: ", tp, ", TN: ", tn, "FP: ", fp, "FN: ", fn)
print("ROC AUC: ", roc_auc_score(y_test, predicted))
end = timeit.default_timer()
print('Runtime: ', end - start)
