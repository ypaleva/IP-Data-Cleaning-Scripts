import glob
import timeit
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import GridSearchCV, train_test_split, cross_val_score
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.utils import shuffle

path_active_normal = './Active-Interpacket-CSVs/'
path_full_random_normal = './Full-Interpacket-CSVs/Full_Benign_Random-Interpacket-CSVs/'
path_full_structured_normal = './Full-Interpacket-CSVs/Full_Benign_Structured-Interpacket-CSVs/'
path_minimal_normal = './Minimal-Interpacket-CSVs/Minimal_Benign-Interpacket-CSVs/'
path_reduced_normal = './Reduced-Interpacket-CSVs/Reduced_Benign-Interpacket-CSVs/'

path_full_scan = './Full_Attacks/scan/'
path_minimal_scan = './Minimal_Attacks/scan/'
path_reduced_scan = './Reduced_Attacks/scan/'

df_active_normal = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(path_active_normal + '*.csv')],
                             ignore_index=True)
print("Active normal shape: ", df_active_normal.shape)
df_full_random_normal = pd.concat(
    [pd.read_csv(f, low_memory=False) for f in glob.glob(path_full_random_normal + '*.csv')],
    ignore_index=True)
print("Full random normal shape: ", df_full_random_normal.shape)
df_full_structured_normal = pd.concat(
    [pd.read_csv(f, low_memory=False) for f in glob.glob(path_full_structured_normal + '*.csv')],
    ignore_index=True)
print("Full structured normal shape: ", df_full_structured_normal.shape)
df_minimal_normal = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(path_minimal_normal + '*.csv')],
                              ignore_index=True)
print("Minimal normal shape: ", df_minimal_normal.shape)
df_reduced_normal = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(path_reduced_normal + '*.csv')],
                              ignore_index=True)
print("Reduced normal shape: ", df_reduced_normal.shape)

print()
df_full_scan = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(path_full_scan + '*.csv')],
                         ignore_index=True)
print("Full scan shape: ", df_full_scan.shape)

df_minimal_scan = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(path_minimal_scan + '*.csv')],
                            ignore_index=True)
print("Minimal scan shape: ", df_minimal_scan.shape)

df_reduced_scan = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(path_reduced_scan + '*.csv')],
                            ignore_index=True)
print("Reduced scan shape: ", df_reduced_scan.shape)

active_normal_sample = df_active_normal.sample(4000, random_state=42)
active_normal_sample['Target'] = 0
full_random_normal_sample = df_full_random_normal.sample(60000, random_state=42)
full_random_normal_sample['Target'] = 0
full_structured_normal_sample = df_full_structured_normal.sample(30000, random_state=42)
full_structured_normal_sample['Target'] = 0
minimal_normal_sample = df_minimal_normal.sample(15000, random_state=42)
minimal_normal_sample['Target'] = 0
reduced_normal_sample = df_reduced_normal.sample(41000, random_state=42)
reduced_normal_sample['Target'] = 0

full_scan_sample = df_full_scan.sample(50000, random_state=42)
full_scan_sample['Target'] = 1
minimal_scan_sample = df_minimal_scan.sample(50000, random_state=42)
minimal_scan_sample['Target'] = 1
reduced_scan_sample = df_reduced_scan.sample(50000, random_state=42)
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
print("Scaling done...")
start = timeit.default_timer()
# clf = LogisticRegression(C=100, solver='saga', penalty='l2', max_iter=15000)
clf = SVC(kernel='rbf', C=500, gamma=0.01)
# clf = GaussianNB()

clf.fit(X_train, y_train)
print("Training done...")
predicted = clf.predict(X_test)
print(classification_report(y_test, predicted))
scaled = sc.fit_transform(final)
scores = cross_val_score(clf, scaled, target, cv=5, scoring='roc_auc')
print("Accuracy: %0.2f (+/- %0.2f)" % (scores.mean(), scores.std() * 2))
print("Confusion matrix: ", confusion_matrix(y_test, predicted))
tn, fp, fn, tp = confusion_matrix(y_test, predicted).ravel()
print("TP: ", tp, ", TN: ", tn, "FP: ", fp, "FN: ", fn)
print("ROC AUC: ", roc_auc_score(y_test, predicted))
end = timeit.default_timer()
print('Runtime: ', end - start)
