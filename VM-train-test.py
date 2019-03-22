import glob
import timeit
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.utils import shuffle

path_active_normal = './Active-Interpacket-CSVs/'
path_full_random_normal = './Full-Interpacket-CSVs/Full_Benign_Random-Interpacket-CSVs/'
path_full_structured_normal = './Full-Interpacket-CSVs/Full_Benign_Structured-Interpacket-CSVs/'
path_minimal_normal = './Minimal-Interpacket-CSVs/Minimal_Benign-Interpacket-CSVs/'
path_reduced_normal = './Reduced-Interpacket-CSVs/Reduced_Benign-Interpacket-CSVs/'

path_full_flood = './Full_Attacks/flood/'

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
df_full_flood = pd.concat([pd.read_csv(f, low_memory=False) for f in glob.glob(path_full_flood + '*.csv')],
                          ignore_index=True)
print("Full flood shape: ", df_full_flood.shape)

active_normal_sample = df_active_normal.sample(3000, random_state=42)
active_normal_sample['Target'] = 0
full_random_normal_sample = df_full_random_normal.sample(4000, random_state=42)
full_random_normal_sample['Target'] = 0
full_structured_normal_sample = df_full_structured_normal.sample(5000, random_state=42)
full_structured_normal_sample['Target'] = 0
minimal_normal_sample = df_minimal_normal.sample(5000, random_state=42)
minimal_normal_sample['Target'] = 0
reduced_normal_sample = df_reduced_normal.sample(3000, random_state=42)
reduced_normal_sample['Target'] = 0

full_flood_sample = df_full_flood.sample(20000, random_state=42)
full_flood_sample['Target'] = 1

final_set = [active_normal_sample, full_random_normal_sample, full_structured_normal_sample, minimal_normal_sample,
             reduced_normal_sample, full_flood_sample]

final = pd.concat(final_set)
final = shuffle(final)

target = final.iloc[:, -1]
final.drop(['Target'], inplace=True, axis=1)

X_train, X_test, y_train, y_test = train_test_split(final, target, test_size=0.2, random_state=42)

sc = StandardScaler()
# X_train = sc.fit_transform(X_train)
# X_test = sc.transform(X_test)
scaled = sc.fit_transform(final)
clf = LogisticRegression(penalty='l1', max_iter=15000)
grid = {'C': [0.001, 0.01, 0.1, 1, 5, 10, 50, 100], 'solver': ['saga']}
clf_cv = GridSearchCV(clf, grid, cv=5, scoring='roc_auc', n_jobs=-1, verbose=2)

clf_cv.fit(scaled, target)

print("Best score: ", clf_cv.best_score_)
print("Best params: ", clf_cv.best_params_)
