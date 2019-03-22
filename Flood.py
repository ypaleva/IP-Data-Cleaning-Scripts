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

path_full_flood = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interflow-based/Full_Attacks/flood/'

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


active_normal_sample = df_active_normal.sample(50, random_state=42)
active_normal_sample['Target'] = 0
full_random_normal_sample = df_full_random_normal.sample(77, random_state=42)
full_random_normal_sample['Target'] = 0
full_structured_normal_sample = df_full_structured_normal.sample(50, random_state=42)
full_structured_normal_sample['Target'] = 0
minimal_normal_sample = df_minimal_normal.sample(50, random_state=42)
minimal_normal_sample['Target'] = 0
reduced_normal_sample = df_reduced_normal.sample(50, random_state=42)
reduced_normal_sample['Target'] = 0

full_flood_sample = df_full_flood.sample(277, random_state=42)
full_flood_sample['Target'] = 1


final_set = [active_normal_sample, full_random_normal_sample, full_structured_normal_sample, minimal_normal_sample,
             reduced_normal_sample, full_flood_sample]

final = pd.concat(final_set)
final = shuffle(final)

target = final.iloc[:, -1]
final.drop(['Target'], inplace=True, axis=1)

sc = StandardScaler()

clf = SVC(kernel='rbf')
grid = {'C': [1, 5, 10, 25, 50, 100, 250, 500, 1000], 'gamma': [0.01, 0.001, 0.0001]}
clf_cv = GridSearchCV(clf, grid, cv=5, scoring='roc_auc', n_jobs=-1, verbose=2)

clf_cv.fit(sc.fit_transform(final), target)

print("Best score: ", clf_cv.best_score_)
print("Best params: ", clf_cv.best_params_)


