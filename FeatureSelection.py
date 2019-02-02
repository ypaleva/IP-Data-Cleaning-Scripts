import pandas as pd
import numpy as np
from sklearn.feature_selection import SelectKBest, chi2, VarianceThreshold, GenericUnivariateSelect
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

dir_path_active = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Normal_CSVs_Cropped/active-cropped.csv'
dir_path_full_random = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Normal_CSVs_Cropped/full-benign-random-cropped.csv'
dir_path_full_structured = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Normal_CSVs_Cropped/full-benign-structured-cropped.csv'
dir_path_minimal = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Normal_CSVs_Cropped/minimal-benign-cropped.csv'
dir_path_reduced = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Normal_CSVs_Cropped/reduced-benign-cropped.csv'

dir_path_full_malicious = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Malicious_CSVs_Cropped/full-malicious-cropped.csv'
dir_path_minimal_malicious = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Malicious_CSVs_Cropped/minimal-malicious-cropped.csv'
dir_path_reduced_malicious = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Malicious_CSVs_Cropped/reduced-malicious-cropped.csv'

# --------------------------------------------------------------------------------------------------------------------------

df_active = pd.read_csv(dir_path_active)
df_active['Target'] = '0'
df_full_random = pd.read_csv(dir_path_full_random)
df_full_random['Target'] = '0'
df_full_structured = pd.read_csv(dir_path_full_structured)
df_full_structured['Target'] = '0'
df_minimal = pd.read_csv(dir_path_minimal)
df_minimal['Target'] = '0'
df_reduced = pd.read_csv(dir_path_reduced)
df_reduced['Target'] = '0'

df_full_malicious = pd.read_csv(dir_path_full_malicious)
df_full_malicious['Target'] = '1'
df_minimal_malicious = pd.read_csv(dir_path_minimal_malicious)
df_minimal_malicious['Target'] = '1'
df_reduced_malicious = pd.read_csv(dir_path_reduced_malicious)
df_reduced_malicious['Target'] = '1'

print('Active: ', df_active.shape)
print('Full random: ', df_full_random.shape)
print('Full structured: ', df_full_structured.shape)
print('Minimal: ', df_minimal.shape)
print('Reduced: ', df_reduced.shape)
print()
print()
print('Full malicious: ', df_full_malicious.shape)
print('Minimal malicious: ', df_minimal_malicious.shape)
print('Reduced malicious: ', df_reduced_malicious.shape)
print()
print('-------------------------------------------------------')

# All benign: 173048

active_sample = df_active.sample(3000)  # out of 3469
full_random_sample = df_full_random.sample(3000)  # out of 93427
full_structured_sample = df_full_structured.sample(3000)  # out of 24054
minimal_sample = df_minimal.sample(3000)  # out of 15543
reduced_sample = df_reduced.sample(3000)  # out of 36555

# All malicious: 819791

full_malicious_sample = df_full_malicious.sample(5000)  # out of 105629
minimal_malicious_sample = df_minimal_malicious.sample(5000)  # out of 340432
reduced_malicious_sample = df_reduced_malicious.sample(5000)  # out of 373730

benign_frames = [active_sample, full_random_sample, full_structured_sample, minimal_sample, reduced_sample]
malicious_frames = [full_malicious_sample, minimal_malicious_sample, reduced_malicious_sample]

all_benign = pd.concat(benign_frames)
all_malicious = pd.concat(malicious_frames)

final_set = [all_benign, all_malicious]
final = pd.concat(final_set)

X_train, X_test, y_train, y_test = train_test_split(final.drop('Target', axis=1), final['Target'], test_size=0.001,
                                                    random_state=42)

# std_scaler = StandardScaler()
# X_train = std_scaler.fit_transform(X_train)
vt = VarianceThreshold(threshold=(.8 * (1 - .8)))
vt.fit(X_train)

transformer = GenericUnivariateSelect(chi2, 'k_best', param=20)
X_new = transformer.fit_transform(X_train, y_train)

feature_indices = transformer.get_support(indices=True)

feature_names = [final.columns[idx]
                 for idx, _
                 in enumerate(final)
                 if idx
                 in feature_indices]

removed_features = list(np.setdiff1d(final.columns, feature_names))

print("Found {0} low-variance columns.".format(len(removed_features)))
print(feature_names.__len__())
print(feature_names)
