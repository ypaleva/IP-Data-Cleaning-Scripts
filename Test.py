import glob
import os

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler


def normalize_min_max(df):
    result = df.copy()
    for feature_name in df.columns:
        max_value = df[feature_name].max()
        min_value = df[feature_name].min()
        if (max_value - min_value) == 0:
            result[feature_name] = df[feature_name]
        else:
            result[feature_name] = (df[feature_name] - min_value) / (max_value - min_value)
    return result


def normalize_st_dev(df):
    result = df.copy()
    for feature_name in df.columns:
        value_mean = df[feature_name].mean()
        value_st_dev = df[feature_name].std()
        if value_mean == 0:
            result[feature_name] = df[feature_name]
        else:
            result[feature_name] = (df[feature_name] - value_mean) / value_st_dev
    return result


dir_path = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Malicious-Binary-Scaled'
os.makedirs(dir_path)
files = glob.glob('/home/yoanapaleva/PycharmProjects/networking-data-prep/*.csv')

scaler = StandardScaler()

for file in files:
    print(file)
    dataset = pd.read_csv(file)
    df_data = pd.DataFrame(dataset)
    # print(data.head(5))
    # print(data.info())
    # print(data.describe())

    df = df_data.copy()

    df = df.apply(lambda x: x.str.strip() if x.dtype == "object" else x)

    # pd.options.mode.chained_assignment = None
    df.replace('NA', np.nan, inplace=True)
    # Replace with most frequent value: df = df.apply(lambda x:x.fillna(x.value_counts().index[0]))
    df.fillna(0, inplace=True)

    df = df.join(df["SYN/FIN_pkts_sent_a2b"].str.split('/', 1, expand=True).rename(
        columns={0: 'SYN_pkts_sent_a2b', 1: 'FIN_pkts_sent_a2b'}))
    df = df.join(df["SYN/FIN_pkts_sent_b2a"].str.split('/', 1, expand=True).rename(
        columns={0: 'SYN_pkts_sent_b2a', 1: 'FIN_pkts_sent_b2a'}))
    df = df.join(df["req_1323_ws/ts_a2b"].str.split('/', 1, expand=True).rename(
        columns={0: 'req_1323_ws_a2b', 1: 'req_1323_ts_a2b'}))
    df = df.join(df["req_1323_ws/ts_b2a"].str.split('/', 1, expand=True).rename(
        columns={0: 'req_1323_ws_b2a', 1: 'req_1323_ts_b2a'}))

    df.drop(['SYN/FIN_pkts_sent_a2b', 'SYN/FIN_pkts_sent_b2a', 'req_1323_ws/ts_a2b', 'req_1323_ws/ts_b2a'], axis=1,
            inplace=True)

    df.replace('Y', 1, inplace=True)
    df.replace('N', 0, inplace=True)

    df.drop(['conn_#', 'host_a', 'host_b', 'port_a', 'port_b', 'first_packet', 'last_packet'], axis=1, inplace=True)

    df = df.applymap(lambda x: pd.to_numeric(x,errors='coerce'))

    scaled = scaler.fit_transform(df)

    # df = normalize_st_dev(df)

    # df.insert(df.columns.size, 'attack_score', '0', allow_duplicates=True)
    # df.insert(df.columns.size, 'attack_class', 'normal', allow_duplicates=True)

    os.chdir(dir_path)

    new_filename = os.path.basename(file).split('.')[0] + '-scaled'
    pd.DataFrame(scaled).to_csv(new_filename + '.csv', index=False)
