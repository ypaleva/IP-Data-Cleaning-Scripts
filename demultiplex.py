import glob
import os
import shutil
import subprocess

dir_path = '/home/yoanapaleva/PycharmProjects/networking-data-prep/'
perl_script = '/home/yoanapaleva/PycharmProjects/networking-data-prep/split-pcap.pl'
files = glob.glob(dir_path + '*.pcap')

for file in files:
    demultiplex_dir = os.path.basename(file).split('.')[0] + '-demultiplexed'
    print('Demultiplexing file: ', file)

    os.makedirs(demultiplex_dir)
    os.chdir(demultiplex_dir)

    shutil.copy(file, os.path.basename(file).split('.')[0] + '.pcap')
    # print(os.path.basename(file).split('.')[0] + '.pcap')

    pcap_file = str(dir_path + demultiplex_dir + '/*.pcap')
    print('PCAP file: ', pcap_file)
    pcap = glob.glob(pcap_file)[0]

    pipe = subprocess.Popen(["perl", perl_script, "sll", pcap], stdout=subprocess.PIPE)
    pipe.communicate()

    os.remove(dir_path + demultiplex_dir + '/' + os.path.basename(file).split('.')[0] + '.pcap')
    os.remove(dir_path + demultiplex_dir + '/' + os.path.basename(file).split('.')[0] + '.pcap' + '-missed-4-tuples')
    os.chdir(dir_path)
