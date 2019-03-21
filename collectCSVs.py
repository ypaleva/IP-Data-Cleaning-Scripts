import os
import glob
import shutil

dir_path = '/home/yoanapaleva/PycharmProjects/networking-data-prep/Interpacket-based/Minimal-Demultiplexed-Interpacket/Minimal_Malicious-Demultiplexed'
directory = dir_path + '/'
extension = 'csv'

print('Directory: ', directory)
folders = os.listdir(directory)
folders[:] = [d for d in folders if not d[0] == '.']
print('All subfolders in directory: ', folders.__len__())

destination_folder = directory + 'Reduced_Malicious-Interflow-CSVs'
if not os.path.exists(destination_folder):
    os.makedirs(destination_folder)

for folder in folders:
    print('Folder: ', folder)
    folder_path = directory + folder + '/'
    os.chdir(folder_path)
    csv_files = [i for i in glob.glob('*.{}'.format(extension))]
    shutil.copy(csv_files[0], destination_folder)
