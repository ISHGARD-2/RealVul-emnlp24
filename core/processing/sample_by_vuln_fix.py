import difflib
import logging
import os.path
import re

from tqdm import tqdm

from configs.settings import DATA_PATH
from core import FuncCall
from utils.file import Directory, clear_slice
from utils.func_json import write_json, read_json
from utils.log import log




def sampling_by_fix(target_directory):
    """
    cve_list = {cve_database_id: {file_id: {'bad': file, 'good':file}}}
    samples = [{},{}]
    """
    files, file_count, time_consume = Directory(target_directory).collect_files()
    funcs = FuncCall(target_directory, files)
    funcs.main('sampling_by_fix')

    # check files
    cve_list = {}
    for file in funcs.file_list:
        file_name = file.file_path

        cve_database_id = int(file_name.split('_')[1])
        file_label = file_name.split('_')[0]
        file_id = int(file_name.split('_')[2].split('.')[0])

        if cve_database_id not in cve_list.keys():
            cve_list[cve_database_id] = {}

        if file_id not in cve_list[cve_database_id].keys():
            cve_list[cve_database_id][file_id] = {file_label: file}
        else:
            cve_list[cve_database_id][file_id][file_label] = file

    # sampling
    samples = []
    for cve_id in tqdm(cve_list.keys()):
        cve = cve_list[cve_id]

        for file_id in cve.keys():
            file = cve[file_id]

            if 'bad' not in file.keys() or 'good' not in file.keys():
                continue

            bad_funcs = file['bad'].function_list
            good_funcs = file['good'].function_list

            for bad_func in bad_funcs:

                match_func = []
                for good_func in good_funcs:
                    if bad_func.func_name == good_func.func_name and bad_func.func_type == good_func.func_type:
                        match_func.append(good_func)

                if len(match_func) == 0:
                    sample = {'func': bad_func.code,
                              'id': len(samples),
                              'file_name': bad_func.file,
                              'label': 'good',
                              'message': 'sampling_by_fix',
                              'CVE_database_id': cve_id
                              }
                    samples.append(sample)
                elif len(match_func) == 1:
                    bad_code = re.sub('\s|\t|\n', '', bad_func.code)
                    good_code = re.sub('\s|\t|\n', '', match_func[0].code)
                    similarity = difflib.SequenceMatcher(None, bad_code, good_code).quick_ratio()
                    if similarity < 1:
                        sample_bad = {'func': bad_func.code,
                                      'id': len(samples),
                                      'file_name': bad_func.file,
                                      'label': 'bad',
                                      'message': 'sampling_by_fix',
                                      'CVE_database_id': cve_id
                                      }
                        sample_good = {'func': match_func[0].code,
                                       'id': len(samples) + 1,
                                       'file_name': match_func[0].file,
                                       'label': 'good',
                                       'message': 'sampling_by_fix',
                                       'CVE_database_id': cve_id
                                       }
                        samples.append(sample_bad)
                        samples.append(sample_good)
                    else:
                        sample = {'func': bad_func.code,
                                  'id': len(samples),
                                  'file_name': bad_func.file,
                                  'label': 'good',
                                  'message': 'sampling_by_fix',
                                  'CVE_database_id': cve_id
                                  }
                        samples.append(sample)

                elif len(match_func) > 1:
                    continue

    for i, sam in enumerate(samples):
        samples[i]['func'] = clear_slice(sam['func'], append_endline=False)
    return samples


if __name__ == '__main__':
    log(logging.DEBUG)

    #corssvul_data_path_79 = DATA_PATH + "/dataset_unique_79.json"
    corssvul_data_path_89 = DATA_PATH + "/dataset_unique_89.json"

    #xss_target_directory = DATA_PATH + '/crossvul/xss/'
    #xss_write_path = DATA_PATH + '/samples_by_fix_79.json'

    sqli_target_directory = DATA_PATH + '/crossvul/sqli/'
    sqli_write_path = DATA_PATH + '/samples_by_fix_89.json'

    # samples = sampling_by_fix(xss_target_directory)
    # write_json(samples, xss_write_path)

    samples = sampling_by_fix(sqli_target_directory)
    write_json(samples, sqli_write_path)
