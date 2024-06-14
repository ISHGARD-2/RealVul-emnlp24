import logging
import os

from configs.settings import DATA_PATH
from utils.func_json import read_json
from utils.log import log, logger
from utils.my_utils import analy_metadata

if __name__ == '__main__':
    log(logging.DEBUG)
    crossvul_files_path = DATA_PATH + '/crossvul/all'
    crossvul_files_path_89 = DATA_PATH + '/crossvul/sqli'
    crossvul_files_path_79 = DATA_PATH + '/crossvul/xss'

    SARD_79 = read_json(DATA_PATH + '/SARD_php_vulnerability_79.json')
    SARD_89 = read_json(DATA_PATH + '/SARD_php_vulnerability_89.json')

    corssvul_real_79 = read_json(DATA_PATH + '/dataset_unique_79.json')
    corssvul_real_89 = read_json(DATA_PATH + '/dataset_unique_89.json')

    corssvul_fix_79 = read_json(DATA_PATH + '/samples_by_fix_79.json')
    corssvul_fix_89 = read_json(DATA_PATH + '/samples_by_fix_89.json')

    corssvul_syn_79 = read_json(DATA_PATH + '/dataset_synthesis_79.json')
    corssvul_syn_89 = read_json(DATA_PATH + '/dataset_synthesis_89.json')

    # count projects all
    project_data = analy_metadata(['89', '79'])
    crossvul_files_names = os.listdir(crossvul_files_path)
    crossvul_cves = list(set([int(name.split('_')[1]) for name in crossvul_files_names]))

    crossvul_project_all = []
    for proj in project_data:
        for cve in crossvul_cves:
            if cve in proj['cve']:
                crossvul_project_all.append(proj)
                break

    logger.info("[all] Number of Cross Projects: {}".format(str(len(crossvul_project_all))))

    # count projects 79
    project_data = analy_metadata(['79'])
    crossvul_files_names = os.listdir(crossvul_files_path_79)
    crossvul_cves = list(set([int(name.split('_')[1]) for name in crossvul_files_names]))

    crossvul_project_79 = []
    for proj in project_data:
        for cve in crossvul_cves:
            if cve in proj['cve']:
                crossvul_project_79.append(proj)
                break

    logger.info("[79] Number of Cross Projects: {}".format(str(len(crossvul_project_79))))

    # count projects 89
    project_data = analy_metadata(['89'])
    crossvul_files_names = os.listdir(crossvul_files_path_89)
    crossvul_cves = list(set([int(name.split('_')[1]) for name in crossvul_files_names]))

    crossvul_project_89 = []
    for proj in project_data:
        for cve in crossvul_cves:
            if cve in proj['cve']:
                crossvul_project_89.append(proj)
                break

    logger.info("[89] Number of Cross Projects: {}\n\n".format(str(len(crossvul_project_89))))




    # count dataset

    logger.info("[all] Number of samples_by_fix: {}, {}".
                format(str(len(corssvul_fix_79)+len(corssvul_fix_89)),
                       str(sum(data['label'] == "bad" for data in corssvul_fix_79+corssvul_fix_89))))
    logger.info("[79] Number of samples_by_fix: {}, {}".
                format(str(len(corssvul_fix_79)),
                       str(sum(data['label'] == "bad" for data in corssvul_fix_79))))
    logger.info("[89] Number of samples_by_fix: {}, {}\n\n".
                format(str(len(corssvul_fix_89)),
                       str(sum(data['label'] == "bad" for data in corssvul_fix_89))))

    logger.info("[all] Number of real_samples: {}, {}".
                format(str(len(corssvul_real_79)+len(corssvul_real_89)),
                       str(sum(data['label'] == "bad" for data in corssvul_real_79+corssvul_real_89))))
    logger.info("[79] Number of real_samples: {}, {}".
                format(str(len(corssvul_real_79)),
                       str(sum(data['label'] == "bad" for data in corssvul_real_79))))
    logger.info("[89] Number of real_samples: {}, {}\n\n".
                format(str(len(corssvul_real_89)),
                       str(sum(data['label'] == "bad" for data in corssvul_real_89))))

    logger.info("[all] Number of SARD_samples and total for syn: {}, {}".
                format(str(len(SARD_79) + len(SARD_89)), str(len(SARD_79) + len(SARD_89) + len(corssvul_real_79)+len(corssvul_real_89) )))
    logger.info("[79] Number of SARD_samples and total for syn: {}, {}".
                format(str(len(SARD_79)),
                       str(len(SARD_79) + len(corssvul_real_79))))
    logger.info("[89] Number of SARD_samples and total for syn: {}, {}\n\n".
                format(str(len(SARD_89)),
                       str( len(SARD_89) + len(corssvul_real_89) )))



    logger.info("[all] Number of syn_samples: {}, {}".
                format(str(len(corssvul_syn_79) + len(corssvul_syn_89)),
                       str(sum(data['label'] == "bad" for data in corssvul_syn_79 + corssvul_syn_89))))
    logger.info("[79] Number of syn_samples: {}, {}".
                format(str(len(corssvul_syn_79)),
                       str(sum(data['label'] == "bad" for data in corssvul_syn_79))))
    logger.info("[89] Number of syn_samples: {}, {}\n\n".
                format(str(len(corssvul_syn_89)),
                       str(sum(data['label'] == "bad" for data in corssvul_syn_89))))








