
import os
import logging
from configs.settings import RULES_PATH

from utils.log import logger



def block(index):
    default_index_reverse = 'in-function'
    default_index = 0
    blocks = {
        'in-function-up': 0,
        'in-function-down': 1,
        'in-current-line': 2,
        'in-function': 3,
        'in-class': 4,
        'in-class-up': 5,
        'in-class-down': 6,
        'in-file': 7,
        'in-file-up': 8,
        'in-file-down': 9
    }
    if isinstance(index, int):
        blocks_reverse = dict((v, k) for k, v in blocks.items())
        if index in blocks_reverse:
            return blocks_reverse[index]
        else:
            return default_index_reverse
    else:
        if index in blocks:
            return blocks[index]
        else:
            return default_index


class Rule(object):
    def __init__(self):
        origin_lans = ["php"]

        self.rule_dict = {}

        # 逐个处理每一种lan
        for lan in origin_lans:
            self.rules_path = RULES_PATH + "/" + lan
            if not os.path.exists(self.rules_path):
                logger.error("[INIT][RULE] language {} can't found rules".format(self.rules_path))
                os.mkdir(self.rules_path)

            self.rule_list = self.list_parse()

            # import function from rule
            for rule in self.rule_list:
                rulename = rule.split('.')[0]
                rulefile = "rules." + lan + "." + rulename
                self.rule_dict[rulename] = __import__(rulefile, fromlist=rulename)

        self.vulnerabilities = self.vul_init()

    def rules(self, special_rules=None):

        rules = {}

        if special_rules is None:
            logging.error("[+++rule+++] no special rule")
            return self.rule_dict
        else:
            for rulename in self.rule_dict:
                if rulename+".py" in special_rules:
                    rules[rulename] = self.rule_dict[rulename]

            return rules

    def list_parse(self):

        files = os.listdir(self.rules_path)
        result = []

        for f in files:
            if f.startswith("CVI_"):
                result.append(f)

        return result

    def vul_init(self):

        vul_list = []

        for rulename in self.rule_dict:
            p = getattr(self.rule_dict[rulename], rulename)

            ruleclass = p()
            vul_list.append(ruleclass.vulnerability)

        return vul_list
