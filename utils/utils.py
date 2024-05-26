
import os
import re

from configs.const import NOT_SUPPORT_STRING, SLICE_FILTER, INPUT_VARIABLES, REG, STRING_REPLACE_ELEMENT, REGEX
from configs.settings import RULES_PATH

from utils.log import logger

from phply.phplex import lexer
from phply.phpparse import make_parser

TARGET_MODE_FILE = 'file'
TARGET_MODE_FOLDER = 'folder'


class ParseArgs(object):
    def __init__(self, target, formatter, output, special_rules=None, a_sid=None):
        self.target = target
        self.formatter = formatter
        self.output = output if output else ""
        self.language = ['php']
        self.sid = a_sid

        if special_rules != None and special_rules != '':
            self.special_rules = []
            extension = '.py'
            start_name = 'CVI_'

            if ',' in special_rules:
                # check rule name
                s_rules = special_rules.split(',')
                for sr in s_rules:
                    if extension not in sr:
                        sr += extension
                    if start_name not in sr:
                        sr = start_name + sr

                    if self._check_rule_name(sr):
                        self.special_rules.append(sr)
                    else:
                        logger.critical('[PARSE-ARGS] Rule {sr} not exist'.format(sr=sr))
            else:
                special_rules = start_name + special_rules + extension

                if self._check_rule_name(special_rules):
                    self.special_rules = [special_rules]
                else:
                    logger.critical(
                        '[PARSE-ARGS] Exception special rule name(e.g: CVI-110001): {sr}'.format(sr=special_rules))
        else:
            self.special_rules = None


    @staticmethod
    def _check_rule_name(name):
        paths = os.listdir(RULES_PATH)

        for p in paths:
            try:
                if name in os.listdir(os.path.join(RULES_PATH, p)):
                    return True
            except:
                continue

        return False


    @property
    def target_mode(self):
        """
        Parse target mode (git/file/folder/compress)
        :return: str
        """
        target_mode = None

        if os.path.isfile(self.target):
            target_mode = TARGET_MODE_FILE
        if os.path.isdir(self.target):
            target_mode = TARGET_MODE_FOLDER
        if target_mode is None:
            logger.critical('[PARSE-ARGS] [-t <target>] can\'t empty!')
            exit()
        logger.debug('[PARSE-ARGS] Target Mode: {mode}'.format(mode=target_mode))
        return target_mode


    def target_directory(self, target_mode):
        target_directory = None
        if target_mode == TARGET_MODE_FOLDER:
            target_directory = self.target
        elif target_mode == TARGET_MODE_FILE:
            target_directory = self.target
            return target_directory
        else:
            logger.critical('[PARSE-ARGS] exception target mode ({mode})'.format(mode=target_mode))
            exit()

        logger.debug('[PARSE-ARGS] target directory: {directory}'.format(directory=target_directory))
        target_directory = os.path.abspath(target_directory)

        return target_directory


def replace_pad(code):
    new_code = code
    replace_list = [[
        r"\.\s*((\_PAD\_)|(\"\")|(\'\'))\s*\.",
        ".",
        ],
        [
            r"echo\s*((\_PAD\_)|(\"\")|(\'\'))\s*\.",
            "echo ",
        ],
        [
            r"\.\s*((\_PAD\_)|(\"\")|(\'\'))\s*;",
            ";",
        ],
        [
            r"\s*((\_PAD\_)|(\"\")|(\'\'))\s*\.",
            "",
        ]
    ]


    contain = False
    for regex in replace_list:
        if re.search(regex[0], new_code, re.I):
            contain = True
            break

    while contain:
        for regex in replace_list:
            new_code = re.sub(regex[0], regex[1], new_code)

        contain = False
        for regex in replace_list:
            if re.search(regex[0], new_code, re.I):
                contain = True
                break

    return new_code


def slilce_check_syntax(code, log=True):

    try:
        parser = make_parser()
        parser.parse(code, debug=False, lexer=lexer.clone(), tracking=True)

    except SyntaxError as e:
        if log:
            logger.warning('[UTILS] slice syntax error\n')
        return False

    except:
        if log:
            logger.warning('[UTILS] slice error\n')
        return False
    return True

def match_vars(regex_string, with_position=False):
    """
    regex string input
    :regex_string: regex match string
    :return:
    """
    reg = "\\$\\w+"
    if re.search(reg, regex_string, re.I):
        p = re.compile(reg)
        match = p.findall(regex_string)
        matchs = re.finditer(reg, regex_string)

        match_out = []
        positions = []

        for i, mp in enumerate(matchs):
            m = match[i]
            lp = mp.start()
            rp = mp.end()

            if lp > 0 and regex_string[lp - 1] == '\\':
                continue

            match_out.append(m)
            positions.append((lp, rp))

        if with_position:
            return [match_out, positions]
        return match_out
    return None


def match_pair(str, left_str, right_str, instr=False):
    """
    match char pair in php file
    """
    stack_count = 1
    cal_count = 0
    start_pos = str.find(left_str)
    end_pos = str.find(left_str) + 1
    str = str[end_pos:]

    if start_pos == -1:
        return None

    ep = 0
    last_char = ''
    string_count = 0
    pass_trans_char = True
    for i, char in enumerate(str):
        if i > 0:
            last_char = str[i-1]

        if string_count > 0:
            string_count -= 1
            continue

        if instr:
            if last_char == '\\' and char in [last_char, right_str] and pass_trans_char:
                pass_trans_char = False
                continue
            else:
                pass_trans_char = True

        # pass string
        if not instr and char == '\'' and string_count == 0:
            pair_pos = match_pair(str[i:], '\'', '\'', instr=True)
            if pair_pos:
                string_count = pair_pos[1] - pair_pos[0]
                continue
        elif not instr and char == '\"' and string_count == 0:
            pair_pos = match_pair(str[i:], '\"', '\"', instr=True)
            if pair_pos:
                string_count = pair_pos[1] - pair_pos[0]
                continue



        if left_str != right_str and char == left_str:
            stack_count += 1
        elif char == right_str:
            stack_count -= 1
            ep = i
        if stack_count == 0:
            break
    if stack_count != 0:
        return None

    end_pos += ep
    return [start_pos, end_pos]


def match_str(str, match_str, out_php=False, without_brackets=False):
    """
    match special str in php code
    """
    laststr = ""
    string_count = 0

    for i, char in enumerate(str):
        if string_count > 0:
            string_count -= 1
            continue
        # check mark
        if laststr + char == match_str[:len(laststr)+1]:
            # match str
            if len(laststr)+1 == len(match_str):
                # match success
                return i - len(laststr)
            else:
                laststr += char
                continue
        else:
            if char == '?':
                pass
            # last str not match
            laststr = ""

        # pass string
        if not out_php and char == '\'' and string_count == 0:
            pair_pos = match_pair(str[i:], '\'', '\'', instr=True)
            if pair_pos:
                string_count = pair_pos[1] - pair_pos[0]
        if not out_php and char == '\"' and string_count == 0:
            pair_pos = match_pair(str[i:], '\"', '\"', instr=True)
            if pair_pos:
                string_count = pair_pos[1] - pair_pos[0]
        if without_brackets and char == '(' and string_count == 0:
            pair_pos = match_pair(str[i:], '(', ')')
            if pair_pos:
                string_count = pair_pos[1] - pair_pos[0]

    return -1

def support_check(code):
    for match, out_str in NOT_SUPPORT_STRING:
        if out_str:
            p = match_str(code, match)
        else:
            p = code.find(match)
        if p>=0:
            return False
    return True

def slice_input_check(code):
    for input_var in INPUT_VARIABLES:
        if input_var in code:
            return True
    return False

def slice_filter(slice):
    for match, out_str in SLICE_FILTER:
        if out_str:
            p = match_str(slice, match)
        else:
            p = slice.find(match)
        if p >= 0:
            return False
    return True

def match_params(regex_string, with_position=False):
    """
    regex string input
    :regex_string: regex match string
    :return:
    """
    reg = REGEX['variable']
    if re.search(reg, regex_string, re.I):
        p = re.compile(reg)
        match = p.findall(regex_string)
        matchs = re.finditer(reg, regex_string)

        match_out = []
        positions = []

        for i, mp in enumerate(matchs):
            m = match[i]
            lp = mp.start()
            rp = mp.end()

            if lp > 0 and regex_string[lp - 1] == '\\':
                continue

            match_out.append(m)
            positions.append((lp, rp))

        if with_position:
            return [match_out, positions]
        return match_out
    return None

def replace_str(code, match_html=False):
    new_code = ""

    bracket_count = 0
    string_count = 0

    for i, char in enumerate(code):
        # pass string
        if string_count == 0 and char == '(' and bracket_count == 0:
            pair_pos = match_pair(code[i:], '(', ')')
            if pair_pos:
                bracket_count = pair_pos[1] - pair_pos[0] + 1

        if string_count == 0 and char == '[' and bracket_count == 0:
            pair_pos = match_pair(code[i:], '[', ']')
            if pair_pos:
                bracket_count = pair_pos[1] - pair_pos[0] + 1

        if bracket_count > 0:
            bracket_count -= 1
            new_code += char
            continue

        # pass string
        if  char in ['"', '\''] and string_count == 0:
            char_rep = char
            pair_pos = match_pair(code[i:], char_rep, char_rep, instr=True)
            if pair_pos:
                s = code[i + pair_pos[0]:i + pair_pos[1] + 1]

                replace_str = False
                if match_html:
                    for key in STRING_REPLACE_ELEMENT:
                        if key in s:
                            replace_str = True
                            break
                else:
                    replace_str = True

                params = match_vars(s)
                if replace_str:
                    if params is None:
                        string_count = pair_pos[1] - pair_pos[0] + 1
                        new_code += '\"\"'
                    elif '$_GET' not in params:
                        string_count = pair_pos[1] - pair_pos[0] + 1
                        new_code += '\"'
                        for p in params:
                            new_code += '{}\" . \"'.format(p)
                        new_code += '\"'
                    else:
                        string_count = pair_pos[1] - pair_pos[0] + 1
                        new_code += '$_GET[\'input\']'
                else:
                    string_count = pair_pos[1] - pair_pos[0] + 1
                    new_code += s

        if string_count > 0:
            string_count -= 1
            continue

        new_code += char

    new_code = replace_pad(new_code)

    if not match_html and '$' not in new_code:
       return code

    return new_code






if __name__=='__main__':
    os.chdir("D:\\USTC_CD\\学习\\我的论文\\LLMforSAST\\code\\LLMforSAST\\")
    str = """    public function delete($id)
    {
        $oGroupToDelete = $this->loadModel($id);
        $sGroupTitle    = $oGroupToDelete->title;

        if ($oGroupToDelete->hasSurveys) {
            Yii::app()->setFlashMessage(gT("You can't delete a group if it's not empty!"), 'error');
            $this->getController()->redirect(isset($_POST['returnUrl']) ? $_POST['returnUrl'] : array('admin/survey/sa/listsurveys '));
        } elseif ($oGroupToDelete->hasChildGroups) {
            Yii::app()->setFlashMessage(gT("You can't delete a group because one or more groups depend on it as parent!"), 'error');
            $this->getController()->redirect(isset($_POST['returnUrl']) ? $_POST['returnUrl'] : array('admin/survey/sa/listsurveys '));
        } else {
            $oGroupToDelete->delete();

            
            if (!isset($_GET['ajax'])) {
                Yii::app()->setFlashMessage(sprintf(gT("The survey group '%s' was deleted."), $sGroupTitle), 'success');
                $this->getController()->redirect(isset($_POST['returnUrl']) ? $_POST['returnUrl'] : array('admin/survey/sa/listsurveys '));
            }
        }
    }

    

"""
    match_pair(str, '{', '}')

