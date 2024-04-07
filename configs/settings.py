import os

# 全局变量配置
PROJECT_DIRECTORY = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

RESULT_PATH = os.path.join(PROJECT_DIRECTORY, 'result')
if os.path.isdir(RESULT_PATH) is not True:
    os.mkdir(RESULT_PATH)
DEFAULT_RESULT_PATH = RESULT_PATH

CORE_PATH = os.path.join(PROJECT_DIRECTORY, 'core')
RULES_PATH = os.path.join(PROJECT_DIRECTORY, 'rules')
CONFIG_PATH = os.path.join(PROJECT_DIRECTORY, 'config')
LOGS_PATH = os.path.join(PROJECT_DIRECTORY, 'logs')
if os.path.isdir(LOGS_PATH) is not True:
    os.mkdir(LOGS_PATH)
DEFAULT_RESULT_PATH = LOGS_PATH
DATA_PATH = os.path.join(PROJECT_DIRECTORY, 'data')
MAX_SLICE_LENGTH = 2000
MAX_FILE_LENGTH = 30000
