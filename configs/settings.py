import os

# 全局变量配置
PROJECT_DIRECTORY = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

RESULT_PATH = os.path.join(PROJECT_DIRECTORY, 'result')
if os.path.isdir(RESULT_PATH) is not True:
    os.mkdir(RESULT_PATH)


CORE_PATH = os.path.join(PROJECT_DIRECTORY, 'core')
RULES_PATH = os.path.join(PROJECT_DIRECTORY, 'rules')
CONFIG_PATH = os.path.join(PROJECT_DIRECTORY, 'configs')
TMP_PATH = os.path.join(PROJECT_DIRECTORY, 'tmp')
RESULT_PATH = os.path.join(PROJECT_DIRECTORY, 'result')


LOGS_PATH = os.path.join(RESULT_PATH, 'logs')
if os.path.isdir(LOGS_PATH) is not True:
    os.mkdir(LOGS_PATH)
DEFAULT_LOG_PATH = os.path.join(LOGS_PATH, 'log.txt')

DATA_PATH = os.path.join(PROJECT_DIRECTORY, 'data')
MODEL_PATH = os.path.join(PROJECT_DIRECTORY, 'models')

MAX_SLICE_LENGTH =2000
MAX_FILE_LENGTH = 30000


# LLM PATH
LLM_ENV_PATH = ""

