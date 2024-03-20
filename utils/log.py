
import os
import logging
import colorlog
from configs.settings import LOGS_PATH

logger = logging.getLogger('ISHGARD')
logger_console = logging.getLogger('ISHGARDConsoleLog')
log_path = LOGS_PATH


def log(loglevel):
    if os.path.isdir(log_path) is not True:
        os.mkdir(log_path, 0o755)


    log_name = 'main'
    logfile = os.path.join(log_path, log_name + '.log')

    handler = colorlog.StreamHandler()
    handler.setFormatter(
        colorlog.ColoredFormatter(
            fmt='%(log_color)s [%(asctime)s] %(message)s',
            datefmt="%H:%M:%S",
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            },
        )
    )
    f = open(logfile, 'a+')
    handler2 = logging.StreamHandler(f)
    formatter = logging.Formatter(
        "[%(levelname)s][%(threadName)s][%(asctime)s][%(filename)s:%(lineno)d] %(message)s")
    handler2.setFormatter(formatter)
    logger.addHandler(handler2)
    logger.addHandler(handler)

    logger.setLevel(loglevel)



def log_console():
    handler = colorlog.StreamHandler()
    handler.setFormatter(
        colorlog.ColoredFormatter(
            fmt='%(log_color)s %(message)s',
            datefmt="%H:%M:%S",
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'white',
                'WARNING': 'bold_yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            },
        )
    )
    logger_console.addHandler(handler)

    logger_console.setLevel(logging.DEBUG)

log_console()
