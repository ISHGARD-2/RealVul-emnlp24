#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: console.py
@time: 2020/8/25 11:32
@desc:

'''
#
# import os
# import sys
# import ast
# import glob
# import time
# import codecs
# import atexit
# import pprint
# import traceback
# import logging
# from functools import wraps
# from prettytable import PrettyTable
#
# from django.db.models import Q, QuerySet
# from django.db.models.aggregates import Max
#
# from utils.log import logger, logger_console, log, log_add
# from utils import readlineng as readline
# from utils.utils import get_mainstr_from_filename, file_output_format, show_context
# from utils.status import get_scan_id
#
# from Kunlun_M.settings import HISTORY_FILE_PATH, MAX_HISTORY_LENGTH
# from Kunlun_M.settings import RULES_PATH, PROJECT_DIRECTORY, LOGS_PATH
# from Kunlun_M.const import VUL_LEVEL
#
# from core.__version__ import __introduction__
# from core import cli
#
# from web.index.models import ScanTask, ScanResultTask, Rules, Tampers, NewEvilFunc
# from web.index.models import get_resultflow_class, get_dataflow_class
# from web.index.models import get_and_check_scantask_project_id, get_and_check_scanresult, check_and_new_project_id


# def readline_available():
#     """
#     Check if the readline is available. By default
#     it is not in Python default installation on Windows
#     """
#
#     return readline._readline is not None
#
#
#
# def clear_history():
#     if not readline_available():
#         return
#
#     readline.clear_history()
#
#
# def save_history():
#     if not readline_available():
#         return
#
#     history_path = HISTORY_FILE_PATH
#
#     try:
#         with open(history_path, "w+"):
#             pass
#     except Exception:
#         pass
#
#     readline.set_history_length(MAX_HISTORY_LENGTH)
#     try:
#         readline.write_history_file(history_path)
#     except IOError as msg:
#         warn_msg = "there was a problem writing the history file '{0}' ({1})".format(history_path, msg)
#         logger.warn(warn_msg)


# def load_history():
#     if not readline_available():
#         return
#
#     clear_history()
#
#     history_path = HISTORY_FILE_PATH
#
#     if os.path.exists(history_path):
#         try:
#             readline.read_history_file(history_path)
#         except IOError as msg:
#             warn_msg = "there was a problem loading the history file '{0}' ({1})".format(history_path, msg)
#             logger.warn(warn_msg)


# def auto_completion(completion=None, console=None):
#     if not readline_available():
#         return
#
#     readline.set_completer_delims(" ")
#     readline.set_completer(console)
#     readline.parse_and_bind("tab: complete")
#
#     load_history()
#     atexit.register(save_history)


# def stop_after(space_number):
#     """ Decorator that determines when to stop tab-completion
#     Decorator that tells command specific complete function
#     (ex. "complete_use") when to stop tab-completion.
#     Decorator counts number of spaces (' ') in line in order
#     to determine when to stop.
#         ex. "use exploits/dlink/specific_module " -> stop complete after 2 spaces
#         "set rhost " -> stop completing after 2 spaces
#         "run " -> stop after 1 space
#     :param space_number: number of spaces (' ') after which tab-completion should stop
#     :return:
#     """
#
#     def _outer_wrapper(wrapped_function):
#         @wraps(wrapped_function)
#         def _wrapper(self, *args, **kwargs):
#             try:
#                 if args[1].count(" ") == space_number:
#                     return []
#             except Exception as err:
#                 logger.error(err)
#             return wrapped_function(self, *args, **kwargs)
#
#         return _wrapper
#
#     return _outer_wrapper


# class BaseInterpreter(object):
#     global_help = ""
#
#     def __init__(self):
#         self.setup()
#         self.banner = ""
#         self.complete = None
#         self.subcommand_list = []
#
#     def setup(self):
#         """ Initialization of third-party libraries
#         Setting interpreter history.
#         Setting appropriate completer function.
#         :return:
#         """
#         auto_completion(completion=4, console=self.complete)
#
#     def parse_line(self, line):
#         """ Split line into command and argument.
#         :param line: line to parse
#         :return: (command, argument)
#         """
#         command, _, arg = line.strip().partition(" ")
#         return command, arg.strip()
#
#     @property
#     def prompt(self):
#         """ Returns prompt string """
#         return ">>>"
#
#     def get_command_handler(self, command):
#         """ Parsing command and returning appropriate handler.
#         :param command: command
#         :return: command_handler
#         """
#         try:
#             command_handler = getattr(self, "command_{}".format(command))
#         except AttributeError:
#             logger.error("Unknown command: '{}'".format(command))
#             return False
#
#         return command_handler
#
#     def start(self):
#         """ Routersploit main entry point. Starting interpreter loop. """
#
#         logger_console.info(self.global_help)
#         while True:
#             try:
#                 command, args = self.parse_line(input(self.prompt))
#                 command = command.lower()
#                 if not command:
#                     continue
#                 command_handler = self.get_command_handler(command)
#                 command_handler(args)
#             except EOFError:
#                 logger.info("KunLun-M Console mode stopped")
#                 break
#             except KeyboardInterrupt:
#                 logger.info("Console Exit")
#                 break
#             except:
#                 logger.error("[Console] {}".format(traceback.format_exc()))
#
#     def complete(self, text, state):
#         """Return the next possible completion for 'text'.
#         If a command has not been entered, then complete against command list.
#         Otherwise try to call complete_<command> to get list of completions.
#         """
#         if state == 0:
#             original_line = readline.get_line_buffer()
#             line = original_line.lstrip()
#             stripped = len(original_line) - len(line)
#             start_index = readline.get_begidx() - stripped
#             end_index = readline.get_endidx() - stripped
#
#             if start_index > 0:
#                 cmd, args = self.parse_line(line)
#                 if cmd == "":
#                     complete_function = self.default_completer
#                 else:
#                     try:
#                         complete_function = getattr(self, "complete_" + cmd)
#                     except AttributeError:
#                         complete_function = self.default_completer
#             else:
#                 complete_function = self.raw_command_completer
#
#             self.completion_matches = complete_function(text, line, start_index, end_index)
#         try:
#             return self.completion_matches[state]
#         except IndexError:
#             return None
#
#     def commands(self, *ignored):
#         """ Returns full list of interpreter commands.
#         :param ignored:
#         :return: full list of interpreter commands
#         """
#         command_list = [command.rsplit("_").pop() for command in dir(self) if command.startswith("command_")]
#
#         # command_list.extend(self.subcommand_list)
#         return command_list
#
#     def raw_command_completer(self, text, line, start_index, end_index):
#         """ Complete command w/o any argument """
#         return [command for command in self.suggested_commands() if command.startswith(text)]
#
#     def default_completer(self, *ignored):
#         return []
#
#     def suggested_commands(self):
#         """ Entry point for intelligent tab completion.
#         Overwrite this method to suggest suitable commands.
#         :return: list of suitable commands
#         """
#         return self.commands()



