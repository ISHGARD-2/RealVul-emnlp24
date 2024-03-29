from utils.log import logger
import queue
from phply import phpast as php

class OneSlice:
    """
    param_name: str
    func_call_tree: {}
        callers:""
    """
    def __init__(self):
        pass


class Slicing:
    def __init__(self, params, func_call, target_directory, file_path, code_content, line_number, single_rule):
        # output
        vuln_slices = {}

        # input
        self.params = params
        self.func_call = func_call
        self.target_directory = target_directory
        self.file_path = file_path
        self.code_content = code_content
        self.line_number = int(line_number)
        self.single_rule = single_rule

        # process
        # self.params_class = []
        # for p in self.params:
        #     self.params_class.append(php.Variable(params[0], lineno=line_number))

    def main(self, mode):
        """
        vuln slices collection
        """
        func = self.find_vuln_position()

        slice = self.slice_func(func, mode)

        return slice


    def slice_func(self, func, mode):
        global slice_flag, para_list
        para_list = []
        new_para = self.params
        code_split = func.code.split("\n")

        slice_flag = [0 for i in range(len(code_split))]
        slice = ""

        # control flow
        control_flow = func.control_flow

        while_count = 0
        while new_para:
            if while_count >= 1000:
                logger.error("[ERROR][Slincing] slice_func():  while iter error")
            while_count += 1

            para_list += new_para
            origin_pos = self.origin_postion(func, new_para)
            new_para = self.subnode_scan(func, control_flow, origin_pos, self.line_number)
            control_flow.set_flag()

        for i, s in enumerate(slice_flag):
            if s == 1:
                slice += code_split[i] + "\n"

        # find params of function, trans to further function

        control_flow.clear_flag()

        slice = self.clear_slice(slice)

        return slice

    def clear_slice(self, slice):
        slice_split = slice.split('\n')
        new_slice = ""

        # clear multy '\n'
        for line in slice_split:
            reserve = False
            for char in line:
                if char not in [' ', '\t']:
                    reserve = True
            if reserve:
                new_slice += line+'\n'
        return new_slice



    def subnode_scan(self, func, control_flow, origin_pos, end_line):
        global slice_flag, para_list
        new_param = []
        start_line = control_flow.lineno
        flag = control_flow.flag
        sub_flow = control_flow.subnode

        # start to first node mark
        if not flag:
            for i, line in enumerate(func.code_lineno):
                for lno in range(start_line, sub_flow[0].lineno):
                    if lno == line and line < self.line_number:
                        slice_flag[i] = 1
            # last node to end mark
            if end_line < self.line_number:
                for i, line in enumerate(func.code_lineno):
                    for lno in range(sub_flow[-1].lineno+1, end_line):
                        if lno == line and line < self.line_number:
                            slice_flag[i] = 1
            control_flow.set_flag()

        # subnode mark
        for i, flow in enumerate(sub_flow):
            start_lineno = flow.lineno
            if i + 1 == len(sub_flow):
                # last sub flow
                end_lineno = end_line
            else:
                end_lineno = sub_flow[i + 1].lineno

            for p in origin_pos:
                if p["lineno"] >= start_lineno and p["lineno"] < end_lineno:

                    if flow.subnode.__class__.__name__ == 'list':
                        # mark sub flow
                        params = self.subnode_scan(func, flow, origin_pos, end_lineno)
                        for p in params:
                            if p not in para_list and p not in new_param:
                                new_param.append(p)
                    else:
                        if flow.code == "":
                            code = ""
                            for line in range(start_lineno, end_lineno):
                                for i, func_line in enumerate(func.code_lineno):
                                    if line == func_line and line < self.line_number:
                                        # check new param:
                                        code += func.code_split[i]

                                        # mark slice code lineno:
                                        slice_flag[i] = 1
                            flow.code = code
                        else:
                            code = flow.code
                        params = self.single_rule.main(code)

                        for p in params:
                            if p not in para_list and p not in new_param:
                                new_param.append(p)

        return new_param


    def origin_postion(self, func, para_list):
        origin_postions = []
        code_split = func.code_split

        for i, line in enumerate(code_split):
            for para in para_list:
                if para in line:
                    if i >= len(func.code_lineno):
                        logger.error("[ERROR] params origin_postion(): func code_lineno match error")
                        exit()

                    if func.code_lineno[i] < self.line_number:
                        pos = {"param": para, "lineno": func.code_lineno[i], "code": line}
                        origin_postions.append(pos)

        return origin_postions




    def find_vuln_position(self):
        root_func = None
        find_func = None
        for func in self.func_call.function_list:
            if func.file == self.file_path and self.line_number >= func.start_lineno and self.line_number <= func.end_lineno:
                if func.func_name == 'root' and func.func_type == None:
                    root_func = func
                    continue
                else:
                    find_func = func

        if not find_func:
            if not root_func:
                logger.error("[ERROR][SLICING] root_func not found : {}".format(self.code_content))
                exit()
            find_func = root_func

        return find_func