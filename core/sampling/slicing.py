from configs.settings import MAX_SLICE_LENGTH
from core.sampling.pretreatment import get_var_by_ast
from utils.file import clear_slice
from utils.log import logger
import queue
from phply import phpast as php
from configs.const import INPUT_VARIABLES
from utils.my_utils import slice_filter, slice_input_check, match_params, slilce_check_syntax


def get_slice_from_flow(flow, code_slice_flag, isroot=False):
    if not isroot and not flow.flag:
        return

    if not isroot:
        for self_code_line in flow.self_code_position:
            for i in range(self_code_line['position'][0], self_code_line['position'][1]):
                code_slice_flag[i] = 1

    if flow.name != 'others':
        for subflow in flow.subnode:
            get_slice_from_flow(subflow, code_slice_flag)

    if isroot:
        code_slice = ''
        base = flow.all_code_position[0]['position'][0]
        for i, char in enumerate(flow.code):
            if code_slice_flag[i + base]:
                code_slice += char

        return code_slice
    return

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
        if not func:
            return None


        slice = self.slice_func(func, mode)

        if slice is None or self.code_content not in slice:
            logger.debug('[SLICE] slice failed\n')
            return None
        if len(slice) > MAX_SLICE_LENGTH:
            logger.debug('[SLICE] slice too long\n')
            return None
        if not slice_filter(slice):
            logger.debug('[SLICE] slice not support\n')
            return None
        if not slice_input_check(slice):
            logger.debug('[SLICE] no input in slice\n')
            return None
        if not slilce_check_syntax(slice):
            return None

        return slice

    def slice_func(self, func, mode):
        global code_slice_flag, para_list
        para_list = []
        new_para = self.params

        isfunc = False
        if func.func_name != 'root' and func.func_type != None:
            isfunc = True

        # control flow
        if not hasattr(func, 'control_flow'):
            return None

        control_flow = func.control_flow
        code_slice_flag = [0 for i in range(control_flow.all_code_position[-1]['position'][1])]

        while_count = 0
        while new_para:
            if while_count >= 1000:
                logger.error("[ERROR][Slincing] slice_func():  while iter error")
            while_count += 1

            for p in new_para:
                if p['name'] not in INPUT_VARIABLES:
                    para_list.append(p)

            origin_pos = self.origin_postion(func, new_para)

            new_para = self.subnode_scan(func, control_flow, origin_pos, isfunc=isfunc)
            pass

        code_slice = get_slice_from_flow(control_flow, code_slice_flag, True)

        slice_pre = "<?php\n"
        # find params of function, trans to further function
        if isfunc:
            control_params = []
            func_params = func.node_ast.params
            for func_p in func_params:
                func_p_name = func_p.name
                for par in para_list:
                    par = par['name']
                    if par == func_p_name:
                        control_params.append(func_p_name)
                        break
            slice_pre += "// controlable parameters: \n"
            for i, var in enumerate(control_params):
                slice_pre += var+" = $_GET['input"+str(i)+"'];\n"
            slice_pre += '\n'
        # ...

        control_flow.clear_flag()

        slice_pre += "// php code: \n"
        code_slice = slice_pre + clear_slice(code_slice)

        return code_slice




    def subnode_scan(self, func, control_flow, origin_pos, isfunc=False):
        """
        isfunc: slice from a function
        """
        global para_list
        new_param = []
        sub_flow = control_flow.subnode

        # self_check
        all_sp = control_flow.all_code_position[0]['position'][0]
        all_ep = control_flow.all_code_position[-1]['position'][1]

        for var in origin_pos:
            var_sp = var['position'][0]
            var_ep = var['position'][1]
            var_last = var['last']
            if all_sp <= var_sp and var_ep <= all_ep:
                if not var_last and control_flow.name == 'others' and \
                        not self.data_flow_analysis(control_flow.subnode, para_list, control_flow.self_code):
                    continue
                # set_flag
                control_flow.set_flag()
                if var_last and control_flow.name == 'others':
                    control_flow.set_last_flow()
                break

        if control_flow.last_flow:
            return []

        # new params
        if control_flow.flag and not isfunc:
            params = match_params(control_flow.self_code)
            if params:
                for p in params:
                    append = True
                    for new_p in new_param:
                        if new_p['name'] == p:
                            append = False
                            break
                    if append:
                        for tmp_p in para_list:
                            if tmp_p['name'] == p:
                                append = False
                                break

                    if append and p not in INPUT_VARIABLES:
                        new_p = {'name':p, 'lineno':control_flow.lineno}
                        new_param.append(new_p)

        # subnode mark
        if control_flow.name != 'others':
            for i, flow in enumerate(sub_flow):
                if flow.lineno <= self.line_number:
                    params = self.subnode_scan(func, flow, origin_pos)
                    for p in params:
                        append = True
                        for new_p in new_param:
                            if new_p['name'] == p['name']:
                                append = False
                                break
                        if append:
                            for tmp_p in para_list:
                                if tmp_p['name'] == p['name']:
                                    append = False
                                    break

                        if append and p['name'] not in INPUT_VARIABLES:
                            new_param.append(p)

            clear_flag = True
            for i, flow in enumerate(sub_flow):
                if flow.flag == 1:
                    clear_flag = False
                    break

            if clear_flag:
                control_flow.set_flag0()
                new_param = []

        return new_param

    def data_flow_analysis(self, node, params, code):
        vars = []
        if isinstance(node, php.Assignment) or isinstance(node, php.AssignOp):
            tvars = match_params(code[:code.find('=')])
            if tvars:
                for v in tvars:
                    vars.append(v)
        elif isinstance(node, php.ListAssignment):
            logger.debug("[DEBUG] slicing.data_flow_analysis()")
            for n in node.nodes:
                var = get_var_by_ast(n)
                vars.append(var)


        elif isinstance(node, php.MethodCall):
            return True

        for v in vars:
            for p in params:
                if p['name'] == v:
                    return True
        return False

    def origin_postion(self, func, para_list):
        origin_postions = []
        code_line = func.code_line

        for i, line in enumerate(code_line):
            code = line['code']
            position = line['position']
            lineno = line['lineno']
            vars = match_params(code, with_position=True)
            if vars:
                line_vars, positions = vars[0], vars[1]
                for param in para_list:
                    para = param['name']
                    para_lineno = param['lineno']
                    para_pos = []

                    for var, pos in zip(line_vars, positions):

                        if var == para:
                            if i >= len(func.code_line):
                                logger.error("[ERROR] params origin_postion(): func code_lineno match error")


                            if lineno <= para_lineno:
                                last = False
                                if lineno == self.line_number:
                                    last = True

                                p = {"param": para,
                                     "lineno": func.code_line[i],
                                     "position": (position[0] + pos[0], position[0] + pos[1]),
                                     "code": code,
                                     'last':last}

                                para_pos.append(p)
                    if param in INPUT_VARIABLES:
                        para_pos = [para_pos[-1]]
                    origin_postions += para_pos

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
                logger.info("[INFO][SLICING] root_func not found : {}".format(self.code_content))
                return None
            find_func = root_func

        return find_func





