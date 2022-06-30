#!/usr/bin/env python
# -*- coding: utf-8 -*-

import r2pipe
import json
import pandas
import glob 
import time
import pickle
import run_objdump 

'''
 8049446:	66 90                	xchg   %ax,%ax
 8049487:	66 90                	xchg   %ax,%ax
 8049489:	66 90                	xchg   %ax,%ax
 804948b:	66 90                	xchg   %ax,%ax
 804948d:	66 90                	xchg   %ax,%ax
'''

def gen_block(input,cache_file):
    r2=r2pipe.open(input)
    r2.cmd("aaaaaa")
    addr_range_json =json.loads(r2.cmd("afllj"))
    code_list = []
    for i in range(len(addr_range_json)):
        upperbound = str(addr_range_json[i]['maxbound'])
        lowerbound = str(addr_range_json[i]['minbound'])
        run_objdump.disassembly_range(input,lowerbound,upperbound,cache_file)
        code = run_objdump.parse_range_result(cache_file)
        code_list+=code 
    return code_list 


def gen_cfg(input,output,seed=False):
    r2=r2pipe.open(input)
    r2.cmd("aaaaaa")
    out_s = ""
    #get file type
    addr_range_json =json.loads(r2.cmd("afllj"))
    addr_size_mapping = {}
    addr_name_mapping = {}

    for i in range(len(addr_range_json)):
        #offset': 134558685, 'name': 'loc.S_0x80532D0', 'size': 41, '
        addr = hex(addr_range_json[i]['offset'])
        name = addr_range_json[i]['name']
        size = addr_range_json[i]['size']
        addr_size_mapping[str(addr)] = size
        addr_name_mapping[str(addr)] = name
    
    # we will assume the input path is the absolute path 
    path = input.split("/")
    path = "/".join(path[:-1])
    mapping_dict = None 
    return_name = []
    if seed == False:
        '''
        return [new_symbol_to_new_addr,new_addr_to_new_symbol,
                new_symbol_to_old_addr,old_addr_to_new_symbol]
        '''
        mapping_dict = pickle.load(open(path+'/mapping_dict.pickle','rb'))
    for x in addr_size_mapping.keys():
        _ = r2.cmd('s '+str(x))
        _ = r2.cmd('s '+str(x))
        size = addr_size_mapping[str(x)]
        name = addr_name_mapping[str(x)]
        sam_json =json.loads(r2.cmd('pDj '+str(size)))
        code_list = []
        query_key = str(x).split("x")[-1]
        query_key = "0x0"+query_key
        if seed == False:
            if query_key in mapping_dict[1].keys()  :
                name = mapping_dict[1][query_key]
            else:
                if "." in name:
                    name = name.split(".")[-1]
                    testing_flag = False 
                    try:
                        aaaaa = int(name,16)
                        testing_flag = True 
                    except:
                        pass 
                    if testing_flag :
                        name = "S_"+name
        else:
            if "." in name:
                name = name.split(".")[-1]
                testing_flag = False 
                try:
                    aaaaa = int(name,16)
                    testing_flag = True 
                except:
                    pass 
                if testing_flag :
                    name = "S_"+name
        for i in range(len(sam_json)):
            if 'opcode' in sam_json[i].keys():
                code = sam_json[i]['opcode']
                if "nop" in code:
                    if str(sam_json[i]['bytes']) == "6690" or str(sam_json[i]['bytes'])=="9960":
                        code = "xchg ax,ax"
                # replace hell 
                code = code.replace(", ",",")
                code = code.replace(" + ","+")
                code = code.replace(" - ","-")
                code = code.replace("dword","DWORD PTR")
                code = code.replace(" ","    ",1)
                code_list.append("    "+code)
        '''
        _start:
            xor    ebp,ebp
            pop    esi
            mov    ecx,esp
            and    esp,0xfffffff0
            push   eax
        '''
        code_tmp  = name+":\n"
        code_tmp += "\n".join(code_list)+"\n"
        out_s+=code_tmp
        return_name.append(name)
    fs = open(output,'w')
    fs.write(out_s)
    fs.close()
    return return_name

def routine(binary,seed):
    '''
    Input the path of the binary
    Return the parsed .s for the binary 
    '''
    objdump_cache = binary+".tmp"
    output = binary+"_r2.s"
    return_name = gen_cfg(binary,output,seed)
    return return_name #output





    
    
