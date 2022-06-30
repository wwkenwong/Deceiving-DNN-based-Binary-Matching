import os
import glob 
import pandas as pd 
import ast 

def disassembly(binary,output):
    os.system("objdump -M intel -d "+binary+" -j .text | cut -f3 > "+output)

def disassembly_range(binary,start,stop,output):
    # objdump  -M intel --start-address=0x080493c0 --stop-address=0x080493f2 -d unstriped.out | cut -f3
    os.system('objdump -M intel --start-address='+str(start)+" --stop-address="+str(stop)+" -d "+binary+" | cut -f3 > "+output)

def parse_range_result(input):
    '''
    input the range disassembly
    output the folder contain the code
    '''
    code = []
    fs = open(input).read()
    fs = fs.split("\n")
    header = False 
    for l in fs:
        if len(l)>0 and "file format" not in l and "Disassembly of section" not in l:
            if "<" in l and ">:" in l :
                # function dec
                if header == False:
                    tmp = l.split("<")[-1]
                    tmp = tmp.replace(">","")
                    code.append(tmp)
                    header = True 
            elif "<" in l and ">" in l and ":" not in l :
                # call function 
                tmp = l.split(' <')
                code.append("    "+tmp[0].split(" ")[0]+"   "+tmp[-1].replace(">",""))
            else:
                code.append("    "+l)
    return code 

def to_s(input,output):
    '''
    input filename 
    output filename
    '''
    code = []
    fs = open(input).read()
    fs = fs.split("\n")
    for l in fs:
        if len(l)>0 and "file format" not in l and "Disassembly of section" not in l:
            if "<" in l and ">:" in l :
                tmp = l.split("<")[-1]
                tmp = tmp.replace(">","")
                code.append(tmp)
            elif "<" in l and ">" in l and ":" not in l :
                tmp = l.split(' <')
                code.append("    "+tmp[0].split(" ")[0]+"   "+tmp[-1].replace(">",""))
            else:
                code.append("    "+l)
    ppp = open(output,'w')
    ppp.write("\n".join(code))
    ppp.close()

def routine(binary):
    '''
    Input the path of the binary
    Return the parsed .s for the binary 
    '''
    objdump_cache = binary+".tmp"
    output = binary+".s"
    disassembly(binary,objdump_cache)
    to_s(objdump_cache,output)
    return output

