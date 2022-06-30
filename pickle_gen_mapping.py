import pandas as pd 
import pickle 
import copy 
import ast 
import glob 
import os 

def gen_seed(s):
    '''
    return [new_symbol_to_new_addr,new_addr_to_new_symbol,\
      new_symbol_to_seed_symbol,seed_symbol_to_new_symbol,\
      new_symbol_to_old_addr,old_addr_to_new_symbol]

    '''
    sym_to_addr = {}
    sym_to_cur_sym = {}
    for symbol in s[3].keys():
        addr = s[0][s[3][symbol]].upper().replace('X','x').replace('0x0','0x')
        sym_to_addr[symbol] = addr
        sym_to_cur_sym[symbol] = s[3][symbol]
    return sym_to_addr,sym_to_cur_sym

def gen_mutated(sym_to_addr,sym_to_cur_sym,failure_seed,s):
    failure = []
    for symbol in sym_to_addr.keys():
        old_addr = sym_to_addr[symbol]
        try:
            new_symbol = s[3][old_addr]
            addr = s[0][new_symbol].upper().replace('X','x').replace('0x0','0x')
            sym_to_addr[symbol] = addr
            sym_to_cur_sym[symbol] = new_symbol
        except:
            failure.append(symbol)
    for symbol in failure:
        tmp = sym_to_addr.pop(symbol, None)
        tmp = sym_to_cur_sym.pop(symbol, None)
    failure += failure_seed
    return sym_to_addr,sym_to_cur_sym,failure


def run_pickle(folder,step_size = None):
    if step_size == None:
        df = pd.read_csv(folder+'/record.csv')
    else:
        df = pd.read_csv(folder+'/record_step_'+str(step_size)+'.csv')

    chk = sorted(list(set(df['generation'])))

    df['mapping_addr'] = 1
    df['mapping_symm'] = 1
    df['failure'] = 1

    for gen in chk:
        disappeared = copy.copy(df[df['generation']==gen])
        damaged_index = list(disappeared.index)
        for i in range(len(disappeared)):
            path = disappeared.iloc[i]['output']
            exe = "/".join(path.split("/")[:-1])
            #exe = exe.replace("/container/","/container_cat/")
            s = pickle.load(open(exe+'/mapping_dict.pickle','rb'))
            if gen==1:
                sym_to_addr = {}
                sym_to_cur_sym = {}
                for symbol in s[3].keys():
                    addr = s[0][s[3][symbol]].upper().replace('X','x').replace('0x0','0x')
                    sym_to_addr[symbol] = addr
                    sym_to_cur_sym[symbol] = s[3][symbol]
                df['mapping_addr'].iloc[damaged_index[i]] = str(sym_to_addr)
                df['mapping_symm'].iloc[damaged_index[i]] = str(sym_to_cur_sym)
                df['failure'].iloc[damaged_index[i]] = str([])
            else:
                get_seed = disappeared.iloc[i]['seed']
                sym_to_addr = ast.literal_eval(df[df['output']==get_seed]['mapping_addr'].values[0])
                sym_to_cur_sym = ast.literal_eval(df[df['output']==get_seed]['mapping_symm'].values[0])
                failure_seed = ast.literal_eval(df[df['output']==get_seed]['failure'].values[0])
                failure = []
                for symbol in sym_to_addr.keys():
                    old_addr = sym_to_addr[symbol]
                    try:
                        new_symbol = s[3][old_addr]
                        addr = s[0][new_symbol].upper().replace('X','x').replace('0x0','0x')
                        sym_to_addr[symbol] = addr
                        sym_to_cur_sym[symbol] = new_symbol
                    except:
                        failure.append(symbol)
                for symbol in failure:
                    tmp = sym_to_addr.pop(symbol, None)
                    tmp = sym_to_cur_sym.pop(symbol, None)
                failure += failure_seed
                df['mapping_addr'].iloc[damaged_index[i]] = str(sym_to_addr)
                df['mapping_symm'].iloc[damaged_index[i]] = str(sym_to_cur_sym)
                df['failure'].iloc[damaged_index[i]] = str(failure)
    if step_size == None:
        df.to_csv(folder+'/record_pickle.csv',index=False)
    else:
        df.to_csv(folder+'/record_pickle_'+str(step_size)+'.csv',index=False)


if __name__ == "__main__":
    ssssss = glob.glob("*")
    fail_list = []
    ok = []
    for gg in ssssss:
        if os.path.exists(gg+"/record.csv") == True and os.path.exists(gg+"/record_pickle.csv") == False:
            try:
                run_pickle(gg)
                ok.append(gg)
            except:
                fail_list.append(gg)

    print("[+] Failed : ")
    print(fail_list)

    print("[+] OK : ")
    for xxxx in ok:
        print(xxxx)
