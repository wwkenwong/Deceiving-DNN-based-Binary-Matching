import os
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"

import subprocess
from subprocess import check_output
import random 
import string
import datetime
import random 
import pandas as pd 
import hashlib
import glob 
import r2_cfg
import run_objdump
import pickle 
from pickle_gen_mapping import * 
import ast 
from argparse import ArgumentParser, RawTextHelpFormatter
import time 
import json 
# items for ncc 
import task_utils
import copy 
import rgx_utils as rgx

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np 

from train_task_classifyapp_patched_embedding_testing import * 

def open_path(path):
    if not os.path.exists(path):
        os.makedirs(path)

def cosine_similarity(v1, v2):
    return np.dot(v1, v2) / (np.linalg.norm(v1) * np.linalg.norm(v2))

SURVIVIE = 2 
TARGET = 0.40 
mutant = {}
tmp_bin_name = "/tmp/output_bin_"+str(random.randint(0,300000))
tmp_train_folder = "/tmp/ir_train_"+str(random.randint(0,300000))+"/"
seq_train_folder = tmp_train_folder.replace("ir","seq")
decompiler = "./retdec_run/retdec/install/bin/retdec-decompiler"

global seed_vector
seed_vector = None 

embeddings = task_utils.get_embeddings()
vocab_size = embeddings.shape[0]

open_path(tmp_train_folder)
open_path(seq_train_folder)
# embedding_matrix_normalized = tf.nn.l2_normalize(embeddings, axis=1)
# vocabulary_size, embedding_dimension = embedding_matrix_normalized.shape


folder_vocabulary = task_utils.vocabulary_dir
dictionary_pickle = os.path.join(folder_vocabulary, 'dic_pickle')
with open(dictionary_pickle, 'rb') as f:
    dictionary = pickle.load(f)

unk_index = dictionary[rgx.unknown_token]
del dictionary


global st_time 


def generate(seed,save_bin_folder,mode,F_mode,function_name,tmp_bin = tmp_bin_name,iter=1):
    p = ['python2','./uroboros_automate-func-name.py',seed,'-i',str(iter),'-o',tmp_bin,'-d',str(mode),'-m',F_mode,'-f',save_bin_folder+"/tmp/","--function",function_name]
    s = check_output(p)
    h = hashlib.md5(open(tmp_bin, 'rb').read()).hexdigest()
    ctr = 1 
    if not os.path.exists(save_bin_folder+"/"+str(h)+"_container/"):
        os.system("mv "+save_bin_folder+"/tmp/"+" "+save_bin_folder+"/"+str(h)+"_container/")
        os.system("mv "+tmp_bin+" "+save_bin_folder+"/"+str(h)+"_container/"+str(h))
        return save_bin_folder+"/"+str(h)+"_container/"+str(h)
    else:
        saved_flag = False 
        while saved_flag == False:
            h_tmp = str(h)+"_ctr"+str(ctr)
            if not os.path.exists(save_bin_folder+"/"+str(h_tmp)+"_container/"):
                os.system("mv "+save_bin_folder+"/tmp/"+" "+save_bin_folder+"/"+str(h_tmp)+"_container/")
                os.system("mv "+tmp_bin+" "+save_bin_folder+"/"+str(h_tmp)+"_container/"+str(h_tmp))
                saved_flag == True 
                return save_bin_folder+"/"+str(h_tmp)+"_container/"+str(h_tmp)
            else:
                ctr += 1 


def ret_top5(gen_1,score_list,grad_list,SAVE_PATH,STEP_SIZE,metric = 'grad_list',IDAFLAG=False):
    df_tmp = pd.DataFrame()
    df_tmp['gen_1'] = gen_1
    df_tmp['score_list'] = score_list
    df_tmp['grad_list'] = grad_list
    if metric == 'score_list':
        df_tmp = df_tmp.sort_values(metric,ascending=True)
    else:
        df_tmp = df_tmp.sort_values(metric,ascending=False)
    if IDAFLAG:
        df_tmp = df_tmp.dropna()
        df_tmp = df_tmp[df_tmp['grad_list']!=501]
    if os.path.exists(SAVE_PATH+'/big_log_'+str(STEP_SIZE)+'.csv'):
        logging_df = pd.read_csv(SAVE_PATH+'/big_log_'+str(STEP_SIZE)+'.csv')
        logging_df = logging_df.append(df_tmp)
        logging_df.to_csv(SAVE_PATH+'/big_log_'+str(STEP_SIZE)+'.csv', index=False )
    else:
        df_tmp.to_csv(SAVE_PATH+'/big_log_'+str(STEP_SIZE)+'.csv', index=False )
    gen_1 = df_tmp['gen_1'].values[:SURVIVIE]
    score_list = df_tmp['score_list'].values[:SURVIVIE]
    grad_list = df_tmp['grad_list'].values[:SURVIVIE]
    print(df_tmp)
    df_tmp.to_csv(SAVE_PATH+'/log_'+str(STEP_SIZE)+'.csv')
    return gen_1,score_list,grad_list

def call_retdec(binary,check_addr,function_name,SEED_MODE =False):
    #binary,check_addr,function_name
    addr = None 
    try:
        if not SEED_MODE:
            addr = check_addr[function_name]
    except:
        return None , None  
    if not SEED_MODE:
        binary_ = "/".join(binary.split("/")[:-1])+"/unstriped.out"
        function_name = addr
    else:
        binary_ = binary 
    p = [decompiler,binary_,"-s","-k","--select-functions",function_name]
    _ = os.system("rm -rf "+tmp_train_folder)
    _ = os.system("rm -rf "+seq_train_folder)
    open_path(tmp_train_folder)
    open_path(seq_train_folder)
    try:
        st = os.system(" ".join(p))
    except:
        return None , None  
    if st==0 :
        #hack a bit to remove uselistorder
        tt = open(binary_+".ll").read()
        tt = tt.split("\n")
        tt_tmp = []
        for gg in tt:
            if "uselistorder" not in gg \
                and "ptrtoint" not in gg \
                and " = local_unnamed_addr " not in gg \
                and not gg.startswith("@global_var_") \
                and not gg.startswith("source_filename") \
                and not gg.startswith("target datalayout =")  \
                and not gg.startswith("%_IO_FILE")  \
                and not gg.startswith("%_TYPEDEF")  \
                and "= internal constant" not in gg \
                and " = !{i64" not in gg \
                and "= external global" not in gg :
                tt_tmp.append(gg)
        tt = tt_tmp
        qq = open(binary_+".ll",'w')
        qq.write("\n".join(tt))
        qq.close()
        os.system("cp "+binary_+".ll "+tmp_train_folder)
        # this step will gen .rec on the seq_train_folder folder  
        task_utils.llvm_ir_to_trainable(tmp_train_folder)
        X_train = glob.glob(seq_train_folder+"/*")
        X_train = [f for f in X_train if f[-4:] == '.rec']
        if len(X_train)==0:
            exit()
        # now make a copy of torch embeding 
        weights = torch.from_numpy(copy.copy(embeddings)).type(torch.FloatTensor)
        weights = F.normalize(weights, p=2, dim=1)
        embed = nn.Embedding(vocab_size, 200)
        embed.weight = torch.nn.Parameter(weights)
        embed_inuse = copy.copy(embed)

        X_seq_train, maxlen_train, seq_len_train = encode_srcs(X_train, 'training', copy.copy(unk_index))
        X_seq_train = pad_src(X_seq_train, maxlen_train, copy.copy(unk_index))

        X = torch.from_numpy(X_seq_train).type(torch.LongTensor)
        vec = embed_inuse(X)
        vec.mean().backward()
        grad = float(embed_inuse.weight.grad.norm())
        # TF pipeline 
        # gen_test = EmbeddingPredictionSequence(64, X_seq_train, embedding_matrix_normalized, seq_len_train)
        # print(gen_test)

        # if it is the seed corpus, we are done here  :)
        if SEED_MODE:
            return vec,grad
        else :
            global seed_vector 
            flat_seed = copy.copy(seed_vector)
            flat_seed = flat_seed.detach().numpy()
            flat_seed = flat_seed.flatten() 
            flat_new = vec.detach().numpy()
            flat_new = flat_new.flatten() 
            abs_diff = abs(len(flat_new)-len(flat_seed))
            flat_seed = flat_seed.tolist()
            flat_new = flat_new.tolist()
            if len(flat_new)>len(flat_seed):
                for xxx in range(0,abs_diff):
                    flat_seed.append(0)
            else:
                for xxx in range(0,abs_diff):
                    flat_new.append(0)
            flat_new = np.array(flat_new)
            flat_seed= np.array(flat_seed)
            sim = cosine_similarity(flat_new,flat_seed)
            return sim,grad
    else:
        return None , None 


def wrapper(MAIN_SEED,SAVE_PATH,function_name):
    #seed_corpus = [MAIN_SEED]
    seed_corpus = []

    seed_of_output = []
    output = []
    generation = []
    operand = []

    open_path(SAVE_PATH)

    # no use 0 , 4, 10 
    diversification = [1,2,3,4,5,7,8,9,10,11]

    if os.path.isfile(SAVE_PATH+"/bypassed.log") == True:
        print("Done :)")
        exit() 

    if os.path.isfile(MAIN_SEED+".s") == False:
        seed_s = run_objdump.routine(MAIN_SEED)

    # # train seed's model 
    # if True: #os.path.isfile(MAIN_SEED+".pickle"):
    #     # we gen the matching model first 
    #     #model_original = pickle.load(open(MAIN_SEED+".pickle",'rb'))
    #     model_original = pickle.load(open("big.pickle",'rb'))
    # else:
    #     model_original = train_pickle(MAIN_SEED+".s")
    #     with open(MAIN_SEED+".pickle", 'wb') as handle:
    #         pickle.dump(model_original, handle, protocol=pickle.HIGHEST_PROTOCOL)

    # every time gen 10 
    # 
    def main(function_name,NUM_GEN):
        generation_dict = {}
        operand_dict = {}
        gen_1 = []
        global seed_vector
        seed_vector,start_grad = call_retdec(MAIN_SEED,None,function_name,SEED_MODE = True)
        for ctr in range(0,1):
            got_sample = False 
            retry_ctr = 0 
            while got_sample == False and retry_ctr <5:
                i = random.choice(diversification)
                try:
                    hash_ = generate(MAIN_SEED,SAVE_PATH,i,'original',function_name=function_name,iter=1)
                    if len(generation_dict.keys())==0:
                        generation_dict[MAIN_SEED] = 0
                        generation_dict[hash_] = 1
                        operand_dict[MAIN_SEED] = []
                        operand_dict[hash_] = [i]
                        cur_gen = 1
                        cur_op = str(operand_dict[hash_])
                    elif MAIN_SEED in generation_dict.keys():
                        old_gen = generation_dict[MAIN_SEED] +1
                        generation_dict[hash_] = old_gen
                        cur_gen = old_gen
                        old_operand = operand_dict[MAIN_SEED].copy()
                        old_operand.append(i)
                        operand_dict[hash_] = old_operand
                        cur_op = str(operand_dict[hash_])
                    seed_of_output.append(MAIN_SEED)
                    output.append(hash_)
                    generation.append(cur_gen)
                    operand.append(cur_op)
                    seed_corpus.append(hash_)
                    gen_1.append(hash_)
                    got_sample = True 
                except:
                    print("[+] Failed")
                    retry_ctr+=1 
                    pass 
            if retry_ctr == 5 :
                fs = open(SAVE_PATH+"/fail.log",'w')
                fs.write(str(i))
                fs.close()
                exit()

        df = pd.DataFrame()
        df['seed'] = seed_of_output
        df['output'] = output
        df['generation'] = generation
        df['operand'] = operand
        df.to_csv(SAVE_PATH+'/record_step_'+str(NUM_GEN)+'.csv')
        run_pickle(SAVE_PATH,step_size =NUM_GEN)

        print("[+] Finished initial corpus generation ")

        bypassed = False 
        bypassed_sample = ""
        score_list = []
        grad_list = []
        xx = pd.read_csv(SAVE_PATH+'/record_pickle_'+str(NUM_GEN)+'.csv')
        for items in gen_1:
            #get id 
            id_ = xx[xx['output']==items].index.values[0]
            checkdict = ast.literal_eval(xx['mapping_symm'].iloc[id_])
            check_addr = ast.literal_eval(xx['mapping_addr'].iloc[id_])
            score,grad = call_retdec(items,checkdict,function_name)
            print("score ",score," rank ",grad)
            #score,grad = run_one(MAIN_SEED,items,model_original,checkdict,function_name)
            if grad!=None :
                grad = abs(grad)
            # run checker 
            # if works, quit 
            #if score <TARGET:
            #    bypassed = True 
            #    bypassed_sample = items
                #break 
                #return seed_of_output,output,generation,operand,bypassed_sample 
            #if score!= None :
            score_list.append(score)
            grad_list.append(grad)
        #ret_top5(gen_1,score_list,grad_list,SAVE_PATH,NUM_GEN,metric='score_list',IDAFLAG=True)

        if bypassed == False :
            gen_1,score_list,grad_list = ret_top5(gen_1,score_list,grad_list,SAVE_PATH,NUM_GEN,metric='score_list',IDAFLAG=True)
            gen_1= gen_1.tolist()
            score_list= score_list.tolist()
            grad_list = grad_list.tolist()

            # gen_1_exit = [gen_1[1]]
            # score_list_exit = [score_list[1]]
            # grad_list_exit = [grad_list[1]]

            gen_1 = [gen_1[0]]
            score_list = [score_list[0]]
            grad_list = [grad_list[0]]

        tmp_gen = []
        if bypassed == False :
            for i in range(0,NUM_GEN):
                cur_gen = 0
                cur_op = ""
                pass_flag = False 
                fail_ctr = 0
                # max items 
                gen_max =  None 
                score_max = 999999999 
                grad_max = -999999999 
                #first we draw one seed from seed files
                set_ida_ctr = 0 
                gen_flag = False 
                while pass_flag == False:
                    if fail_ctr > 0 :
                        print("[+] Trying to escape")
                    seed = gen_1[0]#random.choice(gen_1)
                    mode = random.choice(diversification)
                    iter_ = 1 #random.randint(1,10)
                    #mode = random.randint(0,10)
                    try:
                        if seed == MAIN_SEED:
                            fmode = 'original'
                        else:
                            fmode = 'mutated'
                        hash_ = generate(seed,SAVE_PATH,mode,fmode,function_name=function_name,iter=iter_)
                        gen_flag = True 
                        # consider the initailization case 
                        if len(generation_dict.keys())==0:
                            generation_dict[seed] = 0
                            generation_dict[hash_] = 1
                            operand_dict[seed] = []
                            operand_dict[hash_] = [mode]*iter_
                            cur_gen = 1
                            cur_op = str(operand_dict[hash_])
                        elif seed in generation_dict.keys():
                            old_gen = generation_dict[seed] +1
                            generation_dict[hash_] = old_gen
                            cur_gen = old_gen
                            old_operand = operand_dict[seed].copy()
                            gg = [mode]*iter_
                            old_operand +=gg
                            operand_dict[hash_] = old_operand
                            cur_op = str(operand_dict[hash_])
                        seed_of_output.append(seed)
                        output.append(hash_)
                        generation.append(cur_gen)
                        operand.append(cur_op)
                        seed_corpus.append(hash_)
                        #tmp_gen.append(hash_)
                        # One by one 
                        # do evaluation 
                        df = pd.DataFrame()
                        df['seed'] = seed_of_output
                        df['output'] = output
                        df['generation'] = generation
                        df['operand'] = operand
                        df.to_csv(SAVE_PATH+'/record_step_'+str(NUM_GEN)+'.csv')
                        # update the old 
                        #                     
                        run_pickle(SAVE_PATH,step_size =NUM_GEN)
                        xx = pd.read_csv(SAVE_PATH+'/record_pickle_'+str(NUM_GEN)+'.csv')
                        items = hash_
                        #get id 
                        print(items)
                        id_ = xx[xx['output']==items].index.values[0]
                        checkdict = ast.literal_eval(xx['mapping_symm'].iloc[id_])
                        check_addr = ast.literal_eval(xx['mapping_addr'].iloc[id_])
                        score,grad = call_retdec(items,checkdict,function_name)
                        print("score ",score," rank ",grad)
                        #score,grad = run_one(MAIN_SEED,items,model_original,checkdict,function_name)
                        if grad!=None:
                            grad = abs(grad)
                        # run checker 
                        # if works, quit 
                        if score <TARGET:
                            bypassed = True 
                            bypassed_sample = items
                            #break 
                            return seed_of_output,output,generation,operand,bypassed_sample 
                        if score!= None :
                            if grad > 0 and pass_flag == False and grad >= grad_list[0]:
                                pass_flag = True 
                                gen_1 = [items]
                                score_list = [score]
                                grad_list = [grad]
                            elif fail_ctr > 10 and grad > 0 :
                                pass_flag = True 
                                gen_1 = [gen_max]
                                score_list = [score_max]
                                grad_list = [grad_max]
                            else:
                                fail_ctr +=1 
                                score = None
                    except:
                        if gen_flag== False and i == 0 :
                            set_ida_ctr+=1 
                            if set_ida_ctr == 10:
                                fs = open(SAVE_PATH+"/fail.log",'w')
                                fs.write(str(i))
                                fs.close()
                                exit()
                        pass 
                tmp_gen = []
                gen_1,score_list,grad_list = ret_top5(gen_1,score_list,grad_list,SAVE_PATH,NUM_GEN)
                gen_1= gen_1.tolist()
                score_list= score_list.tolist()
                grad_list = grad_list.tolist()

                gen_1 = [gen_1[0]]
                score_list = [score_list[0]]
                grad_list = [grad_list[0]]


                if i!=0 and i%100==0:
                    df_1 = pd.DataFrame()
                    df_1['seed'] = seed_of_output
                    df_1['output'] = output
                    df_1['generation'] = generation
                    df_1['operand'] = operand
                    df_1.to_csv(SAVE_PATH+'/record_'+str(i)+'.csv')

        return seed_of_output,output,generation,operand,bypassed_sample 

    STEP = [10,20,40,50,100,200]
    STEP = [20]
    out_pd = pd.DataFrame()
    for step_size in STEP:
        seed_of_output,output,generation,operand,bypassed_sample = main(function_name,step_size)
        df = pd.DataFrame()
        df['seed'] = seed_of_output
        df['output'] = output
        df['generation'] = generation
        df['operand'] = operand 
        out_pd = out_pd.append(df)
        if len(bypassed_sample)>0:
            fs = open(SAVE_PATH+'/bypassed.log','w')
            fs.write(bypassed_sample)
            fs.close()
            out_pd.to_csv(SAVE_PATH+'/record.csv')
            run_pickle(SAVE_PATH)
            end_time = time.time()
            global st_time
            duration = end_time - st_time 
            time_log = open(SAVE_PATH+'/duration.log','w')
            time_log.write(str(duration))
            time_log.close()
            exit()
    



if __name__ == "__main__":

    p = ArgumentParser(formatter_class=RawTextHelpFormatter)
    p.add_argument("-binary_seed", help="name of the binary")
    p.add_argument("-function_name", help="name of the targetted function")
    args = p.parse_args()

    binary_seed = args.binary_seed
    function_name = args.function_name
    MAIN_SEED = "./uroboro_testing/bin_bk/"+binary_seed
    SAVE_PATH ="./uroboro_testing/function_container_"+function_name+"_"+MAIN_SEED.split("/")[-1]

    global st_time 
    st_time = time.time()
    wrapper(MAIN_SEED,SAVE_PATH,function_name)

