import subprocess
from subprocess import check_output
import random 
import os
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

SURVIVIE = 1 
TARGET = 0.40 
mutant = {}
tmp_bin_name = "/tmp/output_bin_"+str(random.randint(0,300000))

global st_time 

def open_path(path):
    if not os.path.exists(path):
        os.makedirs(path)

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


def ret_top5(gen_1,score_list,grad_list,SAVE_PATH,STEP_SIZE,metric = 'grad_list'):
    df_tmp = pd.DataFrame()
    df_tmp['gen_1'] = gen_1
    df_tmp['score_list'] = score_list
    df_tmp['grad_list'] = grad_list
    if metric == 'score_list':
        df_tmp = df_tmp.sort_values(metric,ascending=True)
    else:
        df_tmp = df_tmp.sort_values(metric,ascending=False)
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

    # train seed's model 
    if True: #os.path.isfile(MAIN_SEED+".pickle"):
        # we gen the matching model first 
        #model_original = pickle.load(open(MAIN_SEED+".pickle",'rb'))
        model_original = pickle.load(open("gnu.pickle",'rb'))
    else:
        model_original = train_pickle(MAIN_SEED+".s")
        with open(MAIN_SEED+".pickle", 'wb') as handle:
            pickle.dump(model_original, handle, protocol=pickle.HIGHEST_PROTOCOL)

    # every time gen 10 
    # 

    def main(function_name,NUM_GEN):
        generation_dict = {}
        operand_dict = {}
        gen_1 = []
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
                    got_sample= True 
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
            score,grad = run_one(MAIN_SEED,items,model_original,checkdict,function_name)
            grad = abs(grad)
            score = abs(score)
            # run checker 
            # if works, quit 
            # if score <TARGET:
            #     bypassed = True 
            #     bypassed_sample = items
            #     #break 
            #     return seed_of_output,output,generation,operand,bypassed_sample 
            # elif score!= None :
            score_list.append(score)
            grad_list.append(grad)
        if bypassed == False :
            gen_1,score_list,grad_list = ret_top5(gen_1,score_list,grad_list,SAVE_PATH,NUM_GEN,metric='score_list')
            gen_1= gen_1.tolist()
            score_list= score_list.tolist()
            grad_list = grad_list.tolist()
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
                        score,grad = run_one(MAIN_SEED,items,model_original,checkdict,function_name)
                        grad = abs(grad)
                        score = abs(score)
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
                                # let it go 
                                if score<score_max:
                                    gen_max = items 
                                    score_max = score
                                    grad_max = grad
                                pass_flag = True 
                                gen_1 = [gen_max]
                                score_list = [score_max]
                                grad_list = [grad_max]
                            else:
                                if grad>0:
                                    if score<score_max:
                                        gen_max = items 
                                        score_max = score
                                        grad_max = grad
                                fail_ctr +=1 
                                score = None
                    except:
                        pass 
                tmp_gen = []
                gen_1,score_list,grad_list = ret_top5(gen_1,score_list,grad_list,SAVE_PATH,NUM_GEN)
                gen_1= gen_1.tolist()
                score_list= score_list.tolist()
                grad_list = grad_list.tolist()
                gen_1 = [gen_1[0]]
                score_list = [score_list[0]]
                grad_list = [grad_list[0]]


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
    MAIN_SEED = "./bin_bk/"+binary_seed
    SAVE_PATH ="./function_container_"+function_name+"_"+MAIN_SEED.split("/")[-1]
    global st_time 
    st_time = time.time()
    wrapper(MAIN_SEED,SAVE_PATH,function_name)

