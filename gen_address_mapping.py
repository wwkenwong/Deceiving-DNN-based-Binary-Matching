import glob
import os 

'''
Original : 
BB_7:   ->  __x86.get_pc_thunk.bx :   ->  S_0x8049680 : mov (%esp),%ebx
BB_9:   ->  deregister_tm_clones :   ->  S_0x8049690 : mov $0x80591F7,%eax
BB_15:   ->  register_tm_clones :   ->  S_0x80496C0 : mov $0x80591F4,%eax
BB_26:   ->  frame_dummy :   ->  S_0x8049720 : mov 0x8058F10,%eax
BB_32:   ->  emit_mandatory_arg_note :   ->  S_0x804974D : push %ebp
BB_35:   ->  emit_backup_suffix_note :   ->  S_0x8049778 : push %ebp
BB_40:   ->  emit_ancillary_info :   ->  S_0x80497C1 : push %ebp
BB_63:   ->  errno_nonexisting :   ->  S_0x8049947 : push %ebp
'''

# we have 
# 1. New symbol 
# 2. New address
# 3. old address
# 4. old symbol 

# -> 
# new addr -> old addr 
# old addr -> new addr 
# new addr -> old symbol 
# old addr -> new symbol 

# List of mutated file chain 
# if is SEED 
# create file 

def execute_mapping():
    os.system("objdump  -Dr -j .text  a.out |grep \">:\" > addr_map")
    fs = open('addr_map').read()
    fs = fs.split('\n')
    new_symbol_to_new_addr = {}
    new_addr_to_new_symbol = {}
    for gg in fs:
        if len(gg)>0:
            addr_tmp = "0x"+gg.split(" ")[0]
            symbol_tmp = gg.split("<")[-1].replace('>:',"")
            new_symbol_to_new_addr[symbol_tmp] = addr_tmp
            new_addr_to_new_symbol[addr_tmp] = symbol_tmp
    return new_symbol_to_new_addr,new_addr_to_new_symbol


def gen_mapping(mode):
    # original seed vs mutated seed 
    fs = open('final.s').read()
    fs = fs.split('\n')
    arr = []
    # mapping dict
    # In all of case ,we will save the mapping 
    # between new symbol and old addr
    # For the seed corpus 
    new_symbol_to_old_addr = {}
    old_addr_to_new_symbol = {}

    new_symbol_to_new_addr,new_addr_to_new_symbol = execute_mapping()

    # use for original transformation 
    new_symbol_to_seed_symbol = {}
    seed_symbol_to_new_symbol = {}

    for gg in range(0, len(fs)):
        if fs[gg][:4] == "S_0x":
            arr.append(gg)
    if mode =="original":
        for pp in arr:
            #if "BB_" in fs[pp-3] and "_merge:" in fs[pp-3] and "BB_" in fs[pp-2] and "BB_" not in fs[pp-1]:
            if "BB_" in fs[pp-3]  and "BB_" in fs[pp-2] and "BB_" not in fs[pp-1]:
                '''
                Type A 
                2. 
                BB_4547_merge: pp-3 
                BB_4548: pp-2 
                readisaac : pp-1 
                S_0x805B2C8 : push %ebp <---- pp
                3. 
                BB_4472_merge: < OBJDUMP SYMBOL 
                BB_4473:
                randint_all_free :
                S_0x805AE5F : push %ebp < THIS ONE WILL BE IDA SYMBOL 

                8058f95:	e8 c9 32 00 00       	call   805c263 <BB_4472_merge>
                8058fbc:	e8 a2 32 00 00       	call   805c263 <BB_4472_merge>
                805c25f:	eb 02                	jmp    805c263 <BB_4472_merge>
                0805c263 <BB_4472_merge>:

                ================
                Type B 
                BB_945:
                BB_946:
                __libc_csu_init :
                S_0x804C1C0 : push %ebp
                push %edi
                push %esi
                push %ebx


               '''
                old_addr_tmp = fs[pp].split(" ")[0].split("_")[1]
                old_symbol_tmp = fs[pp-1].replace(" ","").split(":")[0]
                new_symbol_tmp_2 = fs[pp-2].replace(" ","").split(":")[0]
                new_symbol_tmp = fs[pp-3].replace(" ","").split(":")[0]

                if new_symbol_tmp not in new_symbol_to_new_addr.keys():
                    new_symbol_tmp = new_symbol_tmp_2

                new_symbol_to_seed_symbol[new_symbol_tmp] = old_symbol_tmp
                seed_symbol_to_new_symbol[old_symbol_tmp] = new_symbol_tmp

                new_symbol_to_old_addr[new_symbol_tmp] = old_addr_tmp
                old_addr_to_new_symbol[old_addr_tmp] = new_symbol_tmp

            elif "BB_" in fs[pp-2] and "BB_" not in fs[pp-1]:
                '''
                BB_2898:
                free_entry :
                S_0x8054D11 : push %ebp
                '''
                # S_0x804974D : push %ebp
                old_addr_tmp = fs[pp].split(" ")[0].split("_")[1]
                old_symbol_tmp = fs[pp-1].replace(" ","").split(":")[0]
                new_symbol_tmp = fs[pp-2].replace(" ","").split(":")[0]
                new_symbol_to_seed_symbol[new_symbol_tmp] = old_symbol_tmp
                seed_symbol_to_new_symbol[old_symbol_tmp] = new_symbol_tmp
                new_symbol_to_old_addr[new_symbol_tmp] = old_addr_tmp
                old_addr_to_new_symbol[old_addr_tmp] = new_symbol_tmp
            # elif "BB_" in fs[pp-2] and "_merge" in fs[pp-2] and "BB_" in fs[pp-1]:
            #     '''
            #     BB_4508_merge: <---- pp-2 
            #     BB_4509: <---- pp-1
            #     S_0x805B0A0 : mov -0x30(%ebp),%eax <---- pp 
            #     '''
            #     # S_0x804974D : push %ebp
            #     old_addr_tmp = fs[pp].split(" ")[0].split("_")[1]
            #     old_symbol_tmp = fs[pp-1].replace(" ","").split(":")[0]
            #     new_symbol_tmp = fs[pp-2].replace(" ","").split(":")[0]
            #     new_symbol_to_seed_symbol[new_symbol_tmp] = old_symbol_tmp
            #     seed_symbol_to_new_symbol[old_symbol_tmp] = new_symbol_tmp
            #     new_symbol_to_old_addr[new_symbol_tmp] = old_addr_tmp
            #     old_addr_to_new_symbol[old_addr_tmp] = new_symbol_tmp

        return [new_symbol_to_new_addr,new_addr_to_new_symbol,\
              new_symbol_to_seed_symbol,seed_symbol_to_new_symbol,\
              new_symbol_to_old_addr,old_addr_to_new_symbol]

    elif mode =="mutated":
        for pp in arr:
            #if "BB_" in fs[pp-2] and "_merge:" in fs[pp-2] and "BB_" in fs[pp-1] :
            if "BB_" in fs[pp-2] and "BB_" in fs[pp-1] :
                '''
                BB_21_merge: < pp-2 
                BB_22: < pp-1 
                S_0x8049C8C : ret <--- pp
                '''
                old_addr_tmp = fs[pp].split(" ")[0].split("_")[1]
                new_symbol_tmp_2 = fs[pp-1].replace(" ","").split(":")[0]
                new_symbol_tmp = fs[pp-2].replace(" ","").split(":")[0]

                if new_symbol_tmp not in new_symbol_to_new_addr.keys():
                    new_symbol_tmp = new_symbol_tmp_2

                new_symbol_to_old_addr[new_symbol_tmp] = old_addr_tmp
                old_addr_to_new_symbol[old_addr_tmp] = new_symbol_tmp

            elif "BB_" in fs[pp-1] :
                old_addr_tmp = fs[pp].split(" ")[0].split("_")[1]
                new_symbol_tmp = fs[pp-1].replace(" ","").split(":")[0]
                #print(fs[pp-2]," -> ",fs[pp-1]," -> ",fs[pp])
                new_symbol_to_old_addr[new_symbol_tmp] = old_addr_tmp
                old_addr_to_new_symbol[old_addr_tmp] = new_symbol_tmp

        return [new_symbol_to_new_addr,new_addr_to_new_symbol,\
              new_symbol_to_old_addr,old_addr_to_new_symbol]

