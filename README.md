# Artifact for the submission of Deceiving Deep Neural Networks-based Binary Code Matching with Adversarial Programs

# Implementation details 

Please check [here](implementation.md)

# System requirement

For Uroboros and basic components: 

- Ubuntu 18.04 LTS or Windows 10 with WSL and [Ubuntu 18.04 for Windows WSL](https://www.microsoft.com/en-us/p/ubuntu-1804-lts/9n9tngvndl3q) installed

- python3.7 or above installed 

- [radare2](https://github.com/radareorg/radare2) with r2pipe installed in python

For binaryAI:

- IDA Pro with idapython and decompiler support installed.

For NCC's inst2vec re-training (optional):

- GPU with atleast >8GB for inst2vec model retraining and augmentation


# Installing requirements for Uroboros

```bash 
sudo apt-get update
sudo apt-get -y install gcc gperf bison libtool gcc-multilib python python-dev python-pip gawk build-essential libc6-i386 lib32z1 lib32ncurses5 lib32bz2-1.0 libbz2-1.0:i386 wget git tar gcc-4.8 gcc-4.8-multilib
```

# Installing requirements for attacking ncc 

- Use the requirements.txt from Neural Code Comprehension: A Learnable Representation of Code Semantics's repository ([here](https://github.com/spcl/ncc/blob/master/requirements.txt)) to install the python dependencies

# Installing requirements for attacking binaryAI 

- Use the requirements.txt of binaryAI ([here](https://github.com/binaryai/sdk/blob/master/docs/requirements.txt)) to install the python dependencies 
- Make sure you have installed IDA Pro version > 7.1 for the support of IDA Pro microcode API
- Obtain the access key of binaryAI from [here](https://binaryai.tencent.com/apply-token)
- And paste it to the <pasteme> inside the ```ida_binaryai_linux.py``` 

# Evaluation steps :

1. Create a folder called ```uroboro_testing```
2. Build coreutils and copy to ```uroboro_testing```

# Option

The framework will take in 2 argument
1. ```<seed_program>``` : The name of the binary under the ```uroboro_testing``` folder 
2. ```<function_name>``` : Name of the function obtained from Objdump/IDA Pro


# Running attack for ncc 
```bash 
python3 ./ncc_harness.py -binary_seed <seed_program> -function_name <function_name>
```
# Running attack for asm2vec 
```bash 
python3 ./harness.py -binary_seed <seed_program> -function_name <function_name>
```
# Running attack for binaryAI 
```bash 
python3 ./ida_harness.py -binary_seed <seed_program> -function_name <function_name>
```

You can see the mutated folders under ```./uroboro_testing/function_container_<function_name>_<seed_program>```. The presents of ```bypassed.txt``` inside the folder indicate a successful attack. 
