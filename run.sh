#!bin/bash

iter_num=10
FLAGS="-d 1 -d 2 -d 3 -d 4 -d 5 -d 6 -d 7 -d 8 -d 9 -d 10"

bins_dir=$1

echo "search for ELFs in $bins_dir"

all_files=`ls $bins_dir`

for f in $all_files
do
  file_path="$bins_dir/$f"
  echo "process file: $file_path"
  `mkdir build_$f`
  echo "python uroboros.py $file_path -i $iter_num $FLAGS -o ./build_$f/$f > ./build_$f/log.txt 2>&1"
  `python uroboros.py $file_path -i $iter_num $FLAGS -o ./build_$f/$f > ./build_$f/log.txt 2>&1`
done

