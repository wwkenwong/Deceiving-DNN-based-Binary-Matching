#!/bin/bash

iter_num=10

make_source_dir="/home/coreutils-m32"
check_source_dir="$make_source_dir/src"

bins_list=`ls $make_source_dir/install/bin`

for i in 10 9 8 7 6 5 4 3 2 1
do
	echo "copy source file to check directory"
	for f in $bins_list
	do
		f_path="$f"_"$i"
		`rm  $check_source_dir/$f`
		`cp ./build_$f/$f_path $check_source_dir/$f`
	done
	echo "make check ... iter_num=$i"
	`cd $make_source_dir && make check > check_log_$i.txt 2>&1`
done

