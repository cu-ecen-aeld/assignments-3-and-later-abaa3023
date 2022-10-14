#!/bin/bash

# Check for number of arguments. Minimum number of required argumnets is 2

if [ $# != 2 ]
then
	echo 'Kindly enter 2 arguments.'
	echo 'First argument is file directory.'
	echo 'Second argument is text string to be searched within the respective files in the mentioned file directory'
	exit 1
fi


# split file directory path into array
IFS='/' read -ra dir_array <<< $1
	
#save current size
size=${#dir_array[@]}
	
# save filename in file
file=${dir_array[$size-1]}
	
# remove filename from input file directory path
unset dir_array[$size-1]

#convert back array to split string for file path
IFS='/';modified_file_directory="${dir_array[*]}";IFS=$' \t\n'

# Check for valid directory

if ! [ -f $1 ]
then
	#remove first element from input file directory path
	unset dir_array[0]
	
	# set root directory
	cd /
	
	# iterate through every folder mentioned in input directory path
	for folder in "${dir_array[@]}"; do
		# if folder does not exist, create one and add to path
		# else set path to folder
		if ! [ -d $folder ]
		then
			mkdir $folder
			cd $folder
		else
			cd $folder
		
		fi
	done
	
	# create file
	touch $file
	
	# write to file
	echo $2>$file

else

	#goes to the specified directory
	cd $modified_file_directory
	
	#write data to file
	echo $2 > $file
		
fi

