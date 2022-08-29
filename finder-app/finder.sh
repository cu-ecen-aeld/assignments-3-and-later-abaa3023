#!/bin/bash

# Check for number of arguments. Minimum number of required argumnets is 2

if [ $# != 2 ]
then
	echo 'Kindly enter 2 arguments.'
	echo 'First argument is file directory.'
	echo 'Second argument is text string to be searched within the respective files in the mentioned file directory'
	exit 1
fi

# Check for valid directory
# If valid, will search for mentioned string in mentioned directory
# return count
# If not valid, will exit with error code 1

if ! [ -d $1 ]
then
	echo 'Kindly enter valid file directory'
	exit 1
fi

# -r is for recursive, will search through every folder in directory
# -i is for ignore case
# -c returns count per file
# -h limits the output only to the count, omits the file name

grep -rich $1 -e $2 > string_count_per_file.txt

total_file_count=$( wc -l < string_count_per_file.txt )
total_string_count=$( paste -sd+ string_count_per_file.txt | bc)

echo "The number of files are $total_file_count and the number of matching lines are $total_string_count"
