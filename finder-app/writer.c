/*
 * Author: Abijith Ananda Krishnan
 *
 * Accepts the following arguments: 
 * the first argument is a full path to a file (including filename) on the  
 * filesystem, referred to below as writefile; 
 * the second argument is a text string which will be written within this 
 * file, referred to below as writestr

 * Exits with value 1 error and print statements if any of the arguments 
 above were not specified
 
 * Creates a new file with name and path writefile with content writestr, 
 overwriting any existing file and creating the path if it doesn’t exist. 
 * Exits with value 1 and error print statement if the file could not be 
 created.
 *
 */


// Header files
#include <stdio.h>
#include <syslog.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h> 
#include <fcntl.h>
#include <unistd.h>



// Entry point of application
int main(int argc, char* argv[])
{
	// Logging timestamp
	char cur_time[128];
	time_t t;
	struct tm* ptm;
	t = time(NULL);
	ptm = localtime(&t);
	strftime(cur_time, 128, "%d-%b-%Y %H:%M:%S", ptm);
	syslog(LOG_USER, "Abijith logged in at %s UTC\n", cur_time);
	openlog(NULL,0,LOG_USER);
	
	// Number of arguments check
	// exits program if number of arguments not equal to 3
	if(argc!=3)
	{
		syslog(LOG_ERR,"errno: %d\nKindly enter 2 arguments.\nFirst argument is file directory.\nSecond argument is text string to be searched within the respective files in the mentioned file directory\n",errno);
		exit(1);
	}
	
	char *writefile = argv[1];
	char *writestr = argv[2];
	int writestrlen = strlen(argv[2]);
	int fd;
	fd=open(writefile, O_WRONLY | O_TRUNC | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
	if(fd == -1)
	{
		syslog(LOG_ERR, "Error %d while opening file", errno);
		exit(1);
	}
	else
		syslog(LOG_DEBUG, "Open successful");
	
	ssize_t nr;
	nr = write(fd, writestr, writestrlen);
	if(nr == -1)
	{
		syslog(LOG_ERR, "Error %d while writing to file", errno);
		exit(1);
	}
	else
		syslog(LOG_DEBUG, "Write successful");
}
