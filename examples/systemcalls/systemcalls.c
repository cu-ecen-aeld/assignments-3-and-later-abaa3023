/*
 * Author: Abijith
 *
 */

// Header files
#include "systemcalls.h"
#include "errno.h"
#include "stdlib.h"
#include "syslog.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>



/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{

/*
 * TODO  add your code here
 *  Call the system() function with the command set in the cmd
 *   and return a boolean true if the system() call completed with success
 *   or false() if it returned a failure
*/
    int ret = system(cmd);
    // check if system command was executed properly or not
    if(ret == -1)
    {
    	syslog(LOG_ERR, "Child process could not be created or status cannot be retrieved. Return value = -1, errno = %d", errno);
    	return false;
    }
    
    // return 127 if a shell could not be executed in the child process
    if(ret == 127)
    {
    	syslog(LOG_ERR, "Shell could not be executed in the child process then return value is as though the child shell terminated by calling exit(1), errno = %d", errno);
    	return false;
    }
    
    syslog(LOG_DEBUG, "system command successfully executed");	
    return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    char * rest_of_args[count];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    
    // checks if directory exists or not
    DIR* dir = opendir(command[0]);
    if(dir)
    {
    	closedir(dir);
    }
    else if(errno == ENOENT)
    {
    	return false;
    }
    
    // add situation if number of arguments is 3
    if(count == 3)
    {
    	DIR* dir1 = opendir(command[2]);
    	if(dir1)
    	{
    		closedir(dir1);
    	}
    	else if(errno == ENOENT)
    	{
    		return false;
    	}
    }
    // assign full path variable
    char *full_path = command[0];
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];
    
    for(i=0; i<(count+1); i++)
    {
        rest_of_args[i]=command[i+1];
    }

/*
 * TODO:
 *   Execute a system command by calling fork, execv(),
 *   and wait instead of system (see LSP page 161).
 *   Use the command[0] as the full path to the command to execute
 *   (first argument to execv), and use the remaining arguments
 *   as second argument to the execv() command.
 *
*/
    
    int status;
    pid_t pid;
    pid=fork();
    if(pid==-1)
    	return false;
    else if(pid == 0)
    {
    	if((execv(full_path, rest_of_args))!=-1)
    		return true;
    	else
    		return false;
    }
    
    if(waitpid(pid,&status,0)==-1)
    	return false;
    else if(WIFEXITED(status))
    	return true;	
    va_end(args);

    return true;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    // check if directory exists
    DIR* dir = opendir(command[0]);
    if(dir)
    {
    	closedir(dir);
    }
    else if(errno == ENOENT)
    {
    	return false;
    }
    // add condition for number of arguments as 3
    if(count == 3)
    {
    	DIR* dir1 = opendir(command[2]);
    	if(dir1)
    	{
    		closedir(dir1);
    	}
    	else if(errno == ENOENT)
    	{
    		return false;
    	}
    }
    // full path is assigned as variable
    char *full_path = command[0];
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];


/*
 * TODO
 *   Call execv, but first using https://stackoverflow.com/a/13784315/1446624 as a refernce,
 *   redirect standard out to a file specified by outputfile.
 *   The rest of the behaviour is same as do_exec()
 *
*/

    int status;
    pid_t pid;
    int fd = open(outputfile, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    if (fd < 0)
    {
    	syslog(LOG_ERR, "Error while opening file");
    	return false;
    }
    pid=fork();
    if(pid==-1)
    	return false;
    else if(pid == 0)
    {
    	if (dup2(fd, 1) < 0) 
    	{
    		syslog(LOG_ERR, "Error while executing dup2");
    		return false;
    	}
    	close(fd);
    	if((execv(full_path, command))!=-1)
    		return true;
    	else
    		return false;
    }
    
    if(waitpid(pid,&status,0)==-1)
    	return false;
    else if(WIFEXITED(status))
    	return true;	
    va_end(args);

    return true;
}
