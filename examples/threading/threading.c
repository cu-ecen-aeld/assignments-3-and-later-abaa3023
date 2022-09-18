#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your paramete
    
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    
    thread_func_args->thread_complete_success = true;
    
    return thread_func_args;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
     
     int rc;
     
     struct thread_data *t_data = (struct thread_data *)malloc(sizeof(struct thread_data));
     
     if(t_data == NULL)
     	ERROR_LOG("\nRunning out of memory\n");
     else
     	DEBUG_LOG("\nMalloc successful\n");
     
     rc = pthread_create(&t_data->thread, NULL, threadfunc, t_data);
     if(rc == 0)
     {
     	DEBUG_LOG("\nCreate successful\n");
     	usleep(wait_to_obtain_ms*1000);
     }
     else
     	ERROR_LOG("\nPthread create failed\n");
     
     rc = pthread_mutex_init(mutex, NULL);
     if(rc!=0)
     	ERROR_LOG("\nMutex initialization failed\n");
     else
     	DEBUG_LOG("\nMutex initialization successful\n");
     
     rc = pthread_mutex_lock(mutex);
     if(rc == 0)
     {
     	DEBUG_LOG("\nPthread Mutex lock sucessful\n");
     	usleep(wait_to_release_ms*1000);
     }
     else
     	ERROR_LOG("\nPthread Mutex Lock failed\n");
     
     rc = pthread_mutex_unlock(mutex);
     if(rc!=0)
     	ERROR_LOG("\nPthread Mutex Unlock failed\n");
     else
     	DEBUG_LOG("\nPthread Mutex Unlock successful\n");
     
     if(t_data->thread_complete_success)
     {
     	syslog(LOG_DEBUG, "Success");  
     	DEBUG_LOG("\nThread process complete\n");
     	pthread_join(t_data->thread, NULL);
     	return true;
     }
     else
     {
     	syslog(LOG_DEBUG, "Error");  
     	ERROR_LOG("\nThread process not complete\n");
     	pthread_join(t_data->thread, NULL);
     	return false;
     }
}
