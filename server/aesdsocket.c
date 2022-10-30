// had seeked help from Guru and fellow classmates regarding the state machine implementation

/*
*   HEADER FILES
*/
#include <sys/types.h>
#include <sys/socket.h>
#include "queue.h"
#include <pthread.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <time.h>
#include "aesd_ioctl.h"
/*
*   MACROS
*/
#define BUF_SIZE_UNIT           (1024)
#define USE_AESD_CHAR_DEVICE

#ifdef  USE_AESD_CHAR_DEVICE
    #define LOG_FILE                ("/dev/aesdchar")
#else
    #define LOG_FILE                ("/var/tmp/aesdsocketdata")
    #define CIRCULAR_BUF_DEPTH      (8)
#endif


typedef enum
{
    Accept_Connections,
    Join_threads,
}main_thread_states_t;
typedef enum
{
    Receive_From_Socket,
    Parse_data,
}worker_threads_states_t;
struct worker_thread_s
{
    pthread_t thread_id;
    bool thread_completed;
    worker_threads_states_t curr_state;
    int socket_file_descriptor;
    char ip_addr[INET6_ADDRSTRLEN];
    TAILQ_ENTRY(worker_thread_s) entries;
};
typedef struct worker_thread_s worker_thread_t;
typedef TAILQ_HEAD(head_s, worker_thread_s) head_t;
typedef struct
{
    bool signal_caught;
    bool free_address_info;
    bool free_socket_descriptor;
    struct addrinfo *host_addr_info;
    int socket_descriptor;
    int connection_count;
#ifndef USE_AESD_CHAR_DEVICE
    bool disarm_alarm;
    pthread_mutex_t mutex;
    timer_t timer_1;
    struct itimerspec itime;
#endif
}socket_state_t;
socket_state_t socket_state;

#ifdef USE_AESD_CHAR_DEVICE
typedef struct
{
	const char *command;
} command_table_t;

static const command_table_t commands[] = {
    {"AESDCHAR_IOCSEEKTO:"}
};
#else
typedef struct
{
    char time_string[100];
}circular_buf_data_t;
typedef struct
{
    uint32_t wptr;
    uint32_t rptr;
    bool queue_empty;
    bool queue_full;
    circular_buf_data_t time_buf[CIRCULAR_BUF_DEPTH];
}circular_buf_metadata_t;
circular_buf_metadata_t circular_buf;
#endif


#ifndef USE_AESD_CHAR_DEVICE
static void initialize_circular_buf()
{
    circular_buf.wptr = 0;
    circular_buf.rptr = 0;
    circular_buf.queue_full = false;
    circular_buf.queue_empty = true;
}

static uint32_t nextPtr(uint32_t ptr) {
  return ((ptr+1)&(CIRCULAR_BUF_DEPTH - 1));
}


static int enqueue_data_into_circ_buf(char* data)
{
  if(circular_buf.queue_full)
  {
    return -1;
  }
  strncpy(circular_buf.time_buf[circular_buf.wptr].time_string,data,80);
  circular_buf.wptr = nextPtr(circular_buf.wptr);
  circular_buf.queue_empty = false;
  if(circular_buf.wptr == circular_buf.rptr)
  {
    circular_buf.queue_full = true;
  }
  return 0;
}
static int dequeue_data_from_circ_buf(char* buf)
{
  if(circular_buf.queue_empty)
  {
    return -1;
  }
  strncpy(buf,circular_buf.time_buf[circular_buf.rptr].time_string,80);
  circular_buf.rptr = nextPtr(circular_buf.rptr);
  circular_buf.queue_full = false;
  if(circular_buf.wptr == circular_buf.rptr)
  {
    circular_buf.queue_empty = true;
  }
  return 0;
}


static int create_and_arm_timer()
{
    int flags = 0;
    int status = 0;
    status = timer_create(CLOCK_REALTIME, NULL, &socket_state.timer_1);
    if(status == -1)
    {
        return -1;
    }
    socket_state.itime.it_interval.tv_sec = 10;
    socket_state.itime.it_interval.tv_nsec = 0;
    socket_state.itime.it_value.tv_sec = 10;
    socket_state.itime.it_value.tv_nsec = 0;
    status = timer_settime(socket_state.timer_1, flags, &socket_state.itime,NULL);
    if(status == -1)
    {
        return -1;
    }
    return 0;
}
static void disarm_and_destroy_timer()
{
    int flags = 0;
    socket_state.itime.it_interval.tv_sec = 0;
    socket_state.itime.it_interval.tv_nsec = 0;
    socket_state.itime.it_value.tv_sec = 0;
    socket_state.itime.it_value.tv_nsec = 0;
    timer_settime(socket_state.timer_1, flags, &socket_state.itime,NULL);
    timer_delete(socket_state.timer_1);
}


static void alarmhandler()
{
    time_t rawtime;
    struct tm info;
    char buffer[80];
    time( &rawtime );
    localtime_r( &rawtime,&info );
    sprintf(buffer,"timestamp: %d/%02d/%02d - %02d:%02d:%02d\n",(info.tm_year + 1900),(info.tm_mon + 1),info.tm_mday,info.tm_hour,info.tm_min,info.tm_sec);
    enqueue_data_into_circ_buf(buffer);
    
}
#endif


static void sighandler()
{
    socket_state.signal_caught = true;
}


static int setup_signal(int signo)
{
    struct sigaction action;
    if(signo == SIGINT || signo == SIGTERM)
    {
        action.sa_handler = sighandler;
    }
    #ifndef USE_AESD_CHAR_DEVICE
    else if(signo == SIGALRM)
    {
        action.sa_handler = alarmhandler;
    }
    #endif
    action.sa_flags = 0;
    sigset_t empty;
    if(sigemptyset(&empty) == -1)
    {
        return -1; 
    }
    action.sa_mask = empty;
    if(sigaction(signo, &action, NULL) == -1)
    {
        return -1;         
    }
    return 0;
}

static void initialize_socket_state()
{
    socket_state.free_address_info = false;
    socket_state.free_socket_descriptor = false;
    socket_state.signal_caught = false;
    socket_state.host_addr_info = NULL;
    socket_state.connection_count = 0;
    #ifndef USE_AESD_CHAR_DEVICE
    socket_state.disarm_alarm = false;
    pthread_mutex_init(&socket_state.mutex, NULL);
    #endif
}
static void perform_cleanup()
{
    if(socket_state.host_addr_info && socket_state.free_address_info)
    {
        freeaddrinfo(socket_state.host_addr_info);
    }
    if(socket_state.free_address_info)
    {
        close(socket_state.socket_descriptor);
    }
    #ifndef USE_AESD_CHAR_DEVICE
    if(socket_state.disarm_alarm)
    {
        disarm_and_destroy_timer();
    }
    pthread_mutex_destroy(&socket_state.mutex);
    #endif
    closelog();
}
static void shutdown_function()
{
    printf("\nCaught Signal. Exiting\n");
    perform_cleanup();
    #ifndef USE_AESD_CHAR_DEVICE
    	unlink("/var/tmp/aesdsocketdata");
    #endif
    exit(1);
}


static void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
static int dump_content(int fd, char* string,int write_len)
{
    ssize_t ret; 
    while(write_len!=0)
    {
        ret = write(fd,string,write_len);
        if(ret == 0)
        {
            break;
        } 
        if(ret == -1)
        {
            if(errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        write_len -= ret;
        string += ret;
    }
    return 0;
}
static int echo_file_socket(int fd, int socket_fd)
{
    ssize_t ret; 
    char write_str[BUF_SIZE_UNIT];
    while(1)
    {
        memset(write_str,0,sizeof(write_str));
        ret = read(fd,write_str,sizeof(write_str));
        if(ret == 0)
        {
            break;
        } 
        if(ret == -1)
        {
            if(errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        int num_bytes_to_send = ret;
        int num_bytes_sent = 0;
        int str_index = 0;
        while(num_bytes_to_send>0)
        {
            num_bytes_sent = send(socket_fd,&write_str[str_index],num_bytes_to_send,0);
            if(num_bytes_sent == -1)
            {
                return -1;
            }
            num_bytes_to_send -= num_bytes_sent;
            str_index += num_bytes_sent;
        }
    }
    return 0;
}
#ifndef USE_AESD_CHAR_DEVICE
static void* server_thread(void* thread_param)
{
    worker_thread_t *thread_params = (worker_thread_t *)thread_param;
    int file_descriptor,num_bytes_read = 0,start_ptr = 0,num_bytes_to_read=0,buf_len=0,buf_cap=0,status=0;
    char *ptr,*buf;
    while(1)
    {
        switch(thread_params->curr_state)
        {
            case Receive_From_Socket:
                if(buf_cap == buf_len)
                {
                    if(buf_cap == 0)
                    {
                        buf = malloc(BUF_SIZE_UNIT);
                        if(!buf)
                        {
                            close(thread_params->socket_file_descriptor);
                    	     thread_params->thread_completed = true;
                            return 0;
                        }
                    }
                    else
                    {
                        int new_len = buf_cap + BUF_SIZE_UNIT; 
                        char *new_buf;   
                        new_buf = realloc(buf,new_len);     
                        if(!new_buf)
                        {
                            free(buf);
                            close(thread_params->socket_file_descriptor);
			     thread_params->thread_completed = true;
			     return 0;
                        }
                        buf = new_buf;           
                    }
                    buf_cap += BUF_SIZE_UNIT;
                }
                num_bytes_read = 0;
                num_bytes_read = recv(thread_params->socket_file_descriptor,(buf+buf_len),(buf_cap - buf_len),0);
                if(num_bytes_read == -1)
                {
                    free(buf);
		     close(thread_params->socket_file_descriptor);
		     thread_params->thread_completed = true;
		     return 0;
                }
                else if(num_bytes_read>0)
                {
                    thread_params->curr_state = Parse_data;
                }
                else if(num_bytes_read == 0)
                {
                    free(buf);
		    close(thread_params->socket_file_descriptor);
		    thread_params->thread_completed = true;
		    return 0;
                }
                break;
            case Parse_data:
                num_bytes_to_read = ((buf_len - start_ptr) + num_bytes_read);
                int temp_read_var = num_bytes_to_read;
                for(ptr = &buf[start_ptr];temp_read_var>0;ptr++,temp_read_var--)
                {
                    if(*ptr == '\n')
                    {
                        temp_read_var--;
                        status = pthread_mutex_lock(&socket_state.mutex);
                        if(status != 0)
                        {
                            free(buf);
			    close(thread_params->socket_file_descriptor);
			    thread_params->thread_completed = true;
			    return 0;
                        }
                        file_descriptor = open(LOG_FILE,O_RDWR|O_CREAT|O_APPEND,S_IRWXU|S_IRWXG|S_IRWXO);
                        if(file_descriptor == -1)
                        {
                            pthread_mutex_unlock(&socket_state.mutex);
			    close(thread_params->socket_file_descriptor);
			    thread_params->thread_completed = true;
			    return 0;
                        }
                        
                        int bytes_written_until_newline = (num_bytes_to_read - temp_read_var);
                        if(dump_content(file_descriptor,&buf[start_ptr],bytes_written_until_newline)==-1)
                        {
                            close(file_descriptor);
			    pthread_mutex_unlock(&socket_state.mutex);
			    close(thread_params->socket_file_descriptor);
			    thread_params->thread_completed = true;
			    return 0;
                        }                        
                        lseek(file_descriptor, 0, SEEK_SET );
                        if(echo_file_socket(file_descriptor,thread_params->socket_file_descriptor)==-1)
                        {
                            close(file_descriptor);
			    pthread_mutex_unlock(&socket_state.mutex);
			    close(thread_params->socket_file_descriptor);
			    thread_params->thread_completed = true;
			    return 0;
                        }
                        char time_buf_string[80];
                    
                        if(dequeue_data_from_circ_buf(time_buf_string)==0)
                        {
                            if(dump_content(file_descriptor,time_buf_string,strlen(time_buf_string))!=-1)
                            {
                                bytes_written_until_newline += strlen(time_buf_string);
                            }
                        }
                        start_ptr = bytes_written_until_newline;
                        close(file_descriptor);
                        status = pthread_mutex_unlock(&socket_state.mutex);
                        if(status != 0)
                        {
                           pthread_mutex_unlock(&socket_state.mutex);
			    close(thread_params->socket_file_descriptor);
			    thread_params->thread_completed = true;
			    return 0;
                        }
                        break;
                    }
                }
                buf_len += num_bytes_read;
                thread_params->curr_state = Receive_From_Socket;
                break;
        }
    }
    close(file_descriptor);
    pthread_mutex_unlock(&socket_state.mutex);
    close(thread_params->socket_file_descriptor);
    thread_params->thread_completed = true;
    return 0;
}
#else
static void* aesd_char_thread(void* thread_param)
{
    worker_thread_t *thread_params = (worker_thread_t *)thread_param;
    int file_descriptor,num_bytes_read = 0,start_ptr = 0,num_bytes_to_read=0,buf_len=0,buf_cap=0;
    char *ptr,*buf;
    while(1)
    {
        switch(thread_params->curr_state)
        {
            case Receive_From_Socket:
                if(buf_cap == buf_len)
                {
                    if(buf_cap == 0)
                    {
                        buf = malloc(BUF_SIZE_UNIT);
                        if(!buf)
                        {
                            close(thread_params->socket_file_descriptor);
                    	     thread_params->thread_completed = true;
                            return 0;
                        }
                    }
                    else
                    {
                        int new_len = buf_cap + BUF_SIZE_UNIT; 
                        char *new_buf;   
                        new_buf = realloc(buf,new_len);     
                        if(!new_buf)
                        {
                            free(buf);
                            close(thread_params->socket_file_descriptor);
			     thread_params->thread_completed = true;
			     return 0;
                        }
                        buf = new_buf;           
                    }
                    buf_cap += BUF_SIZE_UNIT;
                }
                num_bytes_read = 0;
                num_bytes_read = recv(thread_params->socket_file_descriptor,(buf+buf_len),(buf_cap - buf_len),0);
                if(num_bytes_read == -1)
                {
                    free(buf);
		    close(thread_params->socket_file_descriptor);
		    thread_params->thread_completed = true;
		    return 0;
                }
                else if(num_bytes_read>0)
                {
                    thread_params->curr_state = Parse_data;
                }
                else if(num_bytes_read == 0)
                {
                    free(buf);
		    close(thread_params->socket_file_descriptor);
		    thread_params->thread_completed = true;
		    return 0;
                }
                break;
            case Parse_data:
                num_bytes_to_read = ((buf_len - start_ptr) + num_bytes_read);
                
                int temp_read_var = num_bytes_to_read;
                for(ptr = &buf[start_ptr];temp_read_var>0;ptr++,temp_read_var--)
                {
                    if(*ptr == '\n')
                    {
                        temp_read_var--;
                        file_descriptor = open(LOG_FILE,O_RDWR|O_CREAT|O_APPEND,S_IRWXU|S_IRWXG|S_IRWXO);
                        if(file_descriptor == -1)
                        {
                            free(buf);
			     close(thread_params->socket_file_descriptor);
			     thread_params->thread_completed = true;
			     return 0;
                        }
                        
                        int bytes_written_until_newline = (num_bytes_to_read - temp_read_var);
                        
                        if(strncmp(&buf[start_ptr], commands[0].command, strlen(commands[0].command))==0)
                        {
                        	struct aesd_seekto seekto;
                        	sscanf(&buf[start_ptr], "AESDCHAR_IOCSEEKTO:%d,%d", &seekto.write_cmd, &seekto.write_cmd_offset);
                        	printf("Write cmd %d, offset %d\n", seekto.writecmd, seekto.write_cmd_offset);
                        	if(ioctl(file_descriptor, AESD_IOCSEEKTO, &seekto))
                        	{
                        		syslog(LOG_ERR, "IOCTL: %s", strerror(errno));
                        	}
                        }
                        else
                        {
		                if(dump_content(file_descriptor,&buf[start_ptr],bytes_written_until_newline)==-1)
		                {
		                    close(file_descriptor);
				    free(buf);
				    close(thread_params->socket_file_descriptor);
				    thread_params->thread_completed = true;
				    return 0;
		                }
                        }                        
                        
                        if(echo_file_socket(file_descriptor,thread_params->socket_file_descriptor)==-1)
                        {
                            	close(file_descriptor);
				free(buf);
				close(thread_params->socket_file_descriptor);
				thread_params->thread_completed = true;
				return 0;
                        }
                        start_ptr = bytes_written_until_newline;
                        close(file_descriptor);
                        break;
                    }
                }
                buf_len += num_bytes_read;
                thread_params->curr_state = Receive_From_Socket;
                break;
        }
    }
    close(file_descriptor);
    free(buf);
    close(thread_params->socket_file_descriptor);
    thread_params->thread_completed = true;
    return 0;
}
#endif

int main(int argc,char **argv)
{
    initialize_socket_state();
    bool run_as_daemon = false;
    main_thread_states_t main_thread_state;
    openlog(NULL,0,LOG_USER);
    int opt;
    while((opt = getopt(argc, argv,"d")) != -1)
    {
        switch(opt)
        {
            case 'd':
                run_as_daemon = true;
                break;
        }
    }
    int status=0,yes=1;
    struct addrinfo hints;
    struct addrinfo *p = NULL;  // will point to the results
    char s[INET6_ADDRSTRLEN];
    memset(s,0,sizeof(s));
    struct sockaddr_storage client_addr;
    socklen_t addr_size = sizeof(client_addr);
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me
    
    status = getaddrinfo(NULL, "9000", &hints, &socket_state.host_addr_info);
    if(status != 0)
    {
        return -1;
    }
    socket_state.free_address_info = true;
    
    for(p = socket_state.host_addr_info; p != NULL; p = p->ai_next) 
    {
        socket_state.socket_descriptor = socket(p->ai_family, p->ai_socktype,p->ai_protocol);
        if(socket_state.socket_descriptor == -1)
        {
            continue;
        }
        socket_state.free_socket_descriptor = true;
        status = setsockopt(socket_state.socket_descriptor,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
        if(status == -1)
        {
            perform_cleanup();
            return -1;
        }
        status = bind(socket_state.socket_descriptor,p->ai_addr, p->ai_addrlen);
        if(status == -1)
        {
            close(socket_state.socket_descriptor);
            continue;
        }
        break;
    }
    if(p == NULL)
    {
        perform_cleanup();
        return -1;
    }
    
    
    freeaddrinfo(socket_state.host_addr_info);
    socket_state.free_address_info = false;
    
    if(run_as_daemon)
    {
        pid_t pid;
        pid = fork ();
        if (pid == -1)
        {
            perform_cleanup();
            return -1;
        }
        else if (pid != 0)
        {
            perform_cleanup();
            exit (EXIT_SUCCESS);
        }
        else
        {
            if(setsid()==-1)
            {
                perform_cleanup();
                return -1;
            }
            if(chdir("/")==-1)
            {
                perform_cleanup();
                return -1;
            }
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            open ("/dev/null", O_RDWR); /* stdin */
            dup (0); /* stdout */
            dup (0); /* stderror */
        }
    }
    int backlog = 10;
    status = listen(socket_state.socket_descriptor,backlog);
    if(status == -1)
    {
        perform_cleanup();
        return -1;
    }
    
    if(setup_signal(SIGINT)== -1)
    {
        perform_cleanup();
        return -1;
    }
    if(setup_signal(SIGTERM)==-1)
    {
        perform_cleanup();
        return -1;        
    }
    #ifndef USE_AESD_CHAR_DEVICE
    initialize_circular_buf();
    if(setup_signal(SIGALRM)==-1)
    {
        perform_cleanup();
        return -1;          
    }
    if(create_and_arm_timer()==-1)
    {
        perform_cleanup();
        return -1;    
    }
    socket_state.disarm_alarm = true;
    #endif
    
    head_t head;
    TAILQ_INIT(&head);
    
    if(socket_state.signal_caught)
    {
        main_thread_state = Join_threads;
    }
    else
    {
        main_thread_state = Accept_Connections;
    }
    
    int socket_fd;
    while(1)
    {
        switch(main_thread_state)
        {
            case Accept_Connections:
                
                socket_fd = accept(socket_state.socket_descriptor,(struct sockaddr*)&client_addr,&addr_size);
                if(socket_fd == -1)
                {   
                    if(errno == EINTR)
                    {
                        goto next_state;
                    }
                    goto next_state;
                }                    
                inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr *)&client_addr), s, sizeof(s));
                worker_thread_t *node = NULL;
                node = malloc(sizeof(worker_thread_t));
                if(!node)
                {
                    goto next_state;
                }
                node->thread_completed = false;
                node->curr_state = Receive_From_Socket;
                node->socket_file_descriptor = socket_fd;
                strcpy(node->ip_addr,s);
                #ifdef USE_AESD_CHAR_DEVICE
                status = pthread_create(&node->thread_id,
                            (void*)0,
                            aesd_char_thread,
                            node);
                #else
                status = pthread_create(&node->thread_id,
                             (void*)0,
                             server_thread,
                             node);
                #endif
                if(status !=0)
                {
                    free(node);
                    goto next_state;
                }   
                TAILQ_INSERT_TAIL(&head, node, entries);
                socket_state.connection_count++;
                node = NULL;
                goto next_state;
                next_state:
                    main_thread_state = Join_threads;
                    break;
            case Join_threads:
                if(socket_state.connection_count>0)
                {
                    worker_thread_t *var = NULL;
                    worker_thread_t *tvar = NULL;
                    TAILQ_FOREACH_SAFE(var,&head,entries,tvar)
                    {
                        if(var->thread_completed)
                        {
                            pthread_join(var->thread_id,NULL);
                            TAILQ_REMOVE(&head, var, entries);
                            free(var);
                            var = NULL;
                            socket_state.connection_count--;
                        }
                    }
                }
                #ifndef USE_AESD_CHAR_DEVICE
                if(socket_state.connection_count==0)
                {
                    status = pthread_mutex_trylock(&socket_state.mutex);
                    if(status == 0)
                    {
                        char time_val_buf[80];
                        if(dequeue_data_from_circ_buf(time_val_buf)==0)
                        {
                            int fd = open(LOG_FILE,O_WRONLY|O_CREAT|O_APPEND,S_IRWXU|S_IRWXG|S_IRWXO);
                            if(fd != -1)
                            {
                                dump_content(fd,time_val_buf,strlen(time_val_buf));
                                close(fd);
                            }
                        }
                        pthread_mutex_unlock(&socket_state.mutex);
                    }
                }
                #endif
                if(socket_state.signal_caught)
                {
                    if(socket_state.connection_count==0)
                    {
                        shutdown_function();
                    }
                    else
                    {
                        break;
                    }
                }
                main_thread_state = Accept_Connections;
                break;
        }    
    }
}
