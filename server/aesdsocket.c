// reference: Beej's guide to network programming
// Tutorials's point
// seeked help from fellow classmates regarding the use of statemachines and respective enums
/*
 * Header files
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include "queue.h"
#include <sys/time.h>
#include <time.h>
#include <pthread.h>



/*
 * Macros
 */
#define PORT "9000" 
#define BUFFER_STD_SIZE 256
#define MAX_CONNECTIONS_ON_INCOMING_QUEUE 10
#define SEND_FLAGS 0
#define RECV_FLAGS 0
#define FILE_PATH "/var/tmp/aesdsocketdata"
#define MAX_BUF_SIZE 1000
#define SOCKET_DOMAIN AF_INET
#define SOCKET_TYPE SOCK_STREAM
#define SOCKET_PROTOCOL 0
#define MAX_ACCEPT 10



/*
 * Global variables
 */
typedef enum
{
    accept_t,
    join_t,
    recv_t,
    send_t
}thread_type_t;



struct node_s
{
    pthread_t thread_id;
    bool thread_completed;
    thread_type_t thread_type;
    int fd;
    char ip_addr[INET6_ADDRSTRLEN];
    TAILQ_ENTRY(node_s) nodes;
};

typedef struct node_s node_t;
typedef TAILQ_HEAD(head_s, node_s) head_t;
typedef struct
{
    bool trigger;
    bool free_address_info;
    bool disarm_alarm;
    struct addrinfo *host_addr_info;
    int serverfd;
    bool free_serverfd;
    pthread_mutex_t mutex;
    int connection_count;
    timer_t timer;
    struct itimerspec itime;
}s_data_t;

s_data_t s_data;

typedef struct
{
    char time[100];
}time_str_s;

typedef struct
{
    bool q_empty;
    bool q_full;
    uint32_t tail;
    uint32_t head;
    time_str_s t_str[MAX_ACCEPT];
}queue_s;

queue_s q;

static uint32_t nextPtr(uint32_t ptr) {

  return ((ptr+1)&(MAX_ACCEPT - 1));

}

static int dequeue(char* buf)
{
  if(q.q_empty)
  {
    return -1;
  }
  strncpy(buf,q.t_str[q.head].time,80);
  q.head = nextPtr(q.head);
  q.q_full = false;
  if(q.tail == q.head)
  {
    q.q_empty = true;
  }
  return 0;
}

static void signal_handler()
{
    s_data.trigger = true;
}

static void alarm_handler()
{
    //https://www.tutorialspoint.com/c_standard_ibrary/c_function_strftime.htm	
    time_t rawtime;
    struct tm *info;
    char time_val[40];
    char buffer[80];
    time( &rawtime );

    info = localtime( &rawtime );

    strftime(time_val,40,"%Y/%m/%d - %H:%M:%S", info);
    sprintf(buffer,"timestamp: %s \n",time_val);
    if(q.q_full)
    {
	exit(-1);
    }
    strncpy(q.t_str[q.tail].time,buffer,80);
    q.tail = nextPtr(q.tail);
    q.q_empty = false;
    if(q.tail == q.head)
    {
	q.q_full = true;
    }
}

static int register_signal(int signum)
{
    struct sigaction action;
    if(signum == SIGINT || signum == SIGTERM)
    {
        action.sa_handler = signal_handler;
    }
    else if(signum == SIGALRM)
    {
        action.sa_handler = alarm_handler;
    }
    action.sa_flags = 0;
    sigset_t empty;
    if(sigemptyset(&empty) == -1)
    {
        syslog(LOG_ERR, "Could not set up empty signal set: %s.", strerror(errno));
        return -1; 
    }
    action.sa_mask = empty;
    if(sigaction(signum, &action, NULL) == -1)
    {
        syslog(LOG_ERR, "Could not set up handle for signal: %s.", strerror(errno));
        return -1;         
    }
    return 0;
}

static void init_queue()
{
    q.q_full = false;
    q.q_empty = true;
    q.tail = 0;
    q.head = 0;
}



static void init_socket()
{

    s_data.free_address_info = false;
    s_data.free_serverfd = false;
    s_data.trigger = false;
    s_data.disarm_alarm = false;
    s_data.host_addr_info = NULL;
    pthread_mutex_init(&s_data.mutex, NULL);
    s_data.connection_count = 0;
}

static void shutdown_function()
{
    printf("\nCaught Signal. Exiting\n");
    printf("Deleting file\n");
    unlink("/var/tmp/aesdsocketdata");
    exit(1);
}

static void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static int write_data(int fd, char* string,int write_len)
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
            //printf("Write len %d\n",write_len);
            perror("Error Write");
            return -1;
        }
        write_len -= ret;
        string += ret;
    }
    return 0;
}
static int echo_file_socket(int fd, int acceptfd)
{
    ssize_t ret; 
    char write_str[BUFFER_STD_SIZE];
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
            //printf("Read Len %d\n",read_len);
            perror("Read");
            return -1;
        }
        int num_bytes_to_send = ret;
        int num_bytes_sent = 0;
        int str_index = 0;
        while(num_bytes_to_send>0)
        {
            num_bytes_sent = send(acceptfd,&write_str[str_index],num_bytes_to_send,0);
            if(num_bytes_sent == -1)
            {
                perror("Send");
                return -1;
            }
            num_bytes_to_send -= num_bytes_sent;
            str_index += num_bytes_sent;
        }
    }
    return 0;
}

// seeked help from Guru post getting stuck
// added goto statements
static void* threadfunc(void* thread_param)
{
    char *buffer;
    int file_fd;
    int recv_bytes = 0,start_ptr = 0,read_bytes=0;
    int buffer_length=0,buffer_capacity=0;
    int status=0;
    node_t *thread_params = (node_t *)thread_param;
    while(1)
    {
        switch(thread_params->thread_type)
        {
            case recv_t:
                if(buffer_capacity == buffer_length)
                {
                    if(buffer_capacity == 0)
                    {
                        buffer = malloc(BUFFER_STD_SIZE);
                        if(buffer == NULL)
                        {
                            goto free_socket_fd;
                        }
                    }
                    else
                    {
                        int new_len = buffer_capacity + BUFFER_STD_SIZE; 
                        char *new_buffer;   
                        new_buffer = realloc(buffer,new_len);     
                        if(!new_buffer)
                        {
                            free(buffer);
                            goto free_mem;
                        }
                        buffer = new_buffer;           
                    }
                    buffer_capacity += BUFFER_STD_SIZE;
                }
                recv_bytes = 0;
                recv_bytes = recv(thread_params->fd,(buffer+buffer_length),(buffer_capacity - buffer_length),RECV_FLAGS);
                if(recv_bytes == -1)
                {
                    syslog(LOG_ERR,"Recv: %s",strerror(errno));
                    goto free_mem;
                }
                else if(recv_bytes>0)
                {
                    thread_params->thread_type = send_t;
                }
                else if(recv_bytes == 0)
                {
                    goto free_mem;
                }
                break;
            case send_t:
                read_bytes = ((buffer_length - start_ptr) + recv_bytes);
                int temp_read_var = read_bytes;
                char *ptr;
                for(ptr = &buffer[start_ptr];temp_read_var>0;ptr++,temp_read_var--)
                {
                    if(*ptr == '\n')
                    {
                        temp_read_var--;
                        status = pthread_mutex_lock(&s_data.mutex);
                        if(status != 0)
                        {
                            syslog(LOG_ERR,"Mutex Lock: %s",strerror(errno));
                            goto free_mem;
                        }
                        file_fd = open(FILE_PATH,O_RDWR|O_CREAT|O_APPEND,S_IRWXU|S_IRWXG|S_IRWXO);
                        if(file_fd == -1)
                        {
                            syslog(LOG_ERR,"Open: %s",strerror(errno));
                            goto unlock_mutex;
                        }

                        int newline_data = (read_bytes - temp_read_var);
                        if(write_data(file_fd,&buffer[start_ptr],newline_data)==-1)
                        {
                            goto close_filefd;
                        }                        
                        lseek(file_fd, 0, SEEK_SET );

                        if(echo_file_socket(file_fd,thread_params->fd)==-1)
                        {
                            goto close_filefd;
                        }
                        char time_str[80];
                    
                        if(dequeue(time_str)==0)
                        {
                            if(write_data(file_fd,time_str,strlen(time_str))!=-1)
                            {
                                newline_data += strlen(time_str);
                            }
                        }
                        start_ptr = newline_data;
                        close(file_fd);
                        status = pthread_mutex_unlock(&s_data.mutex);
                        if(status != 0)
                        {
                            syslog(LOG_ERR,"Mutex Unlock: %s",strerror(errno));
                            goto unlock_mutex;
                        }
                        break;
                    }
                }
                buffer_length += recv_bytes;
                thread_params->thread_type = recv_t;
                break;
            
            case accept_t:
            	break;
            case join_t:
            	break;
        }
    }
    close_filefd: close(file_fd);
    unlock_mutex: pthread_mutex_unlock(&s_data.mutex);
    free_mem: free(buffer);
    free_socket_fd: close(thread_params->fd);
                    thread_params->thread_completed = true;
                    syslog(LOG_DEBUG,"Closed connection from %s",thread_params->ip_addr);
                    return 0;
}



int main(int argc,char **argv)
{
	init_socket();
	init_queue();
	bool d_arg = false;
	thread_type_t thread_type;
	if(argc>1)
	{
		if(strcmp(argv[1],"-d") == 0)
		{
			d_arg = true;
		}
	}
	int status=0,yes=1;
	struct addrinfo hints;
	struct addrinfo *p = NULL;
	char s[INET6_ADDRSTRLEN];
	memset(s,0,sizeof(s));
	struct sockaddr_storage c;
	socklen_t addr_size = sizeof(c);
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCKET_TYPE;
	hints.ai_flags = AI_PASSIVE;

    	status = getaddrinfo(NULL, PORT, &hints, &s_data.host_addr_info);
    	if(status != 0)
	{
		syslog(LOG_ERR, "getaddrinfo error = %d\n",errno);
		fprintf(stderr, "getaddrinfo error: %d\n", errno);
		return -1;
	}
    	s_data.free_address_info = true;

	for(p = s_data.host_addr_info; p != NULL; p = p->ai_next) 
	{
		s_data.serverfd = socket(p->ai_family, p->ai_socktype,p->ai_protocol);
		if(s_data.serverfd == -1)
		{
			syslog(LOG_ERR, "socket error = %d\n",errno);
			fprintf(stderr, "socket error: %d\n", errno);
			continue;
		}
		s_data.free_serverfd = true;
		status = setsockopt(s_data.serverfd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
		if(status == -1)
		{
			syslog(LOG_ERR, "setsockopt error = %d\n",errno);
			fprintf(stderr, "setsockopt error: %d\n", errno);
			return -1;
		}
		status = bind(s_data.serverfd,p->ai_addr, p->ai_addrlen);
		if(status == -1)
		{
			syslog(LOG_ERR, "bind error = %d\n",errno);
			fprintf(stderr, "bind error: %d\n", errno);
			close(s_data.serverfd);
			continue;
		}
		break;
	}
	if(p == NULL)
	{
		fprintf(stderr, "server error\n");
		return -1;
	}
    
    
    	freeaddrinfo(s_data.host_addr_info);
    	s_data.free_address_info = false;

	if(d_arg)
	{
		pid_t pid;
		pid = fork();
		if (pid == -1)
		{
		    syslog(LOG_ERR, "fork error = %d\n",errno);
		    fprintf(stderr, "fork error: %d\n", errno);
		    return -1;
		}
		else if (pid != 0)
		{
		    exit(0);
		}
		else
		{
		    status = setsid();	
		    if(status==-1)
		    {
			syslog(LOG_ERR, "setsid error = %d\n",errno);
		    	fprintf(stderr, "setsid error: %d\n", errno);
			return -1;
		    }
		    status = chdir("/");
		    if(status == -1)
		    {
			syslog(LOG_ERR, "chdir error = %d\n",errno);
		    	fprintf(stderr, "chdir error: %d\n", errno);
			return -1;
		    }
		    close(STDIN_FILENO);
		    close(STDOUT_FILENO);
		    close(STDERR_FILENO);
		    open ("/dev/null", O_RDWR);
		    dup (0);
		    dup (0);
		}
	}
	status = listen(s_data.serverfd,MAX_CONNECTIONS_ON_INCOMING_QUEUE);
	if(status == -1)
	{
		syslog(LOG_ERR, "listen error = %d\n",errno);
		fprintf(stderr, "listen error: %d\n", errno);
		return -1;
	}
	status = register_signal(SIGINT);
	if(status == -1)
	{
		return -1;
	}
	status = register_signal(SIGTERM);
	if(status == -1)
	{
		return -1;        
	}
	status = register_signal(SIGALRM);
	if(status == -1)
	{
		return -1;          
	}

	status = timer_create(CLOCK_REALTIME, NULL, &s_data.timer);
	if(status == -1)
	{
		perror("Create timer");
		return -1;
	}
	s_data.itime.it_interval.tv_sec = 10;
	s_data.itime.it_interval.tv_nsec = 0;
	s_data.itime.it_value.tv_sec = 10;
	s_data.itime.it_value.tv_nsec = 0;
	status = timer_settime(s_data.timer, 0, &s_data.itime,NULL);
	if(status == -1)
	{
		perror("Set timer");
		return -1;
	}
	
	s_data.disarm_alarm = true;
	head_t head;
	TAILQ_INIT(&head);

	if(s_data.trigger)
	{
		thread_type = join_t;
	}
	else
	{
		thread_type = accept_t;
	}
    
    	int acceptfd;
    while(1)
    {
        switch(thread_type)
        {
            case accept_t:
                
                acceptfd = accept(s_data.serverfd,(struct sockaddr*)&c,&addr_size);
                if(acceptfd == -1)
                {   
			syslog(LOG_ERR, "accept error = %d\n",errno);
			fprintf(stderr, "accept error: %d\n", errno);
			thread_type = join_t;
			break;
                }                    
                inet_ntop(c.ss_family, get_in_addr((struct sockaddr *)&c), s, sizeof(s));
                syslog(LOG_DEBUG,"Accepted connection from %s\n", s);
                node_t *node = NULL;
                node = malloc(sizeof(node_t));
                if(node == NULL)
                {
			syslog(LOG_ERR, "malloc error = %d\n",errno);
			fprintf(stderr, "malloc error: %d\n", errno);
			thread_type = join_t;
			break;
                }
                node->thread_completed = false;
                node->thread_type = recv_t;
                node->fd = acceptfd;
                strcpy(node->ip_addr,s);
                status = pthread_create(&node->thread_id, (void*)0, threadfunc, node);
                if(status !=0)
                {
			free(node);
			syslog(LOG_ERR, "malloc error = %d\n",errno);
			fprintf(stderr, "malloc error: %d\n", errno);
			thread_type = join_t;
			break;
                }   
                TAILQ_INSERT_TAIL(&head, node, nodes);
                s_data.connection_count++;
                node = NULL;
                thread_type = join_t;
                break;
               
            case join_t:
                if(s_data.connection_count>0)
                {
                    node_t *var = NULL;
                    node_t *tvar = NULL;
                    TAILQ_FOREACH_SAFE(var,&head,nodes,tvar)
                    {
                        if(var->thread_completed)
                        {
                            TAILQ_REMOVE(&head, var, nodes);
                            pthread_join(var->thread_id,NULL);
                            free(var);
                            var = NULL;
                            s_data.connection_count--;
                        }
                    }
                }
                if(s_data.connection_count==0)
                {
                    char time_val_buf[80];
                    if(dequeue(time_val_buf)==0)
                    {
                        status = pthread_mutex_trylock(&s_data.mutex);
                        if(status == 0)
                        {
                            int fd = open(FILE_PATH,O_WRONLY|O_CREAT|O_APPEND,S_IRWXU|S_IRWXG|S_IRWXO);
                            if(fd != -1)
                            {
                                printf("File desc %d\n",fd);
                                write_data(fd,time_val_buf,strlen(time_val_buf));
                                close(fd);
                            }
                            pthread_mutex_unlock(&s_data.mutex);
                        }
                    }
                }
                if(s_data.trigger)
                {
                    if(s_data.connection_count==0)
                    {
                        shutdown_function();
                    }
                    else
                    {
                        break;
                    }
                }
                thread_type = accept_t;
                break;
            case send_t:
            	break;
            case recv_t:
            	break; 
        }    
    }
}

