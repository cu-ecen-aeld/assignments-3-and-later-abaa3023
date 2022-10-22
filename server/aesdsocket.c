#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <sys/types.h>
#include <sys/times.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <sys/socket.h>

#define PORT					"9000"						
#define MAXDATALEN				1024							

#define USE_AESD_CHAR_DEVICE	1								
#if (USE_AESD_CHAR_DEVICE == 1)
#define LOG_FILE				"/dev/aesdchar"						
#else
#define LOG_FILE				"/var/tmp/aesdsocketdata"
#endif

static int fd_socket, fd_client, fd;
static struct addrinfo *res;
pthread_mutex_t w_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t thread, timethread;

typedef struct client_param{
	pthread_t thread_id;
	int client_fd;
	bool exec_flag;
}client_param_t;

typedef struct node{
	client_param_t thread_param;
	TAILQ_ENTRY(node) nodes;
}pnode_t;

typedef TAILQ_HEAD(head_s, node) head_t;
head_t ll_head;

pnode_t* _fill_queue(head_t * head, const pthread_t thread, const int c_fd)
{
	struct node * e = (struct node *)malloc(sizeof(struct node));
	if (e == NULL)
	{
		fprintf(stderr, "malloc failed");
		exit(EXIT_FAILURE);
	}
	e->thread_param.thread_id = thread;
	e->thread_param.client_fd = c_fd;
	e->thread_param.exec_flag = false;
	TAILQ_INSERT_TAIL(head, e, nodes);
	printf("%s: client fd: %d\n", __func__, e->thread_param.client_fd);
	e = NULL;
	return TAILQ_LAST(head, head_s);
}

void _free_queue(head_t * head)
{
    struct node * e = NULL;
    while (!TAILQ_EMPTY(head))
    {
        e = TAILQ_FIRST(head);
        TAILQ_REMOVE(head, e, nodes);
        free(e);
        e = NULL;
    }
}

static void sig_handler(int signo){
		syslog(LOG_DEBUG, "Caught signal,exiting");
		pnode_t *tmp = NULL;
		int ret = EXIT_SUCCESS, res;
		TAILQ_FOREACH(tmp, &ll_head, nodes){
			res = shutdown(tmp->thread_param.client_fd, SHUT_RDWR);
			if(res){
				syslog(LOG_ERR, "shutdown failed: %s", strerror(errno));
			}
			printf("killing thread id: %ld", tmp->thread_param.thread_id);
			res = pthread_kill(tmp->thread_param.thread_id, SIGKILL);
			if(res){
				syslog(LOG_ERR, "thread kill failed: %s", strerror(res));
				exit(EXIT_FAILURE);
			}
		}
		_free_queue(&ll_head);
		
		res = pthread_kill(thread, SIGKILL);
		if(res){
			syslog(LOG_ERR, "cleanup thread kill failed: %s", strerror(res));
			exit(EXIT_FAILURE);
		}

		res = pthread_kill(timethread, SIGKILL);
		if(res){
			syslog(LOG_ERR, "timestamp thread kill failed: %s", strerror(res));
			exit(EXIT_FAILURE);
		}
		
		pthread_mutex_destroy(&w_mutex);
		if(fd_socket>0){
			if (shutdown(fd_socket, SHUT_RDWR)){
				ret = EXIT_FAILURE;
				syslog(LOG_ERR, "shutdown socket: %s", strerror(errno));
			}
		}

		if(fd>0){
			if (close(fd)){
				ret = EXIT_FAILURE;
				syslog(LOG_ERR, "close file: %s", strerror(errno));
			}	
		}

		if (unlink(LOG_FILE)){
			ret = EXIT_FAILURE;
			syslog(LOG_ERR, "unlink file: %s", strerror(errno));
		}

		closelog();

		exit(ret);
}

void daemonize(void){
	pid_t pid;
	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	pid = fork();
	if(pid < 0){
		exit(EXIT_FAILURE);
	}
	if(pid > 0){
		exit(EXIT_SUCCESS);
	}
	if(setsid() == -1){
		exit(-1);
	}
	umask(0);
	if(chdir("/") == -1){
		exit(-1);
	}
	open("/dev/null", O_RDWR);						
	dup(0);
	dup(1);
	dup(2);
	close(0);
	close(1);
	close(2);
}

void *handle_cleanup(void *cleanup_arg){
	int ret;
	head_t *head = cleanup_arg;
	while(1){
		pnode_t *temp = NULL;
		TAILQ_FOREACH(temp, head, nodes){
			if(temp->thread_param.exec_flag){
				syslog(LOG_DEBUG, "Thread found dead %ld. Flag: %d", temp->thread_param.thread_id, temp->thread_param.exec_flag);
				printf("Thread found dead %lx. client fd: %d\n", temp->thread_param.thread_id, temp->thread_param.client_fd);

				shutdown(temp->thread_param.client_fd, SHUT_RDWR);

				ret = pthread_join(temp->thread_param.thread_id, NULL);
				if(ret != 0){
					syslog(LOG_ERR, "Thread join failed %s", strerror(ret));
					exit(EXIT_FAILURE);
				}
				temp->thread_param.exec_flag = false;
				TAILQ_REMOVE(head, temp, nodes);
				free(temp);
				break;
			}
		}
		usleep(10);
	}
	return NULL;
}

void *handle_Thread(void* pthread_arg){
	int size_recv, ret;
	client_param_t* thread_param_tmp = pthread_arg;
	char  buf[MAXDATALEN];
	char *pbuf = NULL;
	ssize_t remainingSpace = sizeof(buf);
	int pos = 0;

	pbuf = (char *)malloc(sizeof(char)*MAXDATALEN);
	if(buf == NULL){
		syslog(LOG_ERR, "malloc failed");
		exit(EXIT_FAILURE);
	}
	printf("Thread %ld in execution with client fd: %d\n", thread_param_tmp->thread_id, thread_param_tmp->client_fd);

	memset(buf, 0, sizeof(buf));
	
	ret = pthread_mutex_lock(&w_mutex);
	if(ret != 0){
		syslog(LOG_ERR, "Unable to lock %s", strerror(errno));
	}
	printf("mutex locked\n");
	fd = open(LOG_FILE, O_WRONLY);
	lseek(fd, 0, SEEK_END);
	while(1){
		size_recv = recv(thread_param_tmp->client_fd, buf, sizeof(buf), 0);
		if(size_recv == -1){
			printf("Error recv %s, client fd: %d, thread id: %lx\n", strerror(errno), thread_param_tmp->client_fd, thread_param_tmp->thread_id);
			syslog(LOG_ERR, "Error recv: %s", strerror(errno));
			ret = pthread_mutex_unlock(&w_mutex);
			if(ret != 0){
				syslog(LOG_ERR, "Unable to unlock %s", strerror(errno));
			}
			printf("mutex unlocked\n");
			pthread_exit(NULL);
		}

		if(size_recv > remainingSpace){
			pbuf = (char *)realloc(pbuf, sizeof(char)*(pos + MAXDATALEN));
			if(pbuf == NULL){
				syslog(LOG_ERR, "reallocation failed");
			}
			remainingSpace += remainingSpace;
		}
		memcpy(&pbuf[pos], buf, size_recv);
		pos += size_recv;
		remainingSpace -= size_recv;

		printf("%s\n", buf);
		if(buf[size_recv-1] == '\n'){
			break;
		}
	}

	ret = write(fd, pbuf, pos);
	if(ret == -1){
		syslog(LOG_ERR, "write failed: %s", strerror(errno));
		printf("write filed: %s\n", strerror(errno));
		ret = pthread_mutex_unlock(&w_mutex);
		if(ret != 0){
			syslog(LOG_ERR, "Unable to unlock %s", strerror(errno));
		}
		printf("mutex unlocked\n");
	}

	close(fd);
	memset(buf, 0, sizeof(buf));

	fd = open(LOG_FILE, O_RDONLY);
	while((ret = read(fd, buf, MAXDATALEN))){
		if(ret == -1){
			if(errno == EINTR){
				continue;
			}
			printf("Error read %s\n", strerror(errno));
			syslog(LOG_ERR, "Error read: %d", errno);
			pthread_exit(NULL);
		}
		ret = send(thread_param_tmp->client_fd, buf, ret, 0);
		if(ret == -1){
			syslog(LOG_ERR, "Error Send: %s", strerror(errno));
			pthread_exit(NULL);
		}
	}

	free(pbuf);
	thread_param_tmp->exec_flag = true;
	thread_param_tmp->client_fd = -1;
	close(fd);
	syslog(LOG_DEBUG, "Connection closed");
	printf("%s: connection closed\n", __func__);
	ret = pthread_mutex_unlock(&w_mutex);
	if(ret != 0){
		syslog(LOG_ERR, "Unable to unlock %s", strerror(errno));
	}
	printf("%s: mutex unlocked\n", __func__);
	return NULL;
}

#if (USE_AESD_CHAR_DEVICE == 1)
void *handle_timestamp(void *timer_arg){
	while(1){
		time_t time_ret;
		struct tm *tmp;
		char time_buf[100] = {0};
		char timestr_buf[200] = "timestamp:";

		time_ret = time(NULL);
		tmp = localtime(&time_ret);
		if(tmp == NULL){
			perror("localtime");
			exit(EXIT_FAILURE);
		}

		if(strftime(time_buf, sizeof(time_buf), "%a, %d %b %Y %T", tmp) == 0){
			syslog(LOG_ERR, "strftime error");
			exit(EXIT_FAILURE);
		}
		strcat(timestr_buf, time_buf);
		strcat(timestr_buf, " \n");

        int rt = pthread_mutex_lock(&w_mutex);
        if(rt){
            syslog(LOG_ERR, "Could not lock mutex\n\r");
            close(fd);
        }
		fd = open(LOG_FILE,O_RDWR | O_APPEND, 0766);
        if (fd < 0){
			syslog(LOG_ERR, "error opening file errno is %d\n\r", errno);
		}
        lseek(fd, 0, SEEK_END);

        int write_bytes = write(fd, timestr_buf, strlen(timestr_buf));
		syslog( LOG_INFO, "%s written to file\n", timestr_buf);
        printf("%s written to file\n", timestr_buf);

        if (write_bytes < 0){
            syslog(LOG_ERR, "Write of timestamp failed errno %d",errno);
            printf("Cannot write timestamp to file\n\r");
        }

		rt = pthread_mutex_unlock(&w_mutex);
        if(rt){
            syslog(LOG_ERR, "Could not lock mutex\n\r");
            close(fd);
        }
		close(fd);

		sleep(10);
	}
}
#endif

int main(int argc, char **argv){
	int yes = 1;
	int ret;
	struct addrinfo hints;
	char s[INET_ADDRSTRLEN];

	struct sockaddr_in peer_addr;
	socklen_t peer_addr_len = sizeof(peer_addr);
	
	// memset(buf, 0, sizeof(buf));
	memset(&hints, 0, sizeof(hints));					//Clear the hints datastructure

	//Setup syslog logging for the utility using LOG_USER
	openlog(NULL, 0, LOG_USER);

	//Configure SIGINT
	if(signal(SIGINT, sig_handler) == SIG_ERR){
		syslog(LOG_ERR, "Error: Cannot handle SIGINT");
		closelog();
		return -1;
	}
	//Configure SIGTERM
	if(signal(SIGTERM, sig_handler) == SIG_ERR){
		syslog(LOG_ERR, "Error: Cannot handle SIGINT");
		closelog();
		return -1;
	}
	
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_PASSIVE;						//Set the flag to make the socket suitable for bind
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(NULL, PORT, &hints, &res);		//The returned socket would be suitable for binding and accepting connections
	if(ret != 0){
		syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(errno));
		closelog();
		return -1;
	}
	
	//Creating an socket endpoint for communication using IPv4 by socket streaming
	fd_socket = socket(AF_INET, SOCK_STREAM, 0);
	if(fd_socket == -1){
		syslog(LOG_ERR, "Error opening socket: %d", errno);
		closelog();
		return -1;
	}

	printf("socket created, fd: %d\n", fd_socket);

	//Configure socket to reuse the address
	ret = setsockopt(fd_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	if(ret == -1){
		syslog(LOG_ERR, "Error setsockopt: %d", errno);
		closelog();
		return -1;
	}

	struct addrinfo *p;
	bool bind_flag = false;
	for(p=res; p!=NULL; p=p->ai_next){
		ret = bind(fd_socket, p->ai_addr, p->ai_addrlen);
		if(ret != 1){
			bind_flag = true;
			printf("binded\n");
			break;
		}
		close(fd_socket);
	}

	if(!bind_flag){
		printf("Error binding %s\n", strerror(errno));
		syslog(LOG_ERR, "Error bind: %d - %s", errno, strerror(errno));
		freeaddrinfo(res); 							// all done with this structure
		closelog();
		close(fd_socket);
		printf("Error binding %s\n", strerror(errno));
		return -1;
	}

	freeaddrinfo(res); 							// all done with this structure
	
	ret = listen(fd_socket, 10);
	if(ret == -1){
		printf("Error listening %s\n", strerror(errno));
		syslog(LOG_ERR, "Error listen: %d", errno);
		closelog();
		close(fd_socket);
		return -1;
	}
	printf("listening\n");

	remove(LOG_FILE);
	//Creating the file to store data over the socket
	fd = open(LOG_FILE, O_CREAT | O_RDWR | O_APPEND, 0644);
    if (fd == -1)
    {
        syslog(LOG_ERR, "open failed with error code: %s\n", strerror(fd));
        exit(EXIT_FAILURE);
    }

	//Daemonize after binded to port 9000
	if((argc == 2) && (strcmp("-d", argv[1]) == 0)){
		// daemonize();
		printf("Daemonizing\n");
		daemon(0,0);
	}

	//Initializing the Linked list
	TAILQ_INIT(&ll_head);

	//Creating thread for each connection
	ret = pthread_create(&thread, NULL, handle_cleanup, &ll_head);
	if(ret != 0){
		syslog(LOG_ERR, "Error: Thread create failed: %s", strerror(errno));
		closelog();
		close(fd_socket);
		return -1;
	}

#if (USE_AESD_CHAR_DEVICE == 1)
	ret = pthread_create(&timethread, NULL, handle_timestamp, NULL);
	if(ret != 0){
		syslog(LOG_ERR, "Error: Thread create failed: %s", strerror(errno));
		closelog();
		close(fd_socket);
		return -1;
	}
#endif

	while(1){											
		//accept loop to listen forever		
		fd_client = accept(fd_socket, (struct sockaddr *)&peer_addr, &peer_addr_len);
		if(fd_client == -1){
			printf("Error accept %s\n", strerror(errno));
			syslog(LOG_ERR, "Error accept: %d - %s", errno, strerror(errno));
			raise(SIGTERM);
			return -1;
		}

		//Review from here - Delete when reviewed
		inet_ntop(peer_addr.sin_family, &peer_addr.sin_addr, s, sizeof(s));
		printf("Connection accepted\n");
		syslog(LOG_DEBUG, "Accepted connection from %s", s);

		pnode_t *pNode = _fill_queue(&ll_head, 0, fd_client);
		//Create thread
		ret = pthread_create(&(pNode->thread_param.thread_id), NULL, handle_Thread, (void*)&pNode->thread_param);
		if(ret != 0){
			syslog(LOG_ERR, "Error: Thread create failed: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		// pNode->thread_param.thread_id = thread;			//Update the thread ID once created
		printf("thread created id: %lx and cfd: %d\n", pNode->thread_param.thread_id, fd_client);
	}

	//Close all while existing
	raise(SIGTERM);
	printf("Exiting the program \n");
	closelog();
	close(fd_client);
	close(fd_socket);
	return 0;
}
