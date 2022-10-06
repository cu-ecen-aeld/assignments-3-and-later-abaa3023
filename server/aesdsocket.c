// reference: Beej's guide to network programming

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
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>



/*
 * Macros
 */
#define PORT 9000 
#define BUFFER_STD_SIZE 256
#define MAX_CONNECTIONS_ON_INCOMING_QUEUE 10
#define SEND_FLAGS 0
#define RECV_FLAGS 0
#define FILE_PATH "/var/tmp/aesdsocketdata"
#define MAX_BUF_SIZE 1000
#define SOCKET_DOMAIN AF_INET
#define SOCKET_TYPE SOCK_STREAM
#define SOCKET_PROTOCOL 0



/*
 * Global variables
 */
int filefd, serverfd;
pid_t pid;
bool d_arg = false;



/* 
 * Signal Handlers
 */
void signal_handler(int signo)
{
	if(signo == SIGINT || signo == SIGTERM)
	{
		close(filefd);
        	close(serverfd);
		remove(FILE_PATH);
		syslog(LOG_ERR, "Caught signal, exiting");
		exit(-1);
	}
}



//void *get_in_addr(struct sockaddr *sa)
//{
//	if(sa->sa_family == AF_INET)
//	{
//		return &(((struct sockaddr_in*)sa)->sin_addr);
//	}
	
//	return &(((struct sockaddr_in6*)sa)->sin6_addr);
//}



/* 
 * Application entry
 */
int main(int argc, char **argv)
{
	// local variables
	char *write_packet, *read_packet, server_buf[MAX_BUF_SIZE];
	struct sockaddr_in s, c;
	int status, recv_bytes, acceptfd, max_buf_size, saved_bytes, send_bytes = 0, read_bytes = 0;
    	socklen_t addr_size;
	
	
	// signals
	if(signal(SIGINT, signal_handler) == SIG_ERR)
	{
		fprintf(stderr, "Cannot hande SIGINT! \n");
		exit(-1);
	}
	
	if(signal(SIGTERM, signal_handler) == SIG_ERR)
   	{
		fprintf(stderr, "Cannot hande SIGTERM! \n");
		exit(-1);
   	}
	
	

    	// first, load up address sructs with getaddrinfo()
	//memset(&hints, 0, sizeof hints);
	//hints.ai_family = AF_UNSPEC; // use IPV4 or IPV6
	//hints.ai_socktype = SOCK_STREAM; 
	//hints.ai_flags = AI_PASSIVE; // fill in my IP for me
	
	
	
	//status = getaddrinfo(NULL, PORT, &hints, &servinfo);
	//if(status != 0)
	//{
	//	syslog(LOG_ERR, "getaddrinfo error = %d\n",status);
	//	fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
	//	exit(-1);
	//}
	//else
	//{
	//	syslog(LOG_DEBUG, "getaddrinfo success\n");
	//}
	
	
	
	// loop through all the results and bind to the first we can
	//for(p = servinfo; p != NULL; p = p->ai_next)
	//{
    	serverfd = socket(SOCKET_DOMAIN , SOCKET_TYPE, SOCKET_PROTOCOL);
    	if(serverfd == -1)
	{
		syslog(LOG_ERR, "socket error = %d\n",errno);
		fprintf(stderr, "socket error: %d\n", errno);
		exit(-1);
	}
	else
	{
		syslog(LOG_DEBUG, "socket success\n");
	}	

	//status = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	//if(status == -1)
	//{
	//	syslog(LOG_ERR, "setsockopt error = %d\n",errno);
	//	fprintf(stderr, "setsockopt error: %d\n", errno);
	//	continue;
	//}
	//else
	//{
	//	syslog(LOG_DEBUG, "setsockopt success\n");
	//}

	// bind it to the port we passed in to getaddrinfo()	

    	s.sin_addr.s_addr = INADDR_ANY;
    	s.sin_family = AF_INET;
    	s.sin_port = htons(PORT);

   	status = bind(serverfd , (struct sockaddr_in *)&s , sizeof(struct sockaddr_in));

	if(status == -1)
	{
		syslog(LOG_ERR, "bind error = %d\n",errno);
		fprintf(stderr, "bind error: %d\n", errno);
		exit(-1);
	}
	else
	{
		syslog(LOG_DEBUG, "bind success\n");
	}
	//	break;
	//}
		
	//freeaddrinfo(servinfo);
	
	//if(p == NULL)
	//{
	//	fprintf(stderr, "server: failed to bind\n");
	//	exit(-1);
	//}


    	if(argc>1)
	{
		if(strcmp(argv[1],"-d") == 0)
		{
			d_arg = true;
		}
	}

	//if(!fork())
	//{
		//close(sockfd);
	//	status = recv(fd, buf, RX_MAX_LEN, RECV_FLAGS);
	//	if(status == -1)
	//	{
	//		syslog(LOG_ERR, "recv error = %d\n",errno);
	//		fprintf(stderr, "recv error: %d\n", errno);
	//		exit(-1);
	//	}
	//	else
	//	{
	//		for(int i=0; i<strlen(buf);i++)
	//		{
				//if(buf[i]!='\n')
				//{
					//writefd = open(FILE_PATH, O_RDWR | O_CREAT | O_APPEND, S_IRWXU | S_IRWXG | S_IRWXO);
	//				if(writefd == -1)
	//				{
	//					syslog(LOG_ERR, "Error %d while opening file\n", errno);
	//					exit(-1);
	//				}
	//				else
	//				{
	//					syslog(LOG_DEBUG, "Open successful\n");
	//				}
					
	//				status = write(writefd, &buf[i], 1);
	//				if(status == -1)
	//				{
	//					syslog(LOG_ERR, "write error = %d\n",errno);
	//					fprintf(stderr, "write error: %d\n", errno);
	//					exit(-1);
	//				}
	//				else
	//				{
	//					syslog(LOG_DEBUG, "write success\n");
	//				}
				//}
				//else
				//{
				//	fprintf(writefd, "\n");
				//}
	//		}
	//		syslog(LOG_DEBUG, "recv success\n");
	//	}
	//}
		
	//if(!fork())
	//{
	//	close(sockfd); //child doesn't need listener
	//	status = send(fd, buf, RX_MAX_LEN, RECV_FLAGS);
	//	if(status == -1)
	//	{
	//		syslog(LOG_ERR, "send error = %d\n",errno);
	//		fprintf(stderr, "send error: %d\n", errno);
	//		continue;
	//	}
	//	else
	//	{
	//		syslog(LOG_DEBUG, "send success\n");
	//		close(fd);
	//	}
	//}
	//close(fd);
	// above commented is the one I had tried reference: Beej's guide
	// seeked help from Dhiraj for daemon process part
    	if(d_arg)
	{
		pid = fork();
		if(pid == -1)
		{
			syslog(LOG_ERR, "fork error = %d\n",errno);
			fprintf(stderr, "fork error: %d\n", errno);
			return -1;
		}
		else if(pid != 0)
		{
			exit(0);
		}
		
		status = setsid();
		if(status == -1)
		{
			syslog(LOG_ERR, "setsid error = %d\n",errno);
			fprintf(stderr, "setsid error: %d\n", errno);
			return -1;
		}
		else
		{
			syslog(LOG_DEBUG, "setsid success\n");
		}
		
		status = chdir("/");
		if(status == -1)
		{
			syslog(LOG_ERR, "chdir error = %d\n",errno);
			fprintf(stderr, "chdir error: %d\n", errno);
			return -1;
		}
		
		open("/dev/null", O_RDWR);
		dup(0);
		dup(0);
	}

    	status = listen(serverfd, MAX_CONNECTIONS_ON_INCOMING_QUEUE);
	if(status == -1)
	{
		syslog(LOG_ERR, "listen error = %d\n",errno);
		fprintf(stderr, "listen error: %d\n", errno);
		//exit(-1);
	}
	else
	{
		syslog(LOG_DEBUG, "listen success\n");
	}
	
	//sa.sa_handler = sigchld_handler; // reap all dead processes
	//sigemptyset(&sa.sa_mask);
	//sa.sa_flags = SA_RESTART;
	
	//status = sigaction(SIGCHLD, &sa, NULL);
	//if(status == -1)
	//{
	//	syslog(LOG_ERR, "sigaction error = %d\n",errno);
	//	fprintf(stderr, "sigaction error: %d\n", errno);
	//	exit(-1);
	//}
	//else
	//{
	//	syslog(LOG_DEBUG, "sigaction success\n");
	//}
	
	//printf("server: waiting for connections...\n");

    filefd = open(FILE_PATH, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);

    while(1)
    {
        addr_size = sizeof(c);
        acceptfd = accept(serverfd, (struct sockaddr_in *) &c, &addr_size);
	if(acceptfd == -1)
	{
		syslog(LOG_ERR, "accept error = %d\n",errno);
		fprintf(stderr, "accept error: %d\n", errno);
		exit(-1);
	}
	else
	{
		syslog(LOG_DEBUG, "accept success\n");
		syslog(LOG_DEBUG, "Accepted connection from : %s\n", inet_ntoa(c.sin_addr));
	}
	
        max_buf_size = MAX_BUF_SIZE;
        saved_bytes = 0;


        write_packet = malloc(sizeof(char) * MAX_BUF_SIZE);

        bool packet_collected = false;
        while(!packet_collected)
        {
            recv_bytes = recv(acceptfd, server_buf, MAX_BUF_SIZE, RECV_FLAGS);

            if (recv_bytes == 0 || (strchr(server_buf, '\n') != NULL))
            {
                packet_collected = true;
            }

            if ((max_buf_size - saved_bytes) < recv_bytes)
            {
                max_buf_size += recv_bytes;
                write_packet = (char *) realloc(write_packet, sizeof(char) * max_buf_size);
            }

            memcpy(write_packet + saved_bytes, server_buf, recv_bytes);
            saved_bytes += recv_bytes;
        }

        write(filefd, write_packet, saved_bytes);
        lseek(filefd, 0, SEEK_SET);


        send_bytes += saved_bytes;

        read_packet = (char*)malloc(sizeof(char) * send_bytes);
        if(read_packet == NULL)
	{
		syslog(LOG_ERR, "malloc error = %d\n",errno);
		fprintf(stderr, "malloc error: %d\n", errno);
		exit(-1);
	}
	else
	{
		syslog(LOG_DEBUG, "malloc success\n");
	}

        read_bytes = read(filefd, read_packet, send_bytes);

        status = send(acceptfd, read_packet, read_bytes , SEND_FLAGS);
        if(status == -1)
	{
		syslog(LOG_ERR, "send error = %d\n",errno);
		fprintf(stderr, "send error: %d\n", errno);
		exit(-1);
	}
	else
	{
		syslog(LOG_DEBUG, "send success\n");
	}
	syslog(LOG_DEBUG, "Closed connection from : %s\n", inet_ntoa(c.sin_addr));
        free(read_packet);
        free(write_packet);
    }


    return 0;
}
