#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <netdb.h>

 
#include "dns_handle.h"
#include "dns_svr.h"

#define BUFFER 1024


int main(int argc, char* argv[]) {

    // time log
    time_t timer;
    char time_buf[BUFFER];


    // logfile
    FILE* log = fopen("dns_svr.log", "w");

    // open file and read header size hint
    // int fd = open("packets/1.comp30023.req.raw", O_RDONLY);
    struct packet packet;
    // struct qr_bin bin;
    unsigned char *buf = malloc(sizeof(unsigned char)*BUFFER);
    uint16_t size = 0;

    // two sockets for communicating with client and upstream server
    int upfd, serverfd, newfd, n, n_sum;
    struct sockaddr_in serv_addr;

    serverfd = init_socket(8053);
    // upfd = init_client(atoi(argv[2]), argv[1], &serv_addr);

    printf("server set up\n");
    if (listen(serverfd, 1) < 0) {
        perror("listen");
        exit(1);
    }
    printf("start listen. Entering loop...\n----------\n");

    while(1) 
    {
        buf = calloc(BUFFER,sizeof(unsigned char));
        newfd = accept(serverfd, NULL, NULL);
        n = read(newfd, buf, BUFFER);
        memcpy(&size, buf, 2);
        size = ntohs(size);

        n_sum = n;
        while (n_sum < size)
        {
            n = read(newfd, buf+n_sum, BUFFER - n_sum);
            n_sum += n;
        }

        printf("connecting to upstream...\n");
        upfd = init_client(atoi(argv[2]), argv[1], &serv_addr);
        if (connect(upfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) <
			0) {
			perror("connect");
			exit(EXIT_FAILURE);
		}

        // parse the received packet
        printf("packet received. Parsing.\n");
        printf("packet length=%d \n",size);

        parse(&packet, buf+2, size);

        // logs request accepted
        printf("Message parsed. Size hint=%d\n", size);

        time(&timer);
        strftime(time_buf, sizeof(time_buf), "%FT%T%z", localtime(&timer));    
        fprintf(log, "%s requested %s\n", time_buf, packet.question.name);
        fflush(log);
        printf("id=%d\n", ntohs(packet.header.id));
        printf("quesiton=%s\n", packet.question.name);
        printf("query type=%d\n", ntohs(packet.question.type));

        // if query is not AAAA, respond error code and close connection
        if (ntohs(packet.question.type) != 28)
        {
            printf("not supported\n");

            // attempt to update QR and rcode on a buffer then write back
            uint16_t temp;
            memcpy(&temp, buf+4, sizeof(uint16_t));
            // temp = ntohs(80);

            // temp ^= 1 << 7;  // rcode
            // temp ^= 1 << 10; // recursion
            // temp ^= 1 << 15; // qr bit

            // memcpy(buf+4, &temp, sizeof(uint16_t));
            buf[4] ^= 1 << 7;
            buf[5] ^= 1 << 2;
            buf[5] ^= 1 << 7;

            write(newfd, buf, size + 2);

            // logs the logfile and close connection
            time(&timer);
            strftime(time_buf, sizeof(time_buf), "%FT%T%z", localtime(&timer));
            fprintf(log, "%s unimplemented request\n", time_buf);
            fflush(log);

            close(newfd);
            close(upfd);
            continue;
        }

        // query is AAAA, proceed to upstream communication
        printf("passing up to upstream...\n");

        // send packet without size hint
        write(upfd, buf+2, n_sum - 2);
        
        // reset buffer
        buf = calloc(BUFFER,sizeof(unsigned char));
        // reads response. Keep reading until something comes in
        n = read(upfd, buf+2, BUFFER - 2);
        
        n_sum = n;
        while (n_sum == 0){
            n = read(upfd, buf+2, BUFFER - 2);
            n_sum += n;
        }

        // parse the packet
        size = htons(n_sum);
        memcpy(buf, &size, 2);
        printf("size: %d\n", size);
        parse(&packet, buf+2, size);

        printf("id=%d\n", ntohs(packet.header.id));
        printf("quesiton=%s\n", packet.question.name);
        char ipv6[INET6_ADDRSTRLEN];
        printf("%s\n", inet_ntop(AF_INET6, &(packet.response.addr), ipv6, sizeof(ipv6)));

        // log response if type is AAAA
        if (ntohs(packet.response.type) == 28){
            time(&timer);
            strftime(time_buf, sizeof(time_buf), "%FT%T%z", localtime(&timer));
            fprintf(log, "%s %s is at %s\n", time_buf, packet.question.name, 
                    inet_ntop(AF_INET6, &(packet.response.addr), ipv6, sizeof(ipv6)));
            fflush(log);
        }
        
        // write back to client and close connections
        write(newfd, buf, n_sum + 2);
        printf("closing connection...\n\n");
        close(newfd);
        close(upfd);
    }
    return 0;
}


// socket init basically copied from practical 9
int init_socket(int port)
{
	int sockfd;
	struct sockaddr_in serv_addr;

	/* Create socket */
	sockfd = socket(PF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	/* Create listen address for given port number (in network byte order)
	for all IP addresses of this machine */
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);

	/* Reuse port if possible */
	int re = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int)) < 0) {
		perror("Could not reopen socket");
		exit(EXIT_FAILURE);
	}

	/* Bind address to socket */
	if (bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	return sockfd;

}

// upstream socket init basically from lab 9, but creates a UDP socket
int init_client(const int port, const char* server_name,
						struct sockaddr_in* serv_addr) {
	int sockfd;
	struct hostent* server;

	server = gethostbyname(server_name);
	if (!server) {
		fprintf(stderr, "ERROR, no such host\n");
		exit(EXIT_FAILURE);
	}
	bzero((char*)serv_addr, sizeof(serv_addr));
	serv_addr->sin_family = AF_INET;
	bcopy(server->h_addr_list[0], (char*)&serv_addr->sin_addr.s_addr,
		  server->h_length);
	serv_addr->sin_port = htons(port);

	/* Create datagram socket */
	sockfd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

// utility function to check bit content
void printBits(uint16_t num)
{
   for(int bit=0;bit<(sizeof(uint16_t) * 8); bit++)
   {
      printf("%i ", num & 0x01);
      num = num >> 1;
   }
   printf("\n");
}
