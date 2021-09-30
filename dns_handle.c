#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "dns_handle.h"

// parse a complete packet to extract data
void parse(struct packet* pack, unsigned char* buf, int size){
    // copy data from buffer to packet struct
    memcpy(&(pack->header), buf, HEADER_SIZE);
    pack->ptr = HEADER_SIZE; // set pointer to end of header
    pack->data = malloc(size - HEADER_SIZE);
    
    // parse the question part
    u_int8_t length = buf[(pack->ptr)]; // length of each label of url name. 1 byte in length
    int j = 0, i;
    pack->question.name = malloc(length + 1);

    // iteratively join the url labels together
    while (buf[pack->ptr]){
        
        for (i = 0; i < length; i++){
            pack->question.name[i+j] = buf[++(pack->ptr)];
        }
        if (buf[++(pack->ptr)])
        {
            pack->question.name = realloc(pack->question.name, length + buf[pack->ptr] + 2);
            length = buf[pack->ptr];
            pack->question.name[i + j] = '.';
            j += (i + 1);
        }
    }
    pack->question.name[j+i] = '\0';
    (pack->ptr)++;

    // parse question type and class
    memcpy(&(pack->question.type), buf + pack->ptr, sizeof(uint16_t));
    // pack->question.type = ntohs(pack->question.type);
    pack->ptr += 2;
    memcpy(&(pack->question.class), buf + pack->ptr, sizeof(uint16_t));
    // pack->question.class = ntohs(pack->question.class);
    pack->ptr += 2;

    // if the packet contains an answer, fill the response struct
    if (pack->header.an > 0)
    {
        memcpy(&(pack->response.name), buf + pack->ptr, sizeof(uint16_t));
        pack->ptr += 2;
        memcpy(&(pack->response.type), buf + pack->ptr, sizeof(uint16_t));
        pack->ptr += 2;
        memcpy(&(pack->response.class), buf + pack->ptr, sizeof(uint16_t));
        pack->ptr += 2;
        memcpy(&(pack->response.ttl), buf + pack->ptr, sizeof(uint32_t));
        pack->ptr += 4;
        memcpy(&(pack->response.rd), buf + pack->ptr, sizeof(uint16_t));
        pack->ptr += 2;
        // pack->response.rd = ntohs(pack->response.rd);
        memcpy(&(pack->response.addr), buf + pack->ptr, 16);
        pack->ptr += (ntohs(pack->response.rd));
    }

    if (pack->header.ar > 0){
        pack->ar = malloc(size - pack->ptr + 1);
        memcpy(&(pack->ar), buf + pack->ptr, sizeof(pack->ar));
    }

}
