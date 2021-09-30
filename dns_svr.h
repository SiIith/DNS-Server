
struct server_config
{
    char* host;
    int port;
    int fd;

};

int init_socket(int port);
int init_config(char* ipv4, int port, struct server_config* config);
int init_client(const int port, const char* server_name, struct sockaddr_in* serv_addr);
void printBits(uint16_t num);
