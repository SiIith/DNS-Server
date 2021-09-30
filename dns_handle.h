#define HEADER_SIZE 12
/*
format of dns header described in https://routley.io/posts/hand-writing-dns-messages/
*/
struct __attribute__((__packed__)) dns_header
{
	uint16_t id; // 2 bytes
	uint16_t qr:1; // 1 bit QR
	uint16_t opcode:4; // 4 bit opcode
	uint16_t aa:1; // 1 bit what is this
	uint16_t tc:1; // 1 bit tc
	uint16_t rd:1; // 1 bit rd
	uint16_t ra:1;  // 4 bit what is this irrelevant field
	uint16_t z:3;
	uint16_t rcode:4; // 4 bit rcode
	uint16_t qd; // number of questions
	uint16_t an; // number of answers
	uint16_t ns; // authority
	uint16_t ar; // additional
};

/*
bins the 2-byte field to extract information of QR to RCODE.
Not used. 
 */
struct qr_bin
{
	uint8_t qr:1; // 1 bit QR
	uint8_t opcode:4; // 4 bit opcode
	uint8_t aa:1; // 1 bit what is this
	uint8_t tc:1; // 1 bit tc
	uint8_t rd:1; // 1 bit rd
	uint8_t ra:1;  // 4 bit what is this irrelevant field
	uint8_t z:3;
	uint8_t rcode:4; // 4 bit rcode
};

/* 
stores question of packet
 */
struct question
{
	char* name;
	uint16_t type;
	uint16_t class;
	
};

/* 
stores response of packet
 */
struct response
{
	uint16_t name; // 4 byte name
	uint16_t type; // 4 byte type
	uint16_t class; // 4 byte class
	uint32_t ttl; // 8 byte time to live for this response
	uint16_t rd; // 4 byte length sepcifier of rddata
	struct in6_addr addr; // ipv6
};

/* 
dns packet information
 */
struct packet
{
	struct dns_header header;
	int ptr; // pointer to traverse the packet
	char* data; // data AFTER the header
	struct question question;
	struct response response;
	char* ar; // additional record covering to end of message
};

void parse(struct packet* pack, unsigned char* data, int size);