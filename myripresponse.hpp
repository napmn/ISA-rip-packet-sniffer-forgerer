#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <iostream>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>


#define FAIL 1


// ripng entry structure
struct route_table_entry {
    struct in6_addr prefix;
    u_int16_t route_tag;
    u_char prefix_len;
    u_char metric;
};

// structure of simple ripng message with one new hop entry and one normal entry
struct ripmsg {
    u_char command;
    u_char version;
    u_char reserved[2];
    struct route_table_entry next_hop;
    struct route_table_entry entry;
};

// structure of ipv6 address with decimal mask
struct ipv6_addr_mask {
    char *addr;
    int mask;
};

/* 
 * Function parses input arguments of the program and fill global variables
 * with proper values. If the number of hops or router tag has non integer
 * value program exits with return code 1.
 */
void parse_args(int argc, char *argv[]);


/*
 * Function iterates through all available interfaces looking for the one with
 * same name as input parameter of the function. If the interface was found
 * function looks for its linklocal address. If present, this linklocal address
 * is returned. Program exits with error message otherwise.
 */ 
sockaddr_in6 get_linklocal_address(char *device_name);


/*
 * Function sets IPv6 multicast hops on socket file descriptor provided as first
 * parameter. Function also binds given socket to filled sockaddr_in6 structure
 * given as second parameter.
 * If any error occurs during the process, program ends with error message.
 */ 
void set_sock_opt_and_bind(int sockfd, struct sockaddr_in6 *sin6);


/*
 * Function parses string in format <IPv6>/[NETMASK] to structure ipv6_addr_mask.
 * This structure is then returned. Program end with error message if the format
 * of the input string is not supported
 */ 
ipv6_addr_mask parse_addr_and_mask(char *ip_with_mask);


