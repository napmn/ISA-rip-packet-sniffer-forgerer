#include <stdio.h>
#include <signal.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // for getopt
#include <iostream>
#include <arpa/inet.h>
#include <iomanip>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/udp.h>   // declarations for udp header
#include <netinet/ip.h> //declarations for ip header
#include <netinet/ip6.h> // declarations for ipv6 header


#define IP6_HEADER_LEN 40
#define UDP_HEADER_LEN 8

// structure of rip entry, works for RIPv1 and RIPv2
struct rip_entry {
    u_int16_t family;
    u_int16_t route_tag;
    struct in_addr addr;
    struct in_addr mask;
    struct in_addr next_hop;
    u_int32_t metric;
};

// structure of RIPng entry
struct ripng_entry {
    struct in6_addr prefix;
    u_int16_t route_tag;
    u_char prefix_len;
    u_char metric;
};

/*
 * Function parses input arguments of the program. Returns name of the interface
 * if present or prints error message otherwise.
 */ 
char *parse_args(int argc, char *argv[]);


/*
 * Callback function that is triggered when pcap loop sniffs packet.
 * Funtion finds out version of IP protocol and call parsing functions for
 * RIP or RIPng accordingly.
 */
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);


/*
 * Callback function to be called with SIGINT signal. Closes the device handle
 * for sniffing if its opened and exits the program with return code 0.
 */
void exit_handler(int s);


/* Function sets up handler for SIGINT signal */
void setup_sigint_handler();


/*
 * Function opens device with name given as first parameter for sniffind.
 * global variable 'handle' is set as handle to this device.
 */
void open_device(char *dev_name, char *err_buff);


/* Compiles filter for sniffing packets on handle. */
void compile_filter(pcap_t *handle, bpf_program *f_expr, char *expr, bpf_u_int32 net_addr);

/* Sets filter for sniffing packets on handle. */
void set_filter(pcap_t *handle, bpf_program f_expr);


/*
 * Function parses packet and extract data from ethernet header, IP header,
 * UDP header and RIPng payload. Then prints this data to stdout in user
 * friendly form.
 */
void process_ripng(const u_char *buff, int size);


/*
 * Function parses packet and extract data from ethernet header, IP header,
 * UDP header and RIP(v1 / v2) payload. Then prints this data to stdout in user
 * friendly form.
 */
void process_rip(const u_char *buff, int size);


/*
 * Function parses ethernet header from the buffer and outputs
 * source and destination address.
 */
void print_mac_addresses(const u_char *buff);


/* Prints to stdout RIPng command by given value of command. */
void print_ripng_command(int command);


/* Prints to stdout RIP(v1 / v2) command by given value of command. */
void print_rip_command(int command);


/* Parse RIPv2 payload and print its contents in user friendly form */
void print_ripv2_data(u_char *payload, u_int16_t len);


/* Check if rip payload is valid by its length */
int is_rip_valid(int len);


/* Parse RIPv1 payload and print its contents in user friendly form */
void print_ripv1_data(u_char *payload, u_int16_t len);

/* Parse RIPng payload and print its contents in user friendly form */
void print_ripng_data(u_char *payload, u_int16_t len);