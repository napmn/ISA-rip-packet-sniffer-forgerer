/*************************************************
 *                 RIP Response                  *
 *                                               *
 * Author: Lukas Letovanec                       *
 * Login : xletov00                              *
 * Date  : 18/11/2018                            * 
*************************************************/

#include "myripresponse.hpp"


using namespace std;


char *dev_name = NULL; // device name
char *ip_addr = NULL;  // ipv6 address with mask in decimal
int rip_metric = 1; // metric
char const *next_hop_addr = "::"; // next hop address
u_int16_t router_tag_val = 0; // route tag


main(int argc, char *argv[])
{
    int sockfd; // socket descriptor
    struct sockaddr_in6 sin6;
    char addr[INET6_ADDRSTRLEN];
    struct sockaddr_in6 dest_addr;
    struct ripmsg data; // rip data

    // parse input arguments
    parse_args(argc, argv);
    if ((!dev_name) || (!ip_addr)) {  // device name and ip address are required
        cerr << "Arguments device name and ip address are required." << endl;
        exit(FAIL);
    }

    // parse ipv6 address and netmask mask
    struct ipv6_addr_mask ip_mask =  parse_addr_and_mask(ip_addr);

    memset(&sin6, 0, sizeof(sin6));
    sin6 = get_linklocal_address(dev_name);
    sin6.sin6_port = htons(521);

    if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        cerr << "Could not open socket." << endl;
        exit(FAIL);
    }
    cout << "Socket opened..." << endl;
    
    set_sock_opt_and_bind(sockfd, &sin6);
    
    // initialize source structure for socket
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin6_port = htons(521);
    dest_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "FF02::9", &dest_addr.sin6_addr);
    dest_addr.sin6_scope_id = sin6.sin6_scope_id;

    // intialize rip packet to be sent
    data.command = 2;
    data.version = 1;
    data.reserved[0] = 0;
    data.reserved[1] = 0;
    inet_pton(AF_INET6, next_hop_addr, &(data.next_hop.prefix));
    data.next_hop.metric = 255;
    data.next_hop.route_tag = 0;
    data.next_hop.prefix_len = 0;
    inet_pton(AF_INET6, ip_mask.addr, &(data.entry.prefix));
    data.entry.metric = rip_metric;
    data.entry.route_tag = htons(router_tag_val);
    data.entry.prefix_len = ip_mask.mask;

    // send packet
    if ((sendto(sockfd, &data, sizeof(data), 0,(struct sockaddr *)&dest_addr, sizeof(dest_addr))) == -1) {
        cerr << "could not send packet" << endl;
        cerr << strerror(errno) << endl;
        close(sockfd);
        exit(FAIL);
    }
    cout << "Packet sent..." << endl;

    close(sockfd);
    cout << "Socket closed..." << endl;
  
    return 0;
}

ipv6_addr_mask parse_addr_and_mask(char *ip_with_mask) {
    char *ip = strsep(&ip_with_mask, "/");
    struct ipv6_addr_mask ip_and_mask;
    ip_and_mask.addr = ip;
    char *mask_err = NULL;
    if (ip_with_mask == NULL) {
        cerr << "Missing netmask" << endl;
        exit(FAIL);
    }
    int mask = (int)(strtol(ip_with_mask, &mask_err, 10));
    if (*mask_err != '\0') {
        cerr << "Wrong format of netmask" << endl;
        exit(FAIL);
    }
    ip_and_mask.mask = mask;
    return ip_and_mask;
}


void set_sock_opt_and_bind(int sockfd, struct sockaddr_in6 *sin6) {
    int hops = 255;
    if ((setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops))) == -1) {
        cerr << "Could not set socket options." << endl;
        close(sockfd);
        exit(FAIL);
    }
    
    if ((bind(sockfd,(struct sockaddr *)sin6, sizeof(*sin6)) == -1)) {
        cerr << "Could not bind to socket." << endl;
        close(sockfd);
        exit(FAIL);
    }
    
    cout << "Bind successfull" << endl;
}

sockaddr_in6 get_linklocal_address(char *device_name) {
    struct ifaddrs *ifaddr, *ifa;
    struct sockaddr_in6 linklocal_addr;
    memset(&linklocal_addr, 0, sizeof(sockaddr_in6));
    int linklocal_found = 0;

    if (getifaddrs(&ifaddr) == -1) {
        cerr << "Could not get interfaces descriptions" << endl;
        exit(FAIL);
    }

    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) { // iterate through interfaces
        if (strcmp(dev_name, ifa->ifa_name) != 0) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *current_addr = (struct sockaddr_in6 *)ifa->ifa_addr;
            if (IN6_IS_ADDR_LINKLOCAL(&(current_addr->sin6_addr))) { // find if its linklocal address
                linklocal_addr = *current_addr;
                linklocal_found = 1;
                break;
            }
        } 
    }
    freeifaddrs(ifaddr); // free ifaddrs

    if (linklocal_found == 0) {
        cerr << "Could not find linklocal address for interface " << device_name << endl;
        exit(FAIL);
    }
    return linklocal_addr;
}


void parse_args(int argc, char *argv[]) {
    int c = 0;
    char *metric_err = NULL;
    char *tag_err = NULL;

    while((c = getopt(argc, argv, "i:r:n:m:t:")) != -1) {
        switch(c) {
            case 'i':
                dev_name = optarg;
                break;
            case 'r':
                ip_addr = optarg;
                break;
            case 'm':
                rip_metric = (int)(strtol(optarg, &metric_err, 10));
                break;
            case 'n':
                next_hop_addr = optarg;
                break;
            case 't':
                router_tag_val = (u_int16_t)(strtol(optarg, &tag_err, 10));
                break;
            case '?':
                if ((optopt == 'i') || (optopt == 'r') || (optopt == 'm')
                    || (optopt == 'n') || (optopt == 't')) {
                    cerr << "Option -" << (char)optopt << " requires an argument" << endl;
                    exit(FAIL);
                } else {
                    cerr << "Unknown option -" << (char)optopt << endl;
                    exit(FAIL);
                }
       }
    }
    if (metric_err != NULL || tag_err != NULL) {
        if (*metric_err != '\0' || *tag_err != '\0') {
            cerr << "Invalid value in one of the arguments (metric, router tag)" << endl;
            exit(FAIL);
        }
    }
}
