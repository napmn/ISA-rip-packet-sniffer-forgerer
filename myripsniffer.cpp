/*************************************************
 *                 RIP Sniffer                   *
 *                                               *
 * Author: Lukas Letovanec                       *
 * Login : xletov00                              *
 * Date  : 18/11/2018                            * 
*************************************************/

#include "myripsniffer.hpp"


using namespace std;

pcap_t *handle = NULL; // handle of the device to be sniffed
long int packet_no = 0; // packet number

int main(int argc, char *argv[]) {
    bpf_u_int32 net_addr; // network address configured at the input device
    bpf_u_int32 mask; // network mask of the input device
    char err_buff[PCAP_ERRBUF_SIZE]; // error buff
    const u_char *packet; // sniffed packet
    struct pcap_pkthdr header; // packets header
    struct bpf_program f_expr; // compiled filter expression
    char expr[] = "(udp and port 521) or (udp and port 520)"; // filter expression 

    char *device_name = parse_args(argc, argv);  // parse arguments to get device name
    if (device_name == NULL) {
        cerr << "Wrong arguments." << endl;
        exit(1);
    }
    setup_sigint_handler(); // setup function to handle SIGINT signal
    cout << "Device name:\t" << device_name << endl;
    
    if (pcap_lookupnet(device_name, &net_addr, &mask, err_buff) == -1) {
        cerr << "Could not get IP address and mask of the sniffing interface" << endl;
        exit(1);
    }
    
    // open inteface for sniffing
    cout << "Opening device " << device_name << " for sniffing" << endl;
    open_device(device_name, err_buff);

    // compile filter for sniffing only RIP packets 
    compile_filter(handle, &f_expr, expr, net_addr);

    // set the filter
    set_filter(handle, f_expr);

    // infinite loop to sniff packets
    cout << "===================================================================" << endl;
    pcap_loop(handle, -1, process_packet, NULL);

    return 0;
}


void set_filter(pcap_t *handle, bpf_program f_expr) {
    if (pcap_setfilter(handle, &f_expr) == -1) {
        cerr << "Could not set the compiled filter: " << pcap_geterr(handle) << endl;
        pcap_close(handle);
        exit(1);
	}
}


void compile_filter(pcap_t *handle, bpf_program *f_expr, char *expr, bpf_u_int32 net_addr) {
    if (pcap_compile(handle, f_expr, expr, 0, net_addr) == -1) {
        cerr << "Could not parse filter " << expr << " : " << pcap_geterr(handle) << endl;
        pcap_close(handle);
        exit(1);
    }
}


void open_device(char *dev_name, char *err_buff) {
    handle = pcap_open_live(dev_name, 65535, 1, 1000, err_buff);
    if (handle == NULL) {
        cerr << "Could not open device " << dev_name << " for sniffing" << endl;
        cerr << err_buff << endl;
        exit(1);
    }
}


void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buff) {
    int size = header->len;
    //Get the IP Header part of this packet , excluding the ethernet header
    struct ip *ip_h = (struct ip *)(buff + sizeof(struct ethhdr));
    packet_no++;
    cout << "Packet number:\t\t" << packet_no << endl;
    cout << "Total length:\t\t" << size << endl << endl;

    // depending on IP protocol version process RIP or RIPng
    if (ip_h->ip_v == 4) {
        process_rip(buff, size);
    } else if(ip_h->ip_v == 6) {
        process_ripng(buff, size);
    }
    cout << "===================================================================" << endl;

}

void process_ripng(const u_char *buff, int size) {
    struct ethhdr *eth_header = (struct ethhdr *)(buff); // ethernet header

    struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(buff + sizeof(struct ethhdr)); // ipv6 header

    char src_addr[INET6_ADDRSTRLEN]; // source IPv6 address
    char dest_addr[INET6_ADDRSTRLEN]; // destination IPv6 address
    inet_ntop(AF_INET6, (ipv6_header->ip6_src.s6_addr), src_addr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, (ipv6_header->ip6_dst.s6_addr), dest_addr, INET6_ADDRSTRLEN);

    // print ethernet info
    print_mac_addresses(buff);
    
    // print IP info
    cout << "----INTERNET PROTOCOL--------------" << endl;
    cout << "Version:\t\t6" << endl;
    cout << "Source IP:\t\t" << src_addr << endl;
    cout << "Destination IP:\t\t" << dest_addr << endl << endl;

    // get UDP header and print its info 
    struct udphdr *udp_header = (struct udphdr *)(buff + sizeof(struct ethhdr) + IP6_HEADER_LEN);
    cout << "----USER DATAGRAM PROTOCOL---------" << endl;
    cout << "Source port:\t\t" << ntohs(udp_header->source) << endl;
    cout << "Destination port:\t" << ntohs(udp_header->dest) << endl;
    cout << "Length:\t\t\t" << ntohs(udp_header->len) << endl << endl;

    // get RIPng payload, parse info and print it
    u_char *payload = (u_char *)(buff + sizeof(struct ethhdr) + IP6_HEADER_LEN + UDP_HEADER_LEN);
    uint8_t command = *payload; // RIPng command
    uint8_t version = *(payload+1); // RIPng version

    cout << "----RIPng--------------------------" << endl;
    print_ripng_command((int)command);

    // there is only version 1 of RIPng
    if ((int)version == 1) {
        cout << "Version:\t\tRIPng" << endl;
        print_ripng_data(payload, ntohs(udp_header->len));
    } else {
        cout << "Version:\t\tUnknown" << endl;
    }
}


void print_ripng_data(u_char *payload, u_int16_t len) {
    if (is_rip_valid(len) == 0) { // check if ripng has valid length
        return;
    }
    for(int offset = 4; offset < len-8; offset+=20) { // ommit udp header 8 bytes
        char addr[INET6_ADDRSTRLEN];
        struct ripng_entry *entry = (struct ripng_entry *)(payload+offset);
        cout << endl;
        cout << "\tROUTE TABLE ENTRY" << endl;
        cout << "\t\tIPv6 Prefix:\t" << inet_ntop(AF_INET6, &(entry->prefix), addr, INET6_ADDRSTRLEN) << endl;
        cout << "\t\tRoute Tag:\t" << ntohs(entry->route_tag) << endl;
        cout << "\t\tPrefix Length:\t" << (int)entry->prefix_len << endl;
        cout << "\t\tMetric:\t\t" << (int)entry->metric << endl;
    }
}


void print_mac_addresses(const u_char *buff) {
    struct ether_addr *dest_mac_addr = (struct ether_addr *)(buff);
    struct ether_addr *src_mac_addr = dest_mac_addr+1;

    cout << "----ETHERNET------------------------" << endl;
    cout << "Source MAC:\t\t" << ether_ntoa(src_mac_addr) << endl;
    cout << "Destionation MAC:\t" << ether_ntoa(dest_mac_addr) << endl << endl;
}


void process_rip(const u_char *buff, int size) {
    struct ethhdr *eth_header = (struct ethhdr *)(buff); // ethernet header

    unsigned short iphdr_len; // length of ip header
    struct ip *ip_header = (struct ip *)(buff + sizeof(struct ethhdr)); // ip header

    char src_addr[INET_ADDRSTRLEN]; // source ip address
    char dest_addr[INET_ADDRSTRLEN]; // destination ip address
    inet_ntop(AF_INET, &(ip_header->ip_src.s_addr), src_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst.s_addr), dest_addr, INET_ADDRSTRLEN);

    // print ethernet info
    print_mac_addresses(buff);
    
    // print IP info
    cout << "----INTERNET PROTOCOL---------------" << endl;
    cout << "Version:\t\t4" << endl;
    cout << "Source IP:\t\t" << src_addr << endl;
    cout << "Destination IP:\t\t" << dest_addr << endl << endl;
    
    iphdr_len = ip_header->ip_hl*4; // ip_hl containst number of 32bit words, *4 to get num of octets
    
    // print udp info
    struct udphdr *udp_header = (struct udphdr *)(buff + sizeof(struct ethhdr) + iphdr_len);
    cout << "----USER DATAGRAM PROTOCOL----------" << endl;
    cout << "Source port:\t\t" << ntohs(udp_header->source) << endl;
    cout << "Destination port:\t" << ntohs(udp_header->dest) << endl;
    cout << "Length:\t\t\t" << ntohs(udp_header->len) << endl << endl;

    // get RIP payload, parse info and print it
    u_char *payload = (u_char *)(buff + sizeof(struct ethhdr) + iphdr_len + UDP_HEADER_LEN);
    uint8_t command = *payload;     // command type
    uint8_t version = *(payload+1); // version

    cout << "----ROUTING INFORMATION PROTOCOL----" << endl;
    print_rip_command(int(command));

    // Only versions 1 and 2 exists
    if ((int)version == 2) {
        cout << "Version:\t\tRIPv2" << endl;
        print_ripv2_data(payload, ntohs(udp_header->len));
    } else if ((int)version == 1) {
        cout << "Version:\t\tRIPv1" << endl;
        print_ripv1_data(payload, ntohs(udp_header->len));
    } else {
        cout << "Version:\t\tUnknown" << endl;
    }
}


void print_ripv1_data(u_char *payload, u_int16_t len) {
    if (is_rip_valid(len) == 0) { // check if rip data length is valid
        return;
    }
    for(int offset = 4; offset < len-8; offset+=20) { // ommit udp header 8 bytes
        char addr[INET_ADDRSTRLEN];
        struct rip_entry *entry = (struct rip_entry *)(payload+offset);
        cout << endl;
        cout << "\tROUTE TABLE ENTRY" << endl;
        cout << "\t\tAddress Family:\t" << ntohs(entry->family) << endl;
        cout << "\t\tIP Address:\t" << inet_ntop(AF_INET, &(entry->addr), addr, INET_ADDRSTRLEN) << endl;
        cout << "\t\tMetric:\t\t" << ntohl(entry->metric) << endl;
    }
}


int is_rip_valid(int len) {
    if (((len-12) % 20) != 0) { // udp header 8 bytes + version + command + 2 reserved = 12
        cout << "\tINVALID FORMAT OF RIP MESSAGE" << endl;
        return 0;
    }
    return 1;
}

void print_ripv2_data(u_char *payload, u_int16_t len) {
    if (is_rip_valid(len) == 0) { // check if rip data length is valid
        return;
    }
    u_int16_t trailer = 0;
    // parse and print entries
    for(int offset = 4; offset < len-8; offset+=20) { // ommit udp header 8 bytes
        char addr[INET_ADDRSTRLEN];
        struct rip_entry *entry = (struct rip_entry *)(payload+offset); // get next entry
        if ((trailer != 0) && (offset >= (int)trailer)) { // break if we are at the md5 trailer
            break;
        }
        cout << endl;
        if (entry->family != 65535) { // entry, not authentication
            cout << "\tROUTE TABLE ENTRY" << endl;
            cout << "\t\tAddress Family:\t" << ntohs(entry->family) << endl;
            cout << "\t\tRoute tag:\t" << entry->route_tag << endl;
            cout << "\t\tIP Address:\t" << inet_ntop(AF_INET, &(entry->addr), addr, INET_ADDRSTRLEN) << endl;
            cout << "\t\tNetmask:\t" << inet_ntop(AF_INET, &(entry->mask), addr, INET_ADDRSTRLEN) << endl;
            cout << "\t\tNext Hop:\t" << inet_ntop(AF_INET, &(entry->next_hop), addr, INET_ADDRSTRLEN) << endl;
            cout << "\t\tMetric:\t\t" << ntohl(entry->metric) << endl;
        } else { // authentication
            cout << "\tAUTHENTICATION" << endl;
            if (entry->route_tag == htons(3)) { // MD5
                cout << "\t\tVersion:\tKeyed Message Digest (3)" << endl;
                u_char *tmp = (u_char *)entry;
                u_int16_t pass_offset = ntohs(*(u_int16_t *)(tmp+4));        // skip 4 bytes, ff ff and auth type (2B)
                trailer = pass_offset;
                u_int8_t key_id = *(tmp+6);                                   // skip 6 bytes, ff ff auth type(2B) Digest Offset(2B)
                cout << "\t\tKey ID: \t" << (int)key_id << endl;
                u_int8_t authdata_len = *(tmp+7);                             // skip 7 bytes, ff ff auth type(2B) Digest Offset(2B) Key ID(1B)
                cout << "\t\tAuth Data Len:\t" << (int)authdata_len << endl;
                cout << "\t\tPassword:\t";
                u_int8_t pass_len = authdata_len - 4;                         // 4bytes are Data trailer
                for(u_int8_t i = 0; i < pass_len; i++) {                      // print md5 hashed password
                    u_char c = *(payload + (int)pass_offset + 4 + i);         // 4bytes are Data trailer
                    cout << hex << setw(2) << setfill('0') << (int)c << dec;
                }
                cout << endl;
            } else if(entry->route_tag == htons(2)) { // Simple Password
                cout << "\t\tVersion:\tSimple Password (2)" << endl;
                cout << "\t\tPassword:\t";
                for (int i = 0; i < 17; i++) { // print 16 byte password
                    u_char *s = (u_char *)entry;
                    char c = *(s+4+i); // skip first 4 bytes + offset of character to print
                    cout << c << "";
                }
                cout << endl;
            } else {
                cout << "\t\tVersion:\tUnknown" << endl;
            }
        }
    }
}


void print_ripng_command(int command) {
    switch(command) {
        case 1:
            cout << "Command:\t\tRequest (1)" << endl;
            break;
        case 2:
            cout << "Command:\t\tResponse (2)" << endl;
            break;
        default:
            cout << "Command:\t\tUnassigned" << endl;
    }
}


void print_rip_command(int command) {
    switch(command) {
        case 0:
            cout << "Command:\t\tInvalid" << endl;
            break;
        case 1:
            cout << "Command:\t\tRequest (1)" << endl;
            break;
        case 2:
            cout << "Command:\t\tResponse (2)" << endl;
            break;
        case 3:
            cout << "Command:\t\tTraceOn (3)" << endl;
            break;
        case 4:
            cout << "Command:\t\tTraceOff (4)" << endl;
            break;
        case 5:
            cout << "Command:\t\tReserved (5)" << endl;
            break;
        case 6:
            cout << "Command:\t\tTriggered Request (6)" << endl;
            break;
        case 7:
            cout << "Command:\t\tTriggered Response (7)" << endl;
            break;
        case 8:
            cout << "Command:\t\tTriggered Acknowledgement (8)" << endl;
            break;
        case 9:
            cout << "Command:\t\tUpdate Request (9)" << endl;
            break;
        case 10:
            cout << "Command:\t\tUpdate Response (10)" << endl;
            break;
        case 11:
            cout << "Command:\t\tUpdate Acknowledge (11)" << endl;
            break;
        default:
            cout << "Command:\t\tUnassigned" << endl;
    }
}


char *parse_args(int argc, char *argv[]) {
    int c = 0;
    char *i_val = NULL;

    while((c = getopt(argc, argv, "i:")) != -1) {
        switch(c) {
            case 'i':
                i_val = optarg;
                break;
            case '?':
                if (optopt == 'i') {
                    cerr << "Option -" << (char)optopt << " requires an argument" << endl;
                } else {
                    cerr << "Unknown option -" << (char)optopt << endl;
                }
        }
    }
    return i_val;
}

void setup_sigint_handler() {
    struct sigaction sigint_handler;

    sigint_handler.sa_handler = exit_handler;
    sigemptyset(&sigint_handler.sa_mask);
    sigint_handler.sa_flags = 0;
    sigaction(SIGINT, &sigint_handler, NULL);
}


void exit_handler(int s) {
    if (handle != NULL) {
        cout << "\nClosing device..." << endl;
        exit(0);
    }
}