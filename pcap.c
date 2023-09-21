#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;                             // Get Ethernet Header Address

    struct ipheader * ip = (struct ipheader *) (packet + sizeof(struct ethheader)); // Get IP Header Address
    int ip_header_len = ip->iph_ihl * 4;                                            // IP Header Length
    unsigned short ip_payload_len = ntohs(ip->iph_len) - ip_header_len;             // IP Payload Length 

    struct tcpheader* tcp = (struct tcpheader *) ((u_char *)ip + ip_header_len);    // Get TCP Header Address
    int tcp_header_len = TH_OFF(tcp) * 4;                                           // TCP Header Length

    char *data = (char *)tcp + tcp_header_len;                                      // Get Data Address
    int data_len = ip_payload_len - tcp_header_len;                                 // Data Payload Length
    char buffer[1024];                                                              // Stoarge for Message

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type    
        switch(ip->iph_protocol) {          // Check TCP
            case IPPROTO_TCP:
                printf("[       TCP Packet found       ]\n");

                // print About Ethernet
                printf("[Ethernet] Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                    eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                    eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
                printf("[Ethernet] Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n\n", 
                    eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                    eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

                // print About IP
                printf("[IP] Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
                printf("[IP] Destination IP: %s\n\n", inet_ntoa(ip->iph_destip));

                // Print About TCP
                printf("[TCP] Source Port: %hu\n", ntohs(tcp->tcp_sport));
                printf("[TCP] Destination Port: %hu\n\n", ntohs(tcp->tcp_dport));       

                // Print About Message
                memcpy((char*)buffer, data, data_len);                                  
                printf("[Message, Length: %ld] : %s\n\n", strlen(buffer), buffer);   
                
                break;
            default:
                printf("[       Not TCP Packet      ]\n\n");
                break;
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;
    
    // Step 1: Open live pcap session on NIC with name eth0
    handle = pcap_open_live("enp0s8", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}