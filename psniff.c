#include <pcap.h>
#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>

#include "psniff.h"

/*Define packet types*/
int packet_num; //accumilator of packet count
//Ethernet
struct ether_header *eth_header;
char src_mac[5];
char dst_mac[5];
int ether_proto;
//IP
const struct ip_packet *ip;
int ip_type_service;   
int ip_length;      
int ip_offset;    
int ip_time_to_live;    
int ip_proto;  
int ip_csum;
int ip_headr_length;
//ICMP
const struct icmphdr *icmp_p;
u_int icmp_type;
//u_int icmp_seq;
//TCP
const struct tcphdr *tcp;
//UDP
const struct udphdr *udp;
int udp_run;
//ARP
const struct arphdr *arp;
const struct arp_hdr *arp_h;
unsigned short int opcode;

void assign_ethernet(const u_char *packet){
	eth_header = (struct ether_header *) packet;
	ether_proto = ntohs(eth_header->ether_type);	
}

void assign_ip(const u_char *packet){
	ip = (struct ip_packet*)(packet + ethernet_header_length);
	ip_type_service = ip->ip_tos;
	ip_length = ntohs(ip->ip_len);
	ip_offset = ip->ip_off;
	ip_time_to_live = ip->ip_ttl;
	ip_proto = ip->ip_p;

	//disable udp packets
	if (udp_run != 1){
		if (ip_proto == IPPROTO_UDP){
			ip_proto = 99;
		}
		else{
			ip_csum = ntohs(ip->ip_sum);
			printf("%d ", packet_num);
			printf("\033[1;32mIPv4 \033[00m \033[1;33m%s\033[00m (\033[1;35m%s\033[00m) \033[1;31m→\033[00m ", getname(inet_ntoa(ip->ip_src)), inet_ntoa(ip->ip_src));
			printf("\033[1;33m%s\033[00m (\033[1;35m%s\033[00m) ", getname(inet_ntoa(ip->ip_dst)), inet_ntoa(ip->ip_dst));
			ip_headr_length = getipheader_len(packet);
		}
	}
	else {
		ip_csum = ntohs(ip->ip_sum);
		printf("%d ", packet_num);
		printf("\033[1;32mIPv4 \033[00m \033[1;33m%s\033[00m (\033[1;35m%s\033[00m) \033[1;31m→\033[00m ", getname(inet_ntoa(ip->ip_src)), inet_ntoa(ip->ip_src));
		printf("\033[1;33m%s\033[00m (\033[1;35m%s\033[00m) ", getname(inet_ntoa(ip->ip_dst)), inet_ntoa(ip->ip_dst));
		ip_headr_length = getipheader_len(packet);
	}
}

void assign_icmp(const u_char *packet){
	//add id and seq
	printf("\033[1;32mICMP \033[00m");
	icmp_p = (struct icmphdr*)(packet + ip_headr_length + ethernet_header_length);
	icmp_type = (unsigned int)(icmp_p->type);
	//icmp_seq = (unsigned int) (icmp_p->);
	printf("%s\n", geticmptype(icmp_type));
}

void assign_tcp(const u_char *packet){
	tcp = (struct tcphdr*)(packet + ip_headr_length + ethernet_header_length);
	printf("\033[1;32mTCP \033[00m");
	//\033[1;32mARP \033[00m
	printf("\033[1;30msport=\033[00m\033[0;33m%u\033[00m ", (unsigned int)ntohs(tcp->th_sport));
	printf("\033[1;30mdport=\033[00m\033[0;33m%u\033[00m ", (unsigned int)ntohs(tcp->th_dport));
	printf("\033[1;30mseq=\033[00m\033[0;33m%u\033[00m ", (unsigned int)ntohl(tcp->th_seq));
	printf("\033[1;30mack=\033[00m\033[0;33m%u\033[00m ", (unsigned int)ntohl(tcp->th_ack));
	printf("\033[1;30mflag=\033[00m\033[0;33m%s\033[00m\n", gettcpflags(tcp));
	return;
}

void assign_udp(const u_char *packet){
	udp = (struct udphdr*)(packet + ip_headr_length + ethernet_header_length);
	printf("\033[1;32mUDP \033[00m");
	printf("\033[1;30msport=\033[00m\033[0;33m%u\033[00m ", (unsigned int)ntohs(udp->uh_sport));
	printf("\033[1;30mdport=\033[00m\033[0;33m%u\033[00m \n", (unsigned int)ntohs(udp->uh_dport));
}

void assign_arp(const u_char *packet){
	arp = (struct arphdr*)(packet + ethernet_header_length);
	arp_h = (struct arp_hdr*)(packet + ethernet_header_length);
	printf("%d ", packet_num);
	printf("\033[1;32mARP \033[00m");
	opcode = (unsigned short int) ntohs(arp->ar_op);
	printf("(%s) → ", getarptype(opcode));
	//Messy but works aha
	if (opcode == ARPOP_REQUEST){
		printf("Who has ");
		makeaddr_d(arp_h);
		printf("? Tell ");
		makeaddr_s(arp_h);
		printf("\n");
	}
	if (opcode == ARPOP_REPLY){
		makeaddr_s(arp_h);
		printf(" is at ");
		makemac_s(arp_h);
		printf("\n");
	}
}

void packet_handler(u_char *args, const struct pcap_pkthdr* header, const u_char* packet) {
	eth_header = (struct ether_header *) packet;
	assign_ethernet(packet);
	++packet_num;
	if (ether_proto == ETHERTYPE_IP){
		assign_ip(packet);
		if (ip_proto == IPPROTO_ICMP) {
			assign_icmp(packet);
		}
		else if (ip_proto == IPPROTO_TCP){
			assign_tcp(packet);
		}
		else if (ip_proto == IPPROTO_UDP){
			assign_udp(packet);
		}
	}
	else if (ether_proto == ETHERTYPE_ARP){
		assign_arp(packet);
	}
}

int main(int argc, char const *argv[])
{	
	char *device;
	int filt;
	int monitor;
	pcap_t *handle;
	char* bpf_filter = NULL;
	size_t nbytes = 10;
	bpf_u_int32 pcap_device_mask;
	bpf_u_int32 pcap_device_ip;
	struct bpf_program filter;
	const char* version = "1.2";
	unsigned int ts = 0;	
	char error_buffer[PCAP_ERRBUF_SIZE];
	void *ptr;

	//TODO: Change these to run from cmd args
	int snapshot_len = 1028;
	int promiscuous = 1;
	int timeout = 1000;

	/* Find a device */
	device = pcap_lookupdev(error_buffer);
	if (device == NULL) {
		fatal("finding a device");
		return 1;
	}

	if (pcap_lookupnet(device, &pcap_device_ip, &pcap_device_mask, error_buffer) == -1) {
		printf("Couldn't get netmask for device %s: %s\n", device, error_buffer);
		pcap_device_ip = 0;
		pcap_device_mask = 0;
	}

	/* handle cmd args */
	for (int i = 0; i < argc; ++i){
		if (strncmp(argv[i], "-v", 2) == 0){
			printf("psniff version %s\n", version);
			exit(1);
		}
		else if (strncmp(argv[i], "--filter", 8) == 0){
			filt = 1;
		}
		else if (strncmp(argv[i], "--udp", 5) == 0){
			udp_run = 1;
		}
		else if (strncmp(argv[i], "--monitor", 9) == 0){
			monitor = 1;
		}
		else {
			if (i != 0){
				printf("\033[1;31mInvaild Argument:\033[00m %s\n", argv[i]);
				exit(-1);
			}
		}
	}

	struct in_addr address;	

    char ip[13];
    char subnet_mask[13];

    /* Get ip in human readable form */	
    address.s_addr = pcap_device_ip;
    strcpy(ip, inet_ntoa(address));
    if (ip == NULL) {
        perror("inet_ntoa"); /* print error */
        return 1;
    }
    
    /* Get subnet mask in human readable form */
    address.s_addr = pcap_device_mask;
    strcpy(subnet_mask, inet_ntoa(address));
    if (subnet_mask == NULL) {
        perror("inet_ntoa");
        return 1;
    }

    /* Print the start banner */
    banner();
    printf("\033[1;3m%s\033[00m | ", device);
    getlocalip();
    printf("| \033[1;3m%s\033[00m\n\n", subnet_mask);

    if (monitor != 1){
		handle = pcap_open_live(device, snapshot_len, promiscuous, timeout, error_buffer);
	}
	else {
		handle = pcap_create(device, error_buffer);
		if (pcap_can_set_rfmon(handle) == 1){
			fatal("Can't set monitor mode");
		}
		pcap_set_rfmon(handle, 1);
		pcap_set_promisc(handle, 1);
		pcap_set_snaplen(handle, snapshot_len);
		pcap_set_timeout(handle, timeout);
		pcap_activate(handle);
	}

	if (filt == 1){
		printf("Filter: \033[1;36m");
		getline(&bpf_filter, &nbytes, stdin);
		printf("\033[00m");
		if (pcap_compile(handle, &filter, bpf_filter, 0, pcap_device_ip) == -1) {
			printf("\033[1;31mSyntax Error:\033[00m %s", bpf_filter);
			return 2;
		}
		if (pcap_setfilter(handle, &filter) == -1) {
			printf("Error setting filter - %s\n", pcap_geterr(handle));
			return 2;
    	}
	}

	while(1){
		pcap_loop(handle, 1, packet_handler, NULL);
	}

	return 0;
}