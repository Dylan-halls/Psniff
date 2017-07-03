const u_char *ip_header;
const u_char *tcp_header;
const u_char *payload;
const u_char *arp_header;

int ethernet_header_length = 14;
int ip_header_length;
int tcp_header_length;
int payload_length;
int arp_length;

struct ip_packet {
	u_char ip_vhl;
	u_char ip_tos;   
	u_short ip_len;   
	u_short ip_id;     
	u_short ip_off;    
	#define IP_RF 0x8000       
	#define IP_DF 0x4000     
	#define IP_MF 0x2000  
	#define IP_OFFMASK 0x1fff 
	u_char ip_ttl;    
	u_char ip_p;  
	u_short ip_sum; 
	struct in_addr ip_src;
	struct in_addr ip_dst;
	};

struct arp_hdr{
	u_int16_t HardwareType;				// hardware type 
	u_int16_t ProtocolType;				// protocol type

	u_char HardwareAddressLength;			// harware address length
	u_char ProtocolAddressLength;			// protocol address length
	u_int16_t Opcode;				// opcode - request, reply, re request

	u_char s_hw[6];		// source MAC address
	u_char s_ip[4];		// source IP address
	u_char d_hw[6];		// target MAC address
	u_char d_ip[4];
};

void debug(const char* text) {
	printf("[DEBUG] %s\n", text);
}

void fatal(const char *text) {
	printf("[FATAL] %s\n", text);
	exit(-1);
}

const char* getname(const char *ip) 
{
	struct in_addr addr;
	struct hostent *he;

	inet_aton(ip, &addr);
	if (he = gethostbyaddr(&addr, sizeof(addr), AF_INET)) {
		return he->h_name;
	}
	else {
		return ip;
	}
}

long elapsedtime(){
	struct timeval tempo1, tempo2;
	long elapsed_mtime;
	long elapsed_seconds;
	long elapsed_useconds;
	gettimeofday(&tempo2, NULL);
	elapsed_seconds = tempo2.tv_sec - tempo1.tv_sec; 
	elapsed_useconds = tempo2.tv_usec - tempo1.tv_usec;
	return ((elapsed_seconds) * 1000 + elapsed_useconds/1000.0) + 0.5;
}

int getipheader_len(const u_char *packet){
	ip_header = packet + ethernet_header_length;
	ip_header_length = ((*ip_header) & 0x0F);
	ip_header_length = ip_header_length * 4;
	return ip_header_length;
}

const char* geticmptype(u_int type){
	if (type == ICMP_ECHOREPLY){
		return "Echo Reply (ping)";
	}
	if (type == ICMP_ECHO){
		return "Echo Request (ping)";
	}
	if (type == ICMP_DEST_UNREACH){
		return "Destination Unreachable (ping)";
	}
	if (type == ICMP_HOST_UNKNOWN){
		return "Host Unknown (ping)";
	}
}

const char* gettcpflags(const struct tcphdr *tcp){
	if(tcp->th_flags & TH_SYN){
		return "syn";
	}
	if(tcp->th_flags & TH_FIN){
		return "fin";
	}
	if(tcp->th_flags & TH_ACK){
		return "ack";
	}
	if(tcp->th_flags & TH_RST){
		return "rst";
	}
	if(tcp->th_flags & TH_PUSH){
		return "push";
	}
	if(tcp->th_flags & TH_URG){
		return "urg";
	}
	if(tcp->th_flags & TH_SYN+TH_ACK){
		return "syn/ack";
	}
}

const char * getarptype(unsigned short int opcode){
	//TODO: Add suport for other types
	if (opcode == ARPOP_REQUEST){
		return "Request";
	}
	if (opcode == ARPOP_REPLY){
		return "Reply";
	}

}
//vlabs.c@gmail.com
void makeaddr_s(const struct arp_hdr *arp_hdr){
	int i;
	for(i = 0; i < 4; i++) {	
		printf("\033[1;35m%d\033[00m", arp_hdr->s_ip[i]);
		if(i != 3){	
			printf(".");	
		}
	}
}

void makeaddr_d(const struct arp_hdr *arp_hdr){
	int i;
	for(i = 0; i < 4; i++) {	
		printf("\033[1;35m%d\033[00m", arp_hdr->d_ip[i]);
		if(i != 3){	
			printf(".");	
		}
	}
}

void makemac_s(const struct arp_hdr *arp_hdr){
	int j;
	for(j = 0; j < 6; j++){
		printf("\033[1;36m%02x\033[00m", arp_hdr->s_hw[j]);
		if(j != 5){	
			printf("\033[1;36m:\033[00m");	
		}
	}
}

void makemac_d(const struct arp_hdr *arp_hdr){
	int j;
	for(j = 0; j < 6; j++){	
		printf("\033[1;36m%02x\033[00m", arp_hdr->d_hw[j]);
		if(j != 5){	
			printf("\033[1;36m:\033[00m");	
		}
	}
}

char getfilter(){
    char file[100];
    printf("Filter: \n");
    fgets(file, 100, stdin);
    return *file;
}

const char* getlocalip(){
	FILE *fp;
	char path[1035];

	/* Open the command for reading. */
	fp = popen("ifconfig |  grep -Eo 'inet (addr:)?([0-9]*\\.){3}[0-9]*' | grep -Eo '([0-9]*\\.){3}[0-9]*' | grep -v '127.0.0.1' | while read line; do echo -n \"$line \"; done", "r");
	if (fp == NULL) {
		printf("Failed to run command\n" );
		exit(1);
	}

	/* Read the output a line at a time - output it. */
	while (fgets(path, sizeof(path)-1, fp) != NULL) {
		printf("\033[1;3m%s\033[00m", path);
	}

	/* close */
	pclose(fp);
}

void banner(){
	const char *banner = "      ____            _  __  __ \n"
                         "     |  _ \\ ___ _ __ (_)/ _|/ _|\n"
                         "     | |_) / __| '_ \\| | |_| |_ \n"
                         "     |  __/\\__ \\ | | | |  _|  _|\n"
                         "     |_|   |___/_| |_|_|_| |_|  \n";

    printf("\033[1;34m%s\033[00m\n", banner);
}