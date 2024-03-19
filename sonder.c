/*
SONDER v0.9
30.05.06.
kiguar@athlante.com
*/
#define __USE_BSD
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <arpa/inet.h>
#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>

struct pseudo_header 
{ 
      /*for computing TCP checksum, see TCP/IP Illustrated p. 145 */
      unsigned long s_addr;
      unsigned long d_addr;
      char zer0;
      unsigned char protocol;
      unsigned short length;
};

unsigned short in_cksum( unsigned short *addr, int len );

int main(int argc,char **argv)
{
	int sockfd, packet_size, sport, dport;
	int on = 1, data_len = 0;
	char *packet;
	sport = 31337;//source port
	packet_size = (sizeof(struct ip) + sizeof(struct tcphdr));
	packet = malloc(packet_size);
	//receive
	char rcv_packet[1000];
	
	//read tcp
	
	struct iphdr *rip;
	struct tcphdr *rtcp;
	char *buffer;
	char *data;
	buffer = (char*)malloc(8192);
	memset(buffer,0,8192);

	
	//end read tcp

	//struct in_addr srcaddr, dstaddr;
	struct sockaddr_in sock_raw;
	struct ip *iphdr = (struct ip *)packet;
	struct in_addr saddr, daddr;
	struct pseudo_header *psuedo = (struct pseudo_header *) (packet + sizeof(struct iphdr) - sizeof(struct pseudo_header));
	struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof( struct ip));
	/*
	srcaddr	saddr
	dstaddr daddr
	*/
	bzero(packet, sizeof(struct iphdr) + sizeof(struct tcphdr));
	

	saddr.s_addr = inet_addr("127.0.0.1");
	daddr.s_addr = inet_addr("127.0.0.1");
	
	psuedo->protocol = IPPROTO_TCP;
	psuedo->length = htons(sizeof(struct tcphdr));
	/*
	ovo radi
	psuedo->s_addr = inet_addr("127.0.0.1");
	psuedo->d_addr = inet_addr("192.168.0.1");*/
	
	//pseudo bi bio tu	
	//psuedo->d_addr = daddr.s_addr;	
	psuedo->s_addr = saddr.s_addr;
	psuedo->d_addr = daddr.s_addr;
	//problem je Koja je source adresa, zato dolazi checksum error
	
	if (argc<=1){
	printf("no argumets!\nneither address nor port\n");
	exit(1);
	}
	
  	// koji user je to
	uid_t me;
  	struct passwd *my_passwd;
	me = getuid ();
  	my_passwd = getpwuid (me);
	if(getuid() != 0)
	{
		printf("insufficient privilegies for user \"%s\", raw packet needs root!\n",my_passwd->pw_name);
		//printf ("%s",uid_t getuid (void));	
		exit(1);
	}
		
	if( ( sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW )) < 0 )
	{
		perror("socket");
		printf("Prob socket\n");
		exit(1);
	}
		
	//int len_inet = sizeof sock_raw;
	//int sip=getsockname(sockfd, (struct sockaddr *)&sock_raw,&len_inet);
	
	//bez ovoga nije moguce staviti svoj header, onda bi se oslanjao na link layer
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL,(char *)&on,sizeof(on)) < 0)
	{
	      perror("setsockopt");
	      printf("Prob setsockopt\n");
	      exit(1);
	}
	
	memset(&sock_raw, '\0', sizeof(sock_raw) );
        memset((char *)tcp,'\0',sizeof(struct tcphdr));

	
	int i;
	char *fl;
	fl=malloc(128+sizeof(char));
	memset(fl,0,sizeof(fl));
	for(i=0;i<argc;i++)
	{
	//fl na kraju ima u sebi string sa sadrzajem svih argumenta
	fl=strcat(fl,argv[i]);
	fl=strcat(fl," ");
	}	
	
// 	//if (strstr(sa,"-p")!= NULL) printf("port flag detected %s\n",sa);
	
	//izgradi packet dodajuci flagove
	int flags;
	flags=0;
	//printf("test %s\n",fl);
	if (strstr(fl,"+s")!=NULL) {printf("SYN flag\n");flags += 0x02;};
	if (strstr(fl,"+f")!=NULL) {printf("FIN flag\n");flags +=0x01;};
	if (strstr(fl,"+r")!=NULL) {printf("RST flag\n");flags +=0x04;};
	if (strstr(fl,"+p")!=NULL) {printf("PUSH flag\n");flags +=0x08;};
	if (strstr(fl,"+a")!=NULL) {printf("ACK flag\n");flags +=0x10;};
	if (strstr(fl,"+u")!=NULL) {printf("URG flag\n");flags +=0x20;};
	printf("flags total = %s \ntcp hex value = %x\n",fl,flags);
	
// 	//izvlaci adresu iz command line argumenta ako je zadana flagom "-d" za destination
	if (strstr(fl,"-d")!=NULL) {
	int j,k=0;	
	for (j=0;j<argc;j++)
	{
	int t=j;
	if (strstr(argv[j],"-d")) {t=t+1;printf ("adresa je %s\n",argv[t]);
	daddr.s_addr=inet_addr(argv[t]);
	psuedo->d_addr = daddr.s_addr;
			
			}
		}
	}
	
// 	//izvlaci adresu iz command line argumenta ako je zadana flagom "-s" za source
	if (strstr(fl,"-s")!=NULL) {
	int j,k=0;	
	for (j=0;j<argc;j++)
	{
	int t=j;
	if (strstr(argv[j],"-s")) {t=t+1;printf ("source adresa je %s\n",argv[t]);
	saddr.s_addr=inet_addr(argv[t]);
	psuedo->s_addr = saddr.s_addr;			
			}
		}
	}	
	
// 	//izvlaci port iz command line argumenta ako je zadana flagom "-p"
	if (strstr(fl,"-p")!=NULL) {
	int j,k=0;	
	for (j=0;j<argc;j++)
	{
	int t=j;
	if (strstr(argv[j],"-p")) {t=t+1;printf ("port %s\n",argv[t]);
	dport=atoi(argv[t]);
			}
		}
	}	
	
// 	//izvlaci broj paketa iz command line argumenta ako je zadana flagom "-c"
	int count;
	if (strstr(fl,"-c")!=NULL) {
	int j,k=0;	
	for (j=0;j<argc;j++)
	{
	int t=j;
	if (strstr(argv[j],"-c")) {t=t+1;printf ("paketa saljem %s\n",argv[t]);
	count=atoi(argv[t]);
			}
		}
	}	else count=1;
	
	
/* priprema funkcije za parsiranje argumenata
	char* argum (char* argm){
	printf("arg:%s\n",argm);
	return 0;
	}
	argum("-d");	
*/	
        tcp->th_sport = htons(sport);
        tcp->th_dport = htons(dport);
        tcp->th_seq = htonl(random()%time(NULL));
        tcp->th_ack = htonl(random()%time(NULL));
        tcp->th_off = 5;
        /* We won't use th_x2 (i don't know what it is) */
        //tcp->th_flags = TH_SYN+TH_ACK+TH_PUSH+TH_RST+TH_FIN+TH_URG;
        tcp->th_flags = flags;
	tcp->th_win = htons(12000);
	tcp->th_sum = 0;
	tcp->th_sum = in_cksum((unsigned short *)psuedo, sizeof(struct tcphdr) + sizeof(struct pseudo_header));

        bzero(packet, sizeof(struct iphdr));
	iphdr->ip_v = 4;
	iphdr->ip_hl = 5;
	iphdr->ip_len = packet_size;
	iphdr->ip_off = 0;
	iphdr->ip_ttl = IPDEFTTL;
	iphdr->ip_p = IPPROTO_TCP;
	iphdr->ip_src = saddr;
	iphdr->ip_dst = daddr;
	
	iphdr->ip_sum = (unsigned short)in_cksum((unsigned short *)iphdr, sizeof(struct ip));

	sock_raw.sin_family = AF_INET;
	sock_raw.sin_port = htons(dport);
	sock_raw.sin_addr = daddr;	
	
	
	int ic=0;
 	for (ic=0;ic<count;ic++)
	{
	sendto(sockfd, packet, packet_size, 0x0, (struct sockaddr *)&sock_raw, sizeof(sock_raw));
	//recvfrom(sockfd, packet, sizeof(packet), 0 , ,sizeof(daddr));
	puts("\n... done");
	}
	
	//citanje packeta
	int rsockfd;
	rsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
/*	int cntr=0;
	for(;;)
	{
	memset(&in_packet.tcp_head,0,sizeof(in_packet.tcp_head));
	memset(&in_packet.ip_head,0,sizeof(in_packet.ip_head));
	memset(&in_packet.data,0x0,sizeof(in_packet.data));
	
 	cntr=read(sockfd,(struct read_tcp*)&in_packet,sizeof(in_packet));
	}
	printf("test %d\n",in_packet.tcp_head.th_dport);
	printf("test %d\n",in_packet.tcp_head.th_sport);
	printf("ip version %d\n",in_packet.ip_head.ip_len);*/
	

	puts("now reading...");	
	while (read(rsockfd,buffer,8192)>0){
	rip=(struct iphdr*)buffer;
	rtcp=(struct tcphdr*)(buffer + rip->ihl*4);
	//printf("test %d\n",in_packet.tcp_head.th_sport);
	printf("version %d\n",rip->version);
	printf("TTL %d\n",rip->ttl);
	printf("checksum %x\n",ntohs(rip->check));
 	printf("sport %d dport %d\n ",ntohs(rtcp->th_sport),ntohs(rtcp->th_dport));
		
	data=(buffer+(rip->ihl*4))+(rtcp->th_off*4);
	//printf("data %s\n",data);
	printf("seq num %d\n",ntohs(rtcp->th_seq));
	printf("ack %d\n",ntohs(rtcp->th_ack));
	printf("ack %d\n",rtcp->th_ack);
	printf("flags hex %x  dec %d\n",rtcp->th_flags,rtcp->th_flags);
	flags_are(rtcp->th_flags);
	puts("- - - packet - - - ");
	}
	exit(0);
}

flags_are(int a){
//koji su flagovi
if (a & 1) {puts("FIN ");}
if (a & 2) {puts("SYN ");}
if (a & 4) {puts("RST");}
if (a & 8) {puts("PUSH ");}
if (a & 16) {puts("ACK ");}
if (a & 32) {puts("URG ");}
}




unsigned short in_cksum(unsigned short *addr,int len)
{
	        register int sum = 0;
	        u_short answer = 0;
	        register u_short *w = addr;
	        register int nleft = len;
	        /*
		 *          * Our algorithm is simple, using a 32 bit accumulator (sum), we add
		 *          * sequential 16 bit words to it, and at the end, fold back all the
		 *          * carry bits from the top 16 bits into the lower 16 bits.
		 *          */
	        while (nleft > 1)  {
	                sum += *w++;
	                nleft -= 2;
	        }
		        
			/* mop up an odd byte, if necessary */
	        if (nleft == 1) {
	        *(u_char *)(&answer) = *(u_char *)w ;
	        sum += answer;
	        }

	        /* add back carry outs from top 16 bits to low 16 bits */
	        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	        sum += (sum >> 16);                     /* add carry */
	        answer = ~sum;                          /* truncate to 16 bits */
	        return(answer);
}
