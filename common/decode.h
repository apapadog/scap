

typedef struct _EtherHdr
{
	u_int8_t ether_dst[6];
	u_int8_t ether_src[6];
	u_int16_t ether_type;
} EtherHdr;

#define ETHERNET_TYPE_IP	0x0800

#define ETHERNET_HEADER_LEN	14
#define IP_HEADER_LEN		20

typedef struct _IPHdr
{
	u_int8_t ip_verhl;      /* version & header length */
	u_int8_t ip_tos;        /* type of service */
	u_int16_t ip_len;       /* datagram length */
	u_int16_t ip_id;        /* identification  */
	u_int16_t ip_off;       /* fragment offset */
	u_int8_t ip_ttl;        /* time to live field */
	u_int8_t ip_proto;      /* datagram protocol */
	u_int16_t ip_csum;      /* checksum */
	struct in_addr ip_src;  /* source IP */
	struct in_addr ip_dst;  /* dest IP */
} IPHdr;

typedef struct _TCPHdr
{
	u_int16_t th_sport;     /* source port */
	u_int16_t th_dport;     /* destination port */
	u_int32_t th_seq;       /* sequence number */
	u_int32_t th_ack;       /* acknowledgement number */
	u_int8_t th_offx2;      /* offset and reserved */
	u_int8_t th_flags;
	u_int16_t th_win;       /* window */
	u_int16_t th_sum;       /* checksum */
	u_int16_t th_urp;       /* urgent pointer */
} TCPHdr;

typedef struct _UDPHdr
{
	u_int16_t uh_sport;     /*source port*/
	u_int16_t uh_dport;     /*destination port*/
	u_int16_t uh_len;       /*length*/
	u_int16_t uh_sum;       /*checksum*/
} UDPHdr;

#define TCP_FIN 0x01 
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10


