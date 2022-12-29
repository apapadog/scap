/*  
 *  scap_module.c Kernel module for stream capture library.
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/netdevice.h>    // for dev_add a protocol hook function
#include <net/protocol.h>	// for dev_add a protocol hook function
#include <linux/skbuff.h>	// for sk_buff
#include <linux/socket.h>	// for socket creation
#include <linux/if_packet.h>	// for socket creation
#include <net/sock.h>		// for socket creation, struct proto
#include <linux/net.h>		// for socket creation, struct net_proto_family, struct proto_ops
#include <linux/types.h>
#include <linux/mm.h>		// for alloc memory pages
#include <asm/system.h>
#include <asm/page.h>
#include <linux/inet.h>		// for decoding
#include <net/ip.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/poll.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/in.h>
#include <asm/cacheflush.h>
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <asm/io.h>
#include <linux/init.h>
#include <linux/semaphore.h>

#include "../common/scap_defs.h"		// structs and buffers for scap

#define DEBUG_PRINTK 0

//socket functions
static int scap_create(struct net *net, struct socket *sock, int protocol);
static int scap_release(struct socket *sock);
static int scap_mmap(struct file *file, struct socket *sock, struct vm_area_struct *vma);
static int scap_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen);
static int scap_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen);
static unsigned int scap_poll(struct file *file, struct socket *sock, poll_table *wait);

//for scap protocol/socket creation
struct scap_sock {
	struct sock sk;
	unsigned int scap_sock_id;
	scap_conf_t conf;
	uint8_t configured;
	uint8_t running;
	uint8_t mapped_stats;
};

static struct proto scap_proto = {
	.name	  = "PF_SCAP",
	.owner	  = THIS_MODULE,
	.obj_size = sizeof(struct scap_sock),
};

static struct net_proto_family scap_family_ops = {
	.family =	PF_SCAP,
	.create =	scap_create,
	.owner	=	THIS_MODULE,
};

static const struct proto_ops scap_ops = {
	.family =	PF_SCAP,
	.owner =	THIS_MODULE,
	.release =	scap_release,
	.bind =		sock_no_bind,
	.connect =	sock_no_connect,
	.socketpair =	sock_no_socketpair,
	.accept =	sock_no_accept,
	.getname =	sock_no_getname,
	.poll =		scap_poll,
	.ioctl =	sock_no_ioctl,
	.listen =	sock_no_listen,
	.shutdown =	sock_no_shutdown,
	.setsockopt =	scap_setsockopt,
	.getsockopt =	scap_getsockopt,
	.sendmsg =	sock_no_sendmsg,
	.recvmsg =	sock_no_recvmsg,
	.mmap =		scap_mmap,
	.sendpage =	sock_no_sendpage,
};


// scap module data

typedef struct scap_module_stats {
	uint32_t sockets;
	uint32_t sockets_feed;
	uint32_t running_sockets;
	uint32_t free_stream_nodes;

	uint32_t active_streams;  //in hashtable and access list
	uint32_t total_streams;
	uint32_t expired_streams;  //totally

	uint32_t total_chunks;
	uint32_t used_chunks;
	uint32_t unused_chunks;

	uint64_t bytes;
	uint64_t bytes_written;
	uint32_t pkts;
	uint64_t dropped_bytes;  
	uint32_t dropped_pkts;
	uint64_t discarded_bytes;
	uint32_t discarded_pkts;
	uint64_t filtered_bytes;
	uint32_t filtered_pkts;

	struct scap_sock *scap_socket[20];
	struct sk_filter *socket_filter[20];
	int cutoff;
	int timeout;
	int chunk_size;
	int overlap;
	int flush_timeout;
	int need_packets;

	int thread_rr;
	int thread_num;

	int expire_streams;
} scap_module_stats_t;

scap_module_stats_t scap_stats;

struct packet_type protocol_hook;

#define UNIVERSAL_HASHING_A 1894117491

#define HASHTABLE_SIZE 262144

stream_t *stream_hashtable[HASHTABLE_SIZE];
stream_t *access_head, *access_tail;
stream_t *free_stream;
stream_t *free_stream_tail;

scap_chunk_header_t *free_chunk_list;  //head
scap_chunk_header_t *free_chunk_list_tail;
scap_chunk_header_t *free_chunk_list_alloc;

//spinlock_t *block_lock;
//spinlock_t *stream_lock;

#define MAX_QUEUES 32

spinlock_t read_offset_lock[MAX_QUEUES];
spinlock_t last_offset_lock[MAX_QUEUES];
spinlock_t free_offset_lock[MAX_QUEUES];

spinlock_t hashtable_lock[HASHTABLE_SIZE], access_lock, free_stream_lock, free_chunk_lock, expire_streams_lock;


typedef struct scap_buffer {
	char			**block_vec;
//	unsigned int		block_head;
//	unsigned int		block_last;
	unsigned int		block_order;
	unsigned int		block_pages;
	unsigned int		block_nr;
	unsigned int 		block_size;
	spinlock_t		buff_lock;
	uint8_t 		initialized;
} scap_buffer_t;

scap_buffer_t scap_stats_buffer;
scap_buffer_t scap_data_buffer;
scap_buffer_t shared_q;

#define START_P (scap_stats_buffer.block_vec[0])
#define STREAM_BY_OFFSET(x) ((stream_t *)(scap_stats_buffer.block_vec[x/scap_stats_buffer.block_size]+(x%scap_stats_buffer.block_size)))
#define STREAM_NEXT(st) STREAM_BY_OFFSET(st->internal.next_stream_offset)
#define GET_STREAM_OFFSET(st) (st->internal.stream_offset)
#define GET_NEXT_STREAM_OFFSET(st) (st->internal.next_stream_offset)
#define QUEUE_READ_OFFSET(id) *((unsigned int *)(shared_q.block_vec[0]+((id)*12)))
#define QUEUE_LAST_OFFSET(id) *((unsigned int *)(shared_q.block_vec[0]+4+((id)*12)))
#define QUEUE_FREE_OFFSET(id) *((unsigned int *)(shared_q.block_vec[0]+8+((id)*12)))
#define QUEUE_READ_STREAM(id) STREAM_BY_OFFSET(QUEUE_READ_OFFSET(id))
#define QUEUE_LAST_STREAM(id) STREAM_BY_OFFSET(QUEUE_LAST_OFFSET(id))
#define QUEUE_FREE_STREAM(id) STREAM_BY_OFFSET(QUEUE_FREE_OFFSET(id))
#define STREAM_NUM ((unsigned int)((scap_stats_buffer.block_size/sizeof(stream_t))*scap_stats_buffer.block_nr))


//other functions declaration
static int scap_set_buffer(scap_buffer_t *buff, unsigned int block_nr, unsigned int block_size);
static int scap_release_buffer(scap_buffer_t *buff);
void release_chunk(scap_chunk_header_t *chunk, int chunk_size);


static inline unsigned int min_len(unsigned int len1, unsigned int len2) {
	if (len1<len2) 
		return len1;
	else 
		return len2;
}

stream_t *get_free_stream(void) {
	stream_t *st;

	spin_lock_bh(&free_stream_lock);
	if (free_stream==NULL) {
		if (DEBUG_PRINTK==1) printk("scap: we need more memory for scap stats\n");
		//XXX get more mem
		spin_unlock_bh(&free_stream_lock);
		return NULL;
	}

	if (free_stream->status!=STREAM_FREE) {
		if (DEBUG_PRINTK==1) printk("scap: we need more memory for scap stats\n");
		//XXX get more mem
		spin_unlock_bh(&free_stream_lock);
		return NULL;
	}

	st=free_stream;
	free_stream=free_stream->next;
	scap_stats.free_stream_nodes--;
	spin_unlock_bh(&free_stream_lock);
	return st;
}

void release_stream_node(stream_t *st) {

	st->status=STREAM_FREE;
	st->next=NULL;
		
	spin_lock_bh(&free_stream_lock);
	if (free_stream_tail==NULL || free_stream==NULL) {
		free_stream_tail=st;
		free_stream=st;
	}
	else {
		free_stream_tail->next=st;
		free_stream_tail=st;
	}
	scap_stats.free_stream_nodes++;
	spin_unlock_bh(&free_stream_lock);
}

stream_t *new_stream(unsigned int hash) {
	stream_t *st;
	int next_rr;

	st=get_free_stream();
	if (st==NULL) return NULL;
	st->status=STREAM_ACTIVE;
	st->status_detail=STREAM_NOT_DELIVERED;

	spin_lock_bh(&hashtable_lock[hash]);

	if (stream_hashtable[hash]==NULL) {
		st->hashtable_next=NULL;
	}
	else {
		stream_hashtable[hash]->hashtable_prev=st;
		st->hashtable_next=stream_hashtable[hash];
	}
	st->hashtable_prev=NULL;
	st->hash=hash;
	stream_hashtable[hash]=st;

	spin_unlock_bh(&hashtable_lock[hash]);

	st->next=NULL;
	st->access_prev=NULL;

	spin_lock_bh(&access_lock);

	next_rr=(scap_stats.thread_rr+1)%scap_stats.thread_num;

	st->access_next=access_head;
	if (access_head!=NULL) access_head->access_prev=st;
	access_head=st;
	if (access_tail==NULL) {
		access_tail=st;
		st->access_next=NULL;
	}

	spin_unlock_bh(&access_lock);


	//data storage
	memset(&st->data_storage, 0, sizeof(stream_data_storage_t));
	st->internal.flush_clone=NULL;
	st->internal.clone_offset=0;
	st->process.chunk_size=scap_stats.chunk_size;
	st->process.overlap=scap_stats.overlap;
	st->process.flush_timeout=scap_stats.flush_timeout;

	st->process.thread_id=scap_stats.thread_rr;
	scap_stats.thread_rr=next_rr;
	st->process.chunk_len=0;	
	st->process.data_offset=0;

	st->priority=0;

	//lock
	scap_stats.total_streams++;
	scap_stats.active_streams++;
	//unlock
if (DEBUG_PRINTK==1) printk("scap_debug: new stream, stream number: %u\n",scap_stats.total_streams);
	return st;
}

stream_t *clone_stream(stream_t *st) {
	stream_t *st_clone;
	int offset_tmp;
	unsigned int id_tmp;

	st_clone=get_free_stream();
	if (st_clone==NULL) return NULL;
	offset_tmp=st_clone->internal.stream_offset;
	id_tmp=st_clone->internal.id;
	memcpy(st_clone, st, sizeof(stream_t));  //clone st
	st_clone->internal.stream_offset=offset_tmp;
	st_clone->internal.id=id_tmp;
	st_clone->next=NULL;
	st_clone->internal.next_stream_offset=0;
	st_clone->internal.flush_clone=st;
	st->internal.flush_clone=st_clone;
	st_clone->internal.clone_offset=st->internal.stream_offset;
	st->internal.clone_offset=st_clone->internal.stream_offset;

	return st_clone;
}


void creation_event(stream_t *st) {
	int i;

	stream_t *clone=clone_stream(st);
	if (clone==NULL) {
		printk("scap error: no stream_t memory\n");
		return;
	}

	clone->process.event=SCAP_EVENT_CREATION;

	//enqueue event and clone st to QUEUE_LAST_OFFSET(st->process.thread_id) queue
	spin_lock_bh(&last_offset_lock[st->process.thread_id]);
	if ( QUEUE_LAST_OFFSET(st->process.thread_id)!=0 ) 
		QUEUE_LAST_STREAM(st->process.thread_id)->internal.next_stream_offset=clone->internal.stream_offset;
	QUEUE_LAST_OFFSET(st->process.thread_id)=clone->internal.stream_offset;
	spin_unlock_bh(&last_offset_lock[st->process.thread_id]);

	spin_lock_bh(&read_offset_lock[st->process.thread_id]);
	if ( QUEUE_READ_OFFSET(st->process.thread_id)==0 )
		QUEUE_READ_OFFSET(st->process.thread_id)=clone->internal.stream_offset;

	//spin_lock_bh(&free_offset_lock[st->process.thread_id]);
	if ( QUEUE_FREE_OFFSET(st->process.thread_id)==0 )
		QUEUE_FREE_OFFSET(st->process.thread_id)=clone->internal.stream_offset;
	//spin_unlock_bh(&free_offset_lock[st->process.thread_id]);
	spin_unlock_bh(&read_offset_lock[st->process.thread_id]);

//	flush_dcache_page(virt_to_page(scap_stats_buffer.block_vec[clone->internal.stream_offset/scap_stats_buffer.block_size]+(clone->internal.stream_offset%scap_stats_buffer.block_size)));
//	smp_wmb();

	for (i=0; i<scap_stats.sockets_feed; i++) 
		if (scap_stats.scap_socket[i]!=NULL) 
			scap_stats.scap_socket[i]->sk.sk_data_ready(&scap_stats.scap_socket[i]->sk, 0); 
}

void data_event(stream_t *st) {
	int i;

	stream_t *clone=clone_stream(st);
	if (clone==NULL) {
		printk("scap error: no stream_t memory\n");
		return;
	}

	clone->process.event=SCAP_EVENT_DATA_CHUNK;
	if (clone->data_storage.curr_chunk!=NULL) {
		clone->process.chunk_len=clone->data_storage.curr_chunk->write_offset;
		clone->process.data_offset=clone->data_storage.curr_chunk->data_offset;
	}

	//enqueue event and clone st to QUEUE_LAST_OFFSET(st->process.thread_id) queue
	spin_lock_bh(&last_offset_lock[st->process.thread_id]);
	if ( QUEUE_LAST_OFFSET(st->process.thread_id)!=0 ) 
		QUEUE_LAST_STREAM(st->process.thread_id)->internal.next_stream_offset=clone->internal.stream_offset;
	QUEUE_LAST_OFFSET(st->process.thread_id)=clone->internal.stream_offset;
	spin_unlock_bh(&last_offset_lock[st->process.thread_id]);

	spin_lock_bh(&read_offset_lock[st->process.thread_id]);
	if ( QUEUE_READ_OFFSET(st->process.thread_id)==0 )
		QUEUE_READ_OFFSET(st->process.thread_id)=clone->internal.stream_offset;

	//spin_lock_bh(&free_offset_lock[st->process.thread_id]);
	if ( QUEUE_FREE_OFFSET(st->process.thread_id)==0 ) 
		QUEUE_FREE_OFFSET(st->process.thread_id)=clone->internal.stream_offset;
	//spin_unlock_bh(&free_offset_lock[st->process.thread_id]);
	spin_unlock_bh(&read_offset_lock[st->process.thread_id]);

//	flush_dcache_page(virt_to_page(scap_stats_buffer.block_vec[clone->internal.stream_offset/scap_stats_buffer.block_size]));
//	if (clone->data_storage.curr_chunk!=NULL)
//		for (i=0; i<clone->data_storage.curr_chunk->block_nr; i++)
//			flush_dcache_page(virt_to_page(clone->data_storage.curr_chunk->block[i]));
//	smp_wmb();

	for (i=0; i<scap_stats.sockets_feed; i++) 
		if (scap_stats.scap_socket[i]!=NULL) 
			scap_stats.scap_socket[i]->sk.sk_data_ready(&scap_stats.scap_socket[i]->sk, 0); 
}

void termination_event(stream_t *st) {
	int i;

	stream_t *clone=clone_stream(st);
	if (clone==NULL) {
		printk("scap error: no stream_t memory\n");
		return;
	}

	clone->process.event=SCAP_EVENT_TERMINATION;

	//enqueue event and clone st to QUEUE_LAST_OFFSET(st->process.thread_id) queue
	spin_lock_bh(&last_offset_lock[st->process.thread_id]);
	if ( QUEUE_LAST_OFFSET(st->process.thread_id)!=0 ) 
		QUEUE_LAST_STREAM(st->process.thread_id)->internal.next_stream_offset=clone->internal.stream_offset;
	QUEUE_LAST_OFFSET(st->process.thread_id)=clone->internal.stream_offset;
	spin_unlock_bh(&last_offset_lock[st->process.thread_id]);

	spin_lock_bh(&read_offset_lock[st->process.thread_id]);
	if ( QUEUE_READ_OFFSET(st->process.thread_id)==0 )
		QUEUE_READ_OFFSET(st->process.thread_id)=clone->internal.stream_offset;

	//spin_lock_bh(&free_offset_lock[st->process.thread_id]);
	if ( QUEUE_FREE_OFFSET(st->process.thread_id)==0 ) 
		QUEUE_FREE_OFFSET(st->process.thread_id)=clone->internal.stream_offset;
	//spin_unlock_bh(&free_offset_lock[st->process.thread_id]);
	spin_unlock_bh(&read_offset_lock[st->process.thread_id]);

//	flush_dcache_page(virt_to_page(scap_stats_buffer.block_vec[clone->internal.stream_offset/scap_stats_buffer.block_size]));
//	smp_wmb();

	for (i=0; i<scap_stats.sockets_feed; i++) 
		if (scap_stats.scap_socket[i]!=NULL) 
			scap_stats.scap_socket[i]->sk.sk_data_ready(&scap_stats.scap_socket[i]->sk, 0); 
}


void expire_stream(stream_t *st) {

	spin_lock_bh(&hashtable_lock[st->hash]);

	if (st->hashtable_prev!=NULL) st->hashtable_prev->hashtable_next=st->hashtable_next;
else if (stream_hashtable[st->hash]==NULL) printk("scap_debug: hashtable PROBLEM\n");
	else stream_hashtable[st->hash]=st->hashtable_next;
	if (st->hashtable_next!=NULL) st->hashtable_next->hashtable_prev=st->hashtable_prev;

	spin_unlock_bh(&hashtable_lock[st->hash]);

	spin_lock_bh(&access_lock);

	if (st==access_head) access_head=st->access_next;
else if (st->access_prev==NULL) printk("scap_debug: PROBLEM h\n");
	else st->access_prev->access_next=st->access_next;
	if (st==access_tail) access_tail=st->access_prev;
else if (st->access_next==NULL) printk("scap_debug: PROBLEM t\n");
	else st->access_next->access_prev=st->access_prev;

	spin_unlock_bh(&access_lock);


	//lock
	scap_stats.expired_streams++;
	scap_stats.active_streams--;
	//unlock
if (DEBUG_PRINTK==1) printk("scap_debug: expired stream, expired stream number: %u\n",scap_stats.expired_streams);

	if (st->data_storage.curr_chunk!=NULL && st->status==STREAM_CLOSED && st->data_storage.curr_chunk->bytes_free>0) data_event(st);
	termination_event(st);
}

void find_stream_cutoff(stream_t *st) {
	struct scap_sock *sc=NULL;
	int i;

	st->cutoff=scap_stats.cutoff;

	for (i=0; i<scap_stats.sockets_feed; i++) 
		if (scap_stats.scap_socket[i]!=NULL) {
			sc=scap_stats.scap_socket[i];
			break; //testing
		}
	//sc=scap_stats.scap_socket[0];
	if (sc==NULL) return ;

	for (i=0; i<SCAP_DIRECTIONS; i++ ) {
		if (sc->conf.cutoff_per_direction[i]!=-2 && st->stream_hdr.direction==i)
			st->cutoff=sc->conf.cutoff_per_direction[i];
	}

if (DEBUG_PRINTK==1) printk("scap_debug: using cutoff %d for direction %d, for new stream\n",st->cutoff, st->stream_hdr.direction);

}

void find_direction(stream_t *st) {
	stream_t *tmp;

	spin_lock_bh(&hashtable_lock[st->hash]);
	for (tmp=stream_hashtable[st->hash]; tmp!=NULL; tmp=tmp->hashtable_next) {
		if ( (tmp->stream_hdr.dst_ip == st->stream_hdr.src_ip) && (tmp->stream_hdr.src_ip == st->stream_hdr.dst_ip) && 
		   (tmp->stream_hdr.protocol == st->stream_hdr.protocol) && 
		   (tmp->stream_hdr.dst_port == st->stream_hdr.src_port) && (tmp->stream_hdr.src_port == st->stream_hdr.dst_port) ) { 
			st->stream_hdr.direction=SCAP_SERVER_TO_CLIENT;
			st->opposite=tmp;
			tmp->opposite=st;
			spin_unlock_bh(&hashtable_lock[st->hash]);
			return;
		}
	}
	st->stream_hdr.direction=SCAP_CLIENT_TO_SERVER;
	st->opposite=NULL;
	spin_unlock_bh(&hashtable_lock[st->hash]);
}


scap_chunk_header_t* get_free_chunk(stream_t *st, int chunk_size) {
	scap_chunk_header_t* new_chunk;

	spin_lock_bh(&free_chunk_lock);

	if (free_chunk_list==NULL) {
		spin_unlock_bh(&free_chunk_lock);
		return NULL;
	}

	//overload condition, for dropped packets
	if ((scap_stats.unused_chunks<(scap_stats.total_chunks*BLOCK_THRESHOLD_A/BLOCK_THRESHOLD_B)) && st->data_storage.chunk_nr > STREAM_BLOCK_THRESHOLD) {
		spin_unlock_bh(&free_chunk_lock);
		return NULL;
	}

	new_chunk=free_chunk_list;
	free_chunk_list=free_chunk_list->next_chunk;  //remove from free chunk list
	scap_stats.used_chunks++;
	scap_stats.unused_chunks--;

	new_chunk->next_chunk=NULL;
	new_chunk->bytes_free=chunk_size;
	new_chunk->write_offset=0;
	new_chunk->isfree=0;

	spin_unlock_bh(&free_chunk_lock);
if (DEBUG_PRINTK==1) printk("scap_debug: chunks used: %u\n",scap_stats.used_chunks);

	return new_chunk;
}

void release_chunk(scap_chunk_header_t *chunk, int chunk_size) {

	if (chunk==NULL)
		return;

	if (chunk->isfree==1) {
		if (DEBUG_PRINTK==1) printk("scap_debug: PROBLEM double release!\n");
		return;
	}

	spin_lock_bh(&free_chunk_lock);

	if (free_chunk_list==NULL || free_chunk_list_tail==NULL) {
		free_chunk_list_tail=chunk;
		free_chunk_list=chunk;
	}
	else {
		free_chunk_list_tail->next_chunk=chunk;
		free_chunk_list_tail=chunk;
		//chunk->next_chunk=free_chunk_list;
		//free_chunk_list=chunk;
	}
	chunk->next_chunk=NULL;
	chunk->isfree=1;
	scap_stats.used_chunks--;
	scap_stats.unused_chunks++;

	spin_unlock_bh(&free_chunk_lock);

if (DEBUG_PRINTK==1) printk("scap_debug: chunks used: %u (released)\n",scap_stats.used_chunks);

}

int write_data_to_chunk(scap_chunk_header_t* chunk_hdr, unsigned char *data, int len) {
	unsigned int written=0, tmp_written=0;

	if (len > chunk_hdr->bytes_free)
		return -1;

//	spin_lock_bh(&block_lock[block_hdr->id]);
	while (written<len) {
		tmp_written=min_len((unsigned int)len-written, (unsigned int)(scap_data_buffer.block_size-(chunk_hdr->write_offset%scap_data_buffer.block_size)));
		memcpy(chunk_hdr->block[chunk_hdr->write_offset/scap_data_buffer.block_size] + (chunk_hdr->write_offset%scap_data_buffer.block_size), data+written, tmp_written);
		chunk_hdr->bytes_free-=tmp_written;
		chunk_hdr->write_offset+=tmp_written;
		written+=tmp_written;
	}
//	spin_unlock_bh(&block_lock[block_hdr->id]);
	return len;
}

static inline void drop_packet(struct sk_buff *skb, u8 *skb_head, int skb_len) {

	scap_stats.dropped_pkts++;
	scap_stats.dropped_bytes+=skb->len;

	if (skb_head != skb->data && skb_shared(skb)) {
		skb->data = skb_head;
		skb->len = skb_len;
	}

	kfree_skb(skb);
}

static inline void discard_packet(struct sk_buff *skb, u8 *skb_head, int skb_len) {

	scap_stats.discarded_pkts++;
	scap_stats.discarded_bytes+=skb->len;

	if (skb_head != skb->data && skb_shared(skb)) {
		skb->data = skb_head;
		skb->len = skb_len;
	}

	kfree_skb(skb);
}

static inline void filter_packet(struct sk_buff *skb, u8 *skb_head, int skb_len) {

	scap_stats.filtered_pkts++;
	scap_stats.filtered_bytes+=skb->len;

	if (skb_head != skb->data && skb_shared(skb)) {
		skb->data = skb_head;
		skb->len = skb_len;
	}

	kfree_skb(skb);
}


//packet handler
static int packet_recv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{ 
//per-packet operation
	u8 *skb_head = skb->data;
	int skb_len = skb->len;
	//unsigned int res=1;
	//struct sk_filter *filter;
	EtherHdr *eth;
	IPHdr *iph;
	TCPHdr *tcph=NULL;
	UDPHdr *udph=NULL;
	int hlen, tcplen;
	uint32_t ip_src, ip_dst;
	uint16_t sport, dport;
	stream_t *st, *st2;
	unsigned int hash;
	unsigned char *data;
	uint16_t data_len, data_write_len;
	struct timeval now;
	//struct timeval last_access;
	int i;

	if (skb->pkt_type == PACKET_LOOPBACK) {
		kfree_skb(skb);
		return 0;
	}

	skb_push(skb, skb->data - skb_mac_header(skb));


// decode
	eth = (EtherHdr *) skb->data;
	if ( ntohs(eth->ether_type) != ETHERNET_TYPE_IP ) {  //not ip packet
		if (skb_head != skb->data && skb_shared(skb)) {
			skb->data = skb_head;
			skb->len = skb_len;
		}

		kfree_skb(skb);
		return 0;
	}

	iph = (IPHdr *) ( (u_char*)(skb->data + ETHERNET_HEADER_LEN));
	hlen = ((iph)->ip_verhl & 0x0f) << 2;
	ip_src = (iph->ip_src).s_addr;
	ip_dst = (iph->ip_dst).s_addr;

	if ( iph->ip_proto == IPPROTO_TCP) {
		tcph = (TCPHdr *) ((u_char*)(skb->data + ETHERNET_HEADER_LEN + hlen));
		sport = ntohs(tcph->th_sport);
		dport = ntohs(tcph->th_dport);
		tcplen= tcph->th_offx2 >> 2;
		data = skb->data + ETHERNET_HEADER_LEN + hlen + tcplen;
		data_len = (uint16_t)(skb->len - (ETHERNET_HEADER_LEN + hlen + tcplen));
	}
	else if (iph->ip_proto == IPPROTO_UDP) {
		udph = (UDPHdr *) ((u_char*)(skb->data + ETHERNET_HEADER_LEN + hlen));
		sport = ntohs(udph->uh_sport);
		dport = ntohs(udph->uh_dport);
		data = skb->data + ETHERNET_HEADER_LEN + hlen + sizeof(UDPHdr);
		data_len = skb->len - (ETHERNET_HEADER_LEN + hlen + sizeof(UDPHdr));
	}
	else {
		sport=0;
		dport=0;
		data = skb->data + ETHERNET_HEADER_LEN + hlen;
		data_len = skb->len - (ETHERNET_HEADER_LEN + hlen);
	}

	//get timestamp
	if (skb->tstamp.tv64)
		now=ktime_to_timeval(skb->tstamp);
	else do_gettimeofday(&now);

	data_write_len=data_len;
if (DEBUG_PRINTK==1) printk("scap debug skb len: %d data_len %d\n",skb->len,data_len);

	scap_stats.bytes+=data_len;
	scap_stats.pkts++;


	spin_lock_bh(&expire_streams_lock);
	if (scap_stats.expire_streams==0) {
		scap_stats.expire_streams=1;
		spin_unlock_bh(&expire_streams_lock);

		//expired streams process: compare now with stream timestamps strarting from access_tail and add expired to read list after last
		for (st=access_tail; st!=NULL; st=st2) {
			st2=st->access_prev;
			if ( (int)(now.tv_sec - st->stream_stats.end.tv_sec) > scap_stats.timeout ) {
				if (st->status_detail==STREAM_ACTIVE_CUTOFF) st->status=STREAM_CLOSED_STATS_ONLY;
				else st->status=STREAM_CLOSED;
				st->status_detail=STREAM_CLOSED_TIMEOUT;
				if (DEBUG_PRINTK==1) printk("scap_debug: stream expired timeout\n");
				expire_stream(st);
			}
			else break;
		}

		//release blocks and streams
		for (i=0; i<scap_stats.thread_num; i++) {
			spin_lock_bh(&free_offset_lock[i]);
			while ( QUEUE_FREE_OFFSET(i)!=0 && QUEUE_FREE_OFFSET(i)!=QUEUE_READ_OFFSET(i) ) {
				st=QUEUE_FREE_STREAM(i);
				if (st->process.event==SCAP_EVENT_DATA_CHUNK) {
					if (st->data_storage.curr_chunk!=NULL) 
						release_chunk(st->data_storage.curr_chunk, st->process.chunk_size);
				}
				if (st->process.event==SCAP_EVENT_TERMINATION) {
					release_stream_node(st->internal.flush_clone);
				}
				QUEUE_FREE_OFFSET(i)=st->internal.next_stream_offset;
				release_stream_node(st);
			}
			spin_unlock_bh(&free_offset_lock[i]);
		}

		scap_stats.expire_streams=0;
	}
	else
		spin_unlock_bh(&expire_streams_lock);


        hash = (iph->ip_proto + ip_src + ip_dst + sport + dport);
	hash = (UNIVERSAL_HASHING_A * hash) >> 14;

	spin_lock_bh(&hashtable_lock[hash]);

	if (stream_hashtable[hash]==NULL) {
		spin_unlock_bh(&hashtable_lock[hash]);
		st=new_stream(hash);
		if (st==NULL) {
			drop_packet(skb, skb_head, skb_len);
			return -ENOMEM;
		}

		//stream header
		st->stream_hdr.src_ip=ip_src;
		st->stream_hdr.dst_ip=ip_dst;
		st->stream_hdr.src_port=sport;
		st->stream_hdr.dst_port=dport;
		st->stream_hdr.protocol=iph->ip_proto;
		find_direction(st);
		//stream stats
		st->stream_stats.start=now;
		st->stream_stats.end=now;
		st->stream_stats.bytes=data_len;
		st->stream_stats.pkts=1;
		st->stream_stats.bytes_dropped=0;
		st->stream_stats.bytes_discarded=0;
		st->stream_stats.pkts_dropped=0;
		st->stream_stats.pkts_discarded=0;

		find_stream_cutoff(st);
		//st->cutoff=scap_stats.cutoff;
		if (st->cutoff!=0) st->internal.write_data=1;

		creation_event(st);

		if (st->cutoff!=-1) data_write_len=(uint16_t)min_len((unsigned int) st->cutoff,(unsigned int)data_len);
		if (data_write_len>0) {
			//data storage
			uint16_t written=0;
			scap_chunk_header_t *new_chunk=get_free_chunk(st, st->process.chunk_size);

			if (new_chunk==NULL) {
				if (DEBUG_PRINTK==1) printk("scap: no blocks available\n");
				drop_packet(skb, skb_head, skb_len);
				return -ENOMEM;
			}

			st->data_storage.curr_chunk=new_chunk;
			st->data_storage.chunk_nr++;
			written=(uint16_t)min_len((uint16_t)st->data_storage.curr_chunk->bytes_free, data_write_len);
			write_data_to_chunk(st->data_storage.curr_chunk, data, written);

			//chunk size event
			if (st->data_storage.curr_chunk->bytes_free==0) {
				data_event(st);
				st->data_storage.curr_chunk=NULL;
			}

			while (written<data_write_len) {
				scap_chunk_header_t *next_chunk=get_free_chunk(st, st->process.chunk_size);
				uint16_t tmp_written;

				if (next_chunk==NULL) {
					if (DEBUG_PRINTK==1) printk("scap: no blocks available\n");
					drop_packet(skb, skb_head, skb_len);
					return -ENOMEM;
				}

				st->data_storage.chunk_nr++;
				tmp_written=(uint16_t)min_len((uint16_t)next_chunk->bytes_free, data_write_len-written);
				write_data_to_chunk(next_chunk, data+written, tmp_written);
				st->data_storage.curr_chunk=next_chunk;
				written+=tmp_written;

				//chunk size event
				if (st->data_storage.curr_chunk->bytes_free==0) {
					data_event(st);
					st->data_storage.curr_chunk=NULL;
				}
			}
		}

		st->stream_stats.bytes_captured=data_write_len;
		if (data_write_len>0) st->stream_stats.pkts_captured=1;

		if (data_len>data_write_len) {
			//cutoff triggered

			st->stream_stats.bytes_discarded=data_len-data_write_len;
			if (st->cutoff==0) st->stream_stats.pkts_discarded++;
			// same with scap_stats.bytes_discarded  scap_stats.pkts_discarded

			st->status_detail=STREAM_ACTIVE_CUTOFF;
			st->internal.write_data=0;

			if ( st->data_storage.curr_chunk!=NULL && st->data_storage.curr_chunk->bytes_free>0 ) data_event(st);
if (DEBUG_PRINTK==1) printk("scap_debug:stream cutoff reached\n");
		}
	}
	else {
		for (st=stream_hashtable[hash]; st!=NULL; st=st->hashtable_next) {
			if ( (ip_src == st->stream_hdr.src_ip) && (ip_dst == st->stream_hdr.dst_ip) && (iph->ip_proto == st->stream_hdr.protocol) && 
			     (sport == st->stream_hdr.src_port) && (dport == st->stream_hdr.dst_port) ) { 
				//match
				spin_unlock_bh(&hashtable_lock[hash]);				

				//update stats
				//last_access=st->stream_stats.end;
				st->stream_stats.end=now;
				st->stream_stats.bytes+=data_len;
				st->stream_stats.pkts++;

				if (st->status_detail==STREAM_ACTIVE_CUTOFF) data_write_len=0;
				else if (st->cutoff==0 || st->stream_stats.bytes_captured>=st->cutoff) data_write_len=0;

				else if (st->cutoff>0) data_write_len=(uint16_t)min_len((unsigned int)st->cutoff - st->stream_stats.bytes_captured, (unsigned int)data_len);
				if (data_write_len>0 && st->internal.write_data==1) {
					//data storage
					uint16_t written=0;

					if (st->data_storage.curr_chunk==NULL) {
						scap_chunk_header_t *new_chunk=get_free_chunk(st, st->process.chunk_size);

						if (new_chunk==NULL) {
							if (DEBUG_PRINTK==1) printk("scap: no blocks available\n");
							drop_packet(skb, skb_head, skb_len);
							return -ENOMEM;
						}

						st->data_storage.curr_chunk=new_chunk;
						st->data_storage.chunk_nr++;
					}

					written=(uint16_t)min_len((uint16_t)st->data_storage.curr_chunk->bytes_free, data_write_len);
					write_data_to_chunk(st->data_storage.curr_chunk, data, written);

					//chunk size event
					if (st->data_storage.curr_chunk->bytes_free==0) {
						data_event(st);
						st->data_storage.curr_chunk=NULL;
					}

					while (written<data_write_len) {
						scap_chunk_header_t *next_chunk=get_free_chunk(st, st->process.chunk_size);
						uint16_t tmp_written=0;

						if (next_chunk==NULL) {
							if (DEBUG_PRINTK==1) printk("scap_debug: no blocks available\n");
							drop_packet(skb, skb_head, skb_len);
							return -ENOMEM;
						}

						st->data_storage.chunk_nr++;
						tmp_written=(uint16_t)min_len((uint16_t)next_chunk->bytes_free, data_write_len - written);
						write_data_to_chunk(next_chunk, data+written, tmp_written);

						st->data_storage.curr_chunk=next_chunk;
						written+=tmp_written;

						//chunk size event
						if (st->data_storage.curr_chunk->bytes_free==0) {
							data_event(st);
							st->data_storage.curr_chunk=NULL;
						}
					}

					st->stream_stats.bytes_captured+=data_write_len;
					st->stream_stats.pkts_captured++;
				}

				if (data_len > data_write_len) {
					st->stream_stats.bytes_discarded+=data_len-data_write_len;
					if (data_write_len==0) st->stream_stats.pkts_discarded++;
					// same with scap_stats.bytes_discarded  scap_stats.pkts_discarded

					if (st->status_detail!=STREAM_ACTIVE_CUTOFF) {
						//cutoff triggered
						st->status_detail=STREAM_ACTIVE_CUTOFF;
						st->internal.write_data=0;

						if ( st->data_storage.curr_chunk!=NULL && st->data_storage.curr_chunk->bytes_free>0 ) data_event(st);
						if (DEBUG_PRINTK==1) printk("scap_debug:stream cutoff reached\n");
					}
				}

				if (iph->ip_proto==IPPROTO_TCP && (tcph->th_flags & TCP_FIN)) {
					if (st->status_detail==STREAM_ACTIVE_CUTOFF) st->status=STREAM_CLOSED_STATS_ONLY;
					else st->status=STREAM_CLOSED;
					st->status_detail=STREAM_CLOSED_TCP_FIN;
					expire_stream(st);
				}
				else if (iph->ip_proto==IPPROTO_TCP && (tcph->th_flags & TCP_RST)) {
					if (st->status_detail==STREAM_ACTIVE_CUTOFF) st->status=STREAM_CLOSED_STATS_ONLY;
					else st->status=STREAM_CLOSED;
					st->status_detail=STREAM_CLOSED_TCP_RST;
					expire_stream(st);
				}
				//else if (now.tv_sec - last_access.tv_sec > scap_stats.timeout) {
				//	if (st->status_detail==STREAM_ACTIVE_CUTOFF) st->status=STREAM_CLOSED_STATS_ONLY;
				//	else st->status=STREAM_CLOSED;
				//	st->status_detail=STREAM_CLOSED_TIMEOUT;
				//	expire_stream(st);
				//}
				else {
					//if not expired
					spin_lock_bh(&access_lock);
					if (st!=access_head) {
if (st->access_prev==NULL) printk("scap_debug: PROBLEM head\n");
else						st->access_prev->access_next=st->access_next;
						if (st==access_tail) access_tail=st->access_prev;
else if (st->access_next==NULL) printk("scap debug: PROBLEM tail\n");
						else st->access_next->access_prev=st->access_prev;
						st->access_prev=NULL;
						st->access_next=access_head;
						if (access_head!=NULL) access_head->access_prev=st;
						access_head=st;
					}
					spin_unlock_bh(&access_lock);
				}

				//XXX timeout based data event

				break;
			}
		}
		if (st==NULL) { //new stream
			spin_unlock_bh(&hashtable_lock[hash]);
			st=new_stream(hash);
			if (st==NULL) {
				drop_packet(skb, skb_head, skb_len);
				return -ENOMEM;
			}

			//stream header
			st->stream_hdr.src_ip=ip_src;
			st->stream_hdr.dst_ip=ip_dst;
			st->stream_hdr.src_port=sport;
			st->stream_hdr.dst_port=dport;
			st->stream_hdr.protocol=iph->ip_proto;
			find_direction(st);
			//stream stats
			st->stream_stats.start=now;
			st->stream_stats.end=now;
			st->stream_stats.bytes=data_len;
			st->stream_stats.pkts=1;
			st->stream_stats.bytes_dropped=0;
			st->stream_stats.bytes_discarded=0;
			st->stream_stats.pkts_dropped=0;
			st->stream_stats.pkts_discarded=0;

			find_stream_cutoff(st);
			//st->cutoff=scap_stats.cutoff;
			if (st->cutoff!=0) st->internal.write_data=1;

			creation_event(st);

			if (st->cutoff!=-1) data_write_len=(uint16_t)min_len((unsigned int)st->cutoff,(unsigned int)data_len);
			if (data_write_len>0) {
				//data storage
				uint16_t written=0;
				scap_chunk_header_t *new_chunk=get_free_chunk(st, st->process.chunk_size);

				if (new_chunk==NULL) {
					if (DEBUG_PRINTK==1) printk("scap: no blocks available 3\n");
					drop_packet(skb, skb_head, skb_len);
					return -ENOMEM;
				}

				st->data_storage.curr_chunk=new_chunk;
				st->data_storage.chunk_nr++;
				written=(uint16_t)min_len((uint16_t)st->data_storage.curr_chunk->bytes_free, data_write_len);
				write_data_to_chunk(st->data_storage.curr_chunk, data, written);

				//chunk size event
				if (st->data_storage.curr_chunk->bytes_free==0) {
					data_event(st);
					st->data_storage.curr_chunk=NULL;
				}

				while (written<data_write_len) {
					scap_chunk_header_t *next_chunk=get_free_chunk(st, st->process.chunk_size);
					uint16_t tmp_written;

					if (next_chunk==NULL) {
						if (DEBUG_PRINTK==1) printk("scap: no blocks available 3a");
						drop_packet(skb, skb_head, skb_len);
						return -ENOMEM;
					}

					st->data_storage.chunk_nr++;
					tmp_written=(uint16_t)min_len((uint16_t)next_chunk->bytes_free, data_write_len-written);
					write_data_to_chunk(next_chunk, data+written, tmp_written);
					st->data_storage.curr_chunk=next_chunk;
					written+=tmp_written;

					//chunk size event
					if (st->data_storage.curr_chunk->bytes_free==0) {
						data_event(st);
						st->data_storage.curr_chunk=NULL;
					}
				}
			}

			st->stream_stats.bytes_captured=data_write_len;
			if (data_write_len>0) st->stream_stats.pkts_captured=1;

			if (data_len>data_write_len) {
				//cutoff triggered

				st->stream_stats.bytes_discarded=data_len-data_write_len;
				if (st->cutoff==0) st->stream_stats.pkts_discarded++;
				// same with scap_stats.bytes_discarded  scap_stats.pkts_discarded

				st->status_detail=STREAM_ACTIVE_CUTOFF;
				st->internal.write_data=0;

				if ( st->data_storage.curr_chunk!=NULL && st->data_storage.curr_chunk->bytes_free>0 ) data_event(st);
if (DEBUG_PRINTK==1) printk("scap_debug:stream cutoff reached\n");
			}
		}
	}

	if (DEBUG_PRINTK==1) printk("packet received with size %d\n",skb->len);
	scap_stats.bytes_written+=data_write_len;

	if (skb_head != skb->data && skb_shared(skb)) {
		skb->data = skb_head;
		skb->len = skb_len;
	}
	kfree_skb(skb);
	return 0;
}


// scap socket create
static int scap_create(struct net *net, struct socket *sock, int protocol)
{
	struct sock *sk;
	struct scap_sock *scap_sk;

	if (!capable(CAP_NET_RAW))
		return -EPERM;

	sock->state = SS_UNCONNECTED;

	sk = sk_alloc(net, PF_SCAP, GFP_KERNEL, &scap_proto);
	if (sk == NULL) return -ENOBUFS;

	sock->ops = &scap_ops;

	sock_init_data(sock, sk);

	scap_sk = (struct scap_sock*)sk;
	sk->sk_family = PF_SCAP;

	sk_refcnt_debug_inc(sk);

	scap_sk->configured=0;
	scap_sk->running=0;
	scap_sk->mapped_stats=0;

	scap_sk->scap_sock_id=scap_stats.sockets_feed;
	scap_stats.scap_socket[scap_sk->scap_sock_id]=scap_sk;
	scap_stats.socket_filter[scap_sk->scap_sock_id]=NULL;
	scap_stats.sockets++;
	scap_stats.sockets_feed++;

	write_lock_bh(&net->packet.sklist_lock);
	sk_add_node(sk, &net->packet.sklist);
	sock_prot_inuse_add(net, &scap_proto, 1);
	write_unlock_bh(&net->packet.sklist_lock);

	printk("create scap socket. type %d %d protocol %d %d\n",sock->type,PF_SCAP,protocol,htons(ETH_P_ALL));

	return 0;
}

// scap socket release
static int scap_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct scap_sock *scap_sk;
	struct net *net;
	int i;

	if (!sk)
		return 0;

	net = sock_net(sk);
	scap_sk = (struct scap_sock*)sk;

	write_lock_bh(&net->packet.sklist_lock);
	sk_del_node_init(sk);
	sock_prot_inuse_add(net, sk->sk_prot, -1);
	write_unlock_bh(&net->packet.sklist_lock);

	scap_stats.sockets--;
	scap_stats.scap_socket[scap_sk->scap_sock_id]=NULL;
	scap_stats.socket_filter[scap_sk->scap_sock_id]=NULL;

	if (scap_sk->running==1) {
		scap_stats.running_sockets--;
		if (scap_stats.running_sockets==0) {
			dev_remove_pack(&protocol_hook);
		}
	}
	if (scap_stats.sockets==0) {
		if (scap_data_buffer.initialized==1) {
			for (i=0; i<scap_stats.total_chunks; i++)
				if (free_chunk_list_alloc[i].block!=NULL) kfree(free_chunk_list_alloc[i].block);
			if (free_chunk_list_alloc!=NULL) kfree(free_chunk_list_alloc);
			//kfree(block_lock);
			scap_release_buffer(&scap_data_buffer);
			scap_data_buffer.initialized=0;
		}
		if (scap_stats_buffer.initialized==1) {
			scap_release_buffer(&scap_stats_buffer);
			//kfree(stream_lock);
			scap_stats_buffer.initialized=0;
		}
		if (shared_q.initialized==1) {
			scap_release_buffer(&shared_q);
			shared_q.initialized=0;
		}
	}
	if (scap_sk->conf.need_packets>0) 
		scap_stats.need_packets--;

memset(&scap_stats,0,sizeof(scap_module_stats_t)); 

	sock_orphan(sk);
	sock->sk = NULL;

	sk_refcnt_debug_release(sk);

	printk("release scap socket\n");

	return 0;
}

int scap_make_list(void) {

	int i,j;
	stream_t *st=NULL;
	uint32_t id_feed=0;

	free_stream=(stream_t*)(scap_stats_buffer.block_vec[0]);

	//stream_lock=kzalloc(STREAM_NUM * sizeof(spinlock_t), GFP_KERNEL);
	//if (unlikely(!stream_lock))
	//	return -ENOMEM;

	for (i=0; i<scap_stats_buffer.block_nr; i++) {
		for (j=0; j+sizeof(stream_t)<scap_stats_buffer.block_size; j+=sizeof(stream_t)) {
			if (st!=NULL) {
				st->internal.next_stream_offset=(i*scap_stats_buffer.block_size)+j;
				st->next=(stream_t*)(scap_stats_buffer.block_vec[i]+j);
			}
			st=(stream_t*)(scap_stats_buffer.block_vec[i]+j);
			st->status=STREAM_FREE;
			st->status_detail=STREAM_NOT_DELIVERED;
			st->hashtable_next=NULL;
			st->hashtable_prev=NULL;
			st->access_next=NULL;
			st->access_prev=NULL;
			st->internal.stream_offset=(i*scap_stats_buffer.block_size)+j;
			st->internal.id=id_feed;
			id_feed++;
			//spin_lock_init(&stream_lock[st->internal.id]);
		}
	}
	st->internal.next_stream_offset=0;
	st->next=NULL;
	free_stream_tail=st;

	for (i=0; i<MAX_QUEUES; i++) {
		QUEUE_READ_OFFSET(i)=0;
		QUEUE_LAST_OFFSET(i)=0;
		QUEUE_FREE_OFFSET(i)=0;
		spin_lock_init(&read_offset_lock[i]);
		spin_lock_init(&last_offset_lock[i]);
		spin_lock_init(&free_offset_lock[i]);
	}

	scap_stats.free_stream_nodes=STREAM_NUM;

	for (i=0; i<HASHTABLE_SIZE; i++){
		stream_hashtable[i] = 0;
		spin_lock_init(&hashtable_lock[i]);
	}

	access_head=NULL;
	access_tail=NULL;

	spin_lock_init(&access_lock);
	spin_lock_init(&free_stream_lock);
	spin_lock_init(&expire_streams_lock);

	return 0;
}

int scap_make_free_block_list(void) {

	int i,j,k=0;

	scap_stats.total_chunks=(scap_data_buffer.block_size*scap_data_buffer.block_nr)/scap_stats.chunk_size;
	printk("total chunks: %u\n",scap_stats.total_chunks);

	free_chunk_list_alloc=kzalloc(scap_stats.total_chunks * sizeof(scap_chunk_header_t), GFP_KERNEL);
	//block_lock=kzalloc(scap_stats.total_blocks * sizeof(spinlock_t), GFP_KERNEL);
	//if (unlikely(!free_block_list_alloc) || unlikely(!block_lock))
	//	return -ENOMEM;

	free_chunk_list=free_chunk_list_alloc;
	for (i=0; i<scap_stats.total_chunks; i++) {
		free_chunk_list[i].block_nr=scap_stats.chunk_size/scap_data_buffer.block_size;
		if ( (scap_stats.chunk_size%scap_data_buffer.block_size)!=0 ) free_chunk_list[i].block_nr+=1;
		free_chunk_list[i].block=(char**)kzalloc(free_chunk_list[i].block_nr*sizeof(char*), GFP_KERNEL);
		for (j=0; j<free_chunk_list[i].block_nr; j++)
			free_chunk_list[i].block[j]=scap_data_buffer.block_vec[k++];
		free_chunk_list[i].data_offset=i*scap_stats.chunk_size;
		if (i+1==scap_stats.total_chunks) 
			free_chunk_list[i].next_chunk=NULL;
		else 
			free_chunk_list[i].next_chunk=&free_chunk_list[i+1];
		free_chunk_list[i].bytes_free=scap_stats.chunk_size;
		free_chunk_list[i].write_offset=0;
		free_chunk_list[i].chunk_size=scap_stats.chunk_size;
		free_chunk_list[i].isfree=1;
		//free_chunk_list[i].id=i;
		//spin_lock_init(&block_lock[i]);
	}
	free_chunk_list_tail=&free_chunk_list[i-1];

	scap_stats.unused_chunks=scap_stats.total_chunks;
	scap_stats.used_chunks=0;

	spin_lock_init(&free_chunk_lock);

	return 0;
}

//util functions
static void free_block_vec(char **block_vec, unsigned int order, unsigned int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (likely(block_vec[i]))
			free_pages((unsigned long) block_vec[i], order);
	}
	kfree(block_vec);
}

static inline char *alloc_one_block(unsigned long order)
{
	gfp_t gfp_flags = GFP_KERNEL | __GFP_COMP | __GFP_ZERO | __GFP_NOWARN;

	return (char *) __get_free_pages(gfp_flags, order);
}

static char **alloc_block_vec(unsigned int block_nr, int order)
{
	char **block_vec;
	int i;

	block_vec = kzalloc(block_nr * sizeof(char *), GFP_KERNEL);
	if (unlikely(!block_vec))
		return block_vec;

	for (i = 0; i < block_nr; i++) {
		block_vec[i] = alloc_one_block(order);
		if (unlikely(!block_vec[i])) {
			free_block_vec(block_vec, order, block_nr);
			return NULL;
		}	
	}

	return block_vec;
}

//Allocate an scap mmaped buffer
static int scap_set_buffer(scap_buffer_t *buff, unsigned int block_nr, unsigned block_size)
{
	printk("Setting scap buffer. block number: %d block size: %d page size: %lu\n",block_nr,block_size,PAGE_SIZE);

	if (unlikely(block_nr == 0))
		return -EINVAL;
	if (unlikely(block_size == 0))
		return -EINVAL;
	if (unlikely(buff->block_vec)) 
		return -EBUSY;
	//if (unlikely(block_size & (PAGE_SIZE - 1)))
	//	return -EINVAL;

	buff->block_order = get_order(block_size);
	buff->block_vec = alloc_block_vec(block_nr, buff->block_order);
	if (unlikely(!buff->block_vec))
		return -ENOMEM;

	buff->block_nr = block_nr;
	buff->block_pages = block_size/PAGE_SIZE;
	buff->block_size = block_size;
	spin_lock_init(&buff->buff_lock);

	return 0;
}

//free scap buffer on closing
static int scap_release_buffer(scap_buffer_t *buff)
{
	printk("release scap buffer\n");

	if (buff->block_vec) {
		free_block_vec(buff->block_vec, buff->block_order, buff->block_nr);
		buff->block_vec=NULL;
	}
	return 0;
}


static int scap_mmap(struct file *file, struct socket *sock, struct vm_area_struct *vma)
{
	struct sock *sk = sock->sk;
	struct scap_sock *scap_sk = (struct scap_sock *)sk;
	unsigned long start, size;
	int i, err;
	struct page *page;
	int pg_num;

//	if (vma->vm_pgoff)
//		return -EINVAL;

	size = vma->vm_end - vma->vm_start;

 	//vma->vm_flags |= VM_RESERVED;	/* avoid to swap out this VMA */
	printk("mmap size: %lu vm_pgoff: %lu start %lu, end %lu\n",size,vma->vm_pgoff,vma->vm_start,vma->vm_end);

	if (scap_sk->mapped_stats == 0) {

		start = vma->vm_start;
		for (i = 0; i < shared_q.block_nr; i++) {
			page = virt_to_page(shared_q.block_vec[i]);

			for (pg_num = 0; pg_num < shared_q.block_pages; pg_num++, page++) {
				err = vm_insert_page(vma, start, page);
				if (unlikely(err)) return err;
				start += PAGE_SIZE;
			}
		}
		scap_sk->mapped_stats=1;
		//vma->vm_pgoff=0;
		//vma->vm_private_data=NULL;
	}
	else if (scap_sk->mapped_stats == 1) {

		start = vma->vm_start;
		for (i = 0; i < scap_stats_buffer.block_nr; i++) {
			page = virt_to_page(scap_stats_buffer.block_vec[i]);

			for (pg_num = 0; pg_num < scap_stats_buffer.block_pages; pg_num++, page++) {
				err = vm_insert_page(vma, start, page);
				if (unlikely(err)) return err;
				start += PAGE_SIZE;
			}
		}
		scap_sk->mapped_stats=2;
		//vma->vm_pgoff=0;
		//vma->vm_private_data=NULL;
	}

	else if (scap_sk->mapped_stats == 2) {

		start = vma->vm_start;
		for (i = 0; i < scap_data_buffer.block_nr; i++) {
			page = virt_to_page(scap_data_buffer.block_vec[i]);

			for (pg_num = 0; pg_num < scap_data_buffer.block_pages; pg_num++, page++) {
				err = vm_insert_page(vma, start, page);
				if (unlikely(err)) return err;
				start += PAGE_SIZE;
			}
		}
		scap_sk->mapped_stats=3;
		//vma->vm_pgoff=0;
		//vma->vm_private_data=NULL;
	}

	printk("scap mmap\n");

	return 0;
}


static unsigned int scap_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	struct sock *sk = sock->sk;
//	struct scap_sock *scap_sk = (struct scap_sock *)sk;
	unsigned int mask = 0;
	int i;

if (DEBUG_PRINTK==1) printk("scap poll\n");
//if (sock==NULL) { printk("PROBLEM in poll\n"); return 0; }

	poll_wait(file, sk->sk_sleep, wait);

	for (i=0; i<scap_stats.thread_num; i++) {
		spin_lock_bh(&read_offset_lock[i]);
		if (QUEUE_READ_OFFSET(i)!=0) {
			mask |= POLLIN | POLLRDNORM;
			spin_unlock_bh(&read_offset_lock[i]);
			break;
		}
		spin_unlock_bh(&read_offset_lock[i]);
	}

	return mask;
}


static int scap_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct scap_sock *scap_sk = (struct scap_sock *)sk;
	int len;
	//int val;
	void *data;
	scap_stats_t stats;

	if (scap_sk==NULL) return -EINVAL;

	printk("scap getsockopt level: %d optname: %d\n",level,optname);

	if (get_user(len, optlen))
		return -EFAULT;

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case GET_SCAP_STATS:
		if (len > sizeof(scap_stats_t))
			len = sizeof(scap_stats_t);
		else if (len < sizeof(scap_stats_t))
			return -EINVAL;

		stats.active_streams=scap_stats.active_streams;
		stats.expired_streams=scap_stats.expired_streams;
		stats.total_streams=scap_stats.total_streams;
		stats.used_chunks=scap_stats.used_chunks;
		stats.unused_chunks=scap_stats.unused_chunks;
		stats.total_chunks=scap_stats.total_chunks;
		stats.bytes=scap_stats.bytes;
		stats.bytes_written=scap_stats.bytes_written;
		stats.pkts=scap_stats.pkts;
		stats.dropped_bytes=scap_stats.dropped_bytes;
		stats.dropped_pkts=scap_stats.dropped_pkts;
		stats.discarded_bytes=scap_stats.discarded_bytes;
		stats.discarded_pkts=scap_stats.discarded_pkts;
		stats.filtered_bytes=scap_stats.filtered_bytes;
		stats.filtered_pkts=scap_stats.filtered_pkts;

		data = &stats;
		break;
	case GET_INT:   //example
//		if (len > sizeof(unsigned int))
//			len = sizeof(unsigned int);
//		val = po->tp_loss;
//		data = &val;
		break;
	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, data, len))
		return -EFAULT;
	return 0;
}

static int scap_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct scap_sock *scap_sk = (struct scap_sock *)sk;
	int ret;

	if (scap_sk==NULL) return -EINVAL;

	printk("scap setsockopt level: %d optname: %d len: %u\n",level,optname,optlen);

	switch (optname) {
	case CONFIGURE:
	{
		if (optlen < sizeof(scap_conf_t)) 
			return -EINVAL;

		if (copy_from_user(&scap_sk->conf, optval, sizeof(scap_conf_t))) 
			return -EFAULT;

		scap_stats.chunk_size=scap_sk->conf.chunk_size;
		scap_stats.overlap=scap_sk->conf.overlap;
		scap_stats.flush_timeout=scap_sk->conf.flush_timeout;
		scap_stats.thread_num=1;
		scap_stats.thread_rr=0;
//		if (scap_sk->conf.cutoff>scap_stats.cutoff) scap_stats.cutoff=scap_sk->conf.cutoff;
		scap_stats.cutoff=scap_sk->conf.cutoff;
		printk("scap: using cutoff %d bytes per stream\n",scap_stats.cutoff);
//		if (scap_stats.timeout==0 || scap_sk->conf.timeout<scap_stats.timeout) scap_stats.timeout=scap_sk->conf.timeout;
		scap_stats.timeout=scap_sk->conf.timeout;
		printk("scap: using timeout %d seconds of inactivity to expire streams\n",scap_stats.timeout);

		if (shared_q.initialized==0) {
			if ( (ret=scap_set_buffer(&shared_q, 1, PAGE_SIZE))<0 )
				return ret;
			shared_q.initialized=1;
		}
		if (scap_stats_buffer.initialized==0) {
			if ( (ret=scap_set_buffer(&scap_stats_buffer, scap_sk->conf.stats_block_nr, scap_sk->conf.stats_block_size))<0 )
				return ret;
			if ( scap_make_list() < 0 )
				return -ENOMEM;
			scap_stats_buffer.initialized=1;
		}
		//if (scap_data_buffer.initialized==0) {
		//	if ( (ret=scap_set_buffer(&scap_data_buffer, scap_sk->conf.data_block_nr, scap_sk->conf.data_block_size))<0 )
		//		return ret;
		//	if ( scap_make_free_block_list() < 0)
		//		return -ENOMEM;
		//	scap_data_buffer.initialized=1;
		//}


		if (scap_sk->conf.need_packets>0) 
			scap_stats.need_packets++;
		

		scap_sk->configured=1;
		return 0;
	}
	case START:
	{
		struct net_device *dev=NULL;

		if (scap_sk->configured==0)
			return -EFAULT;

		if (scap_data_buffer.initialized==0) {
			if ( (ret=scap_set_buffer(&scap_data_buffer, scap_sk->conf.data_block_nr, scap_sk->conf.data_block_size))<0 )
				return ret;
			if ( scap_make_free_block_list() < 0)
				return -ENOMEM;
			scap_data_buffer.initialized=1;
		}

		scap_stats.expire_streams=0;

		if (scap_stats.running_sockets==0) {
			protocol_hook.type=htons(ETH_P_ALL);
			if (scap_sk->conf.device[0]!='\0') {
				dev=dev_get_by_name(sock_net(sk), scap_sk->conf.device);
				if (dev==NULL) return -EFAULT;
				protocol_hook.dev=dev;
			}
			protocol_hook.func = packet_recv;
			dev_add_pack(&protocol_hook);
			printk("scap starts capturing\n");
		}
		scap_stats.running_sockets++;
		scap_sk->running=1;
		return 0;
	}
	case SET_CUTOFF:
	{
		int cutoff;

		if (optlen < sizeof(int)) 
			return -EINVAL;

		if (copy_from_user(&cutoff, optval, sizeof(int))) 
			return -EFAULT;

		scap_sk->conf.cutoff=cutoff;
		//if ( cutoff>scap_stats.cutoff ) scap_stats.cutoff=cutoff;
		scap_stats.cutoff=cutoff;
		printk("scap: using cutoff %d bytes per stream\n",scap_stats.cutoff);		

		return 0;
	}
	case SET_WORKERS:
	{
		int thread_num;

		if (optlen < sizeof(int)) 
			return -EINVAL;

		if (copy_from_user(&thread_num, optval, sizeof(int))) 
			return -EFAULT;

		scap_sk->conf.thread_num=thread_num;
		scap_stats.thread_num=thread_num;
		scap_stats.thread_rr=0;

		return 0;
	}
	case SET_CUTOFF_DIRECTION:
	{
		int tmp[2];

		if (optlen < sizeof(int)*2) 
			return -EINVAL;

		if (copy_from_user(&tmp[0], optval, sizeof(int)*2)) 
			return -EFAULT;

		scap_sk->conf.cutoff_per_direction[tmp[1]]=tmp[0];
		printk("scap: using cutoff %d bytes per stream in direction %d\n",tmp[0],tmp[1]);		

		return 0;
	}
	case SET_CHUNK_SIZE:
	{
		int tmp[3];

		if (optlen < sizeof(int)*3) 
			return -EINVAL;

		if (copy_from_user(&tmp[0], optval, sizeof(int)*3)) 
			return -EFAULT;

		scap_sk->conf.chunk_size=tmp[0];
		scap_sk->conf.overlap=tmp[1];
		scap_sk->conf.flush_timeout=tmp[2];
		scap_stats.chunk_size=tmp[0];
		scap_stats.overlap=tmp[1];
		scap_stats.flush_timeout=tmp[2];
		printk("scap: using chunk size %d bytes (overlap %d timeout %d)\n",tmp[0],tmp[1],tmp[2]);		

		return 0;
	}
	default:
		return -ENOPROTOOPT;
	}
}


int scap_init(void)
{
	int rc;
	scap_stats.sockets=0;
	scap_stats.running_sockets=0;
	shared_q.initialized=0;
	scap_data_buffer.initialized=0;
	scap_stats_buffer.initialized=0;
	shared_q.block_vec=NULL;
	scap_data_buffer.block_vec=NULL;
	scap_stats_buffer.block_vec=NULL;
	scap_stats.expire_streams=0;

	memset(&scap_stats, 0, sizeof(scap_stats));

	rc = proto_register(&scap_proto, 0);
	if (rc!=0) return rc;

	sock_register(&scap_family_ops);	

	printk("scap module loaded\n");

	return 0;
}

void scap_exit(void)
{
	sock_unregister(PF_SCAP);
	proto_unregister(&scap_proto);

	printk("scap module unloaded\n");
}

module_init(scap_init);
module_exit(scap_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonis Papadogiannakis <papadog@ics.forth.gr>");
MODULE_DESCRIPTION("Stream Capture Library");
MODULE_ALIAS_NETPROTO(PF_SCAP);

