
/* 
  scap structs and buffers shared between scap kernel module and scap user-level library
*/

#ifndef spcap_defs_h
#define scap_defs_h

#define PF_SCAP		27
#define SOCK_SCAP	9

#include "bpf.h"
#include "decode.h"

//BLOCK_THRESHOLD_A / BLOCK_THRESHOLD_B
#define BLOCK_THRESHOLD_A 1
#define BLOCK_THRESHOLD_B 10000
#define STREAM_BLOCK_THRESHOLD 2


//enums, structs
struct scap_stream;

typedef struct scap_descr scap_t;

//for setsockopt, getsockopt
enum {
	GET_SCAP_STATS = 0,
	GET_INT,
	CONFIGURE,
	START,
	SET_CUTOFF,
	SET_CUTOFF_DIRECTION,
	SET_CHUNK_SIZE,
	SET_WORKERS
}; //scap sock options

enum {
	SCAP_PACKETS = 0,
	SCAP_TCP_FAST,
	SCAP_TCP_STRICT
}; //scap reassembly level

//client is defined as the host which initiates the connection
enum {
	SCAP_BOTH = 0,
	SCAP_CLIENT_TO_SERVER,
	SCAP_SERVER_TO_CLIENT,
}; //scap direction

#define SCAP_DIRECTIONS 3

//internal
enum {
	GLOBAL_CUTOFF = 0,
	PER_DIRECTION_CUTOFF,
	CLASS_CUTOFF,
	DIRECTION_CLASS_CUTOFF,
}; //cutoff_type

//internal
typedef struct scap_cutoff_class {
	char *bpf_filter;
	struct bpf_program *fp;
	int cutoff;
	struct scap_cutoff_class *next;
} scap_cutoff_class_t;

typedef struct scap_conf {
	char device[15];
	int timeout;
	int cutoff;
	unsigned int data_block_nr;
	unsigned int data_block_size;
	unsigned int stats_block_nr;
	unsigned int stats_block_size;
	uint8_t reassembly_level;
//	uint8_t stream_direction;
	int need_packets;
//	int flush_size;
//	int flush_timeout;
	char *bpf_filter;
	struct bpf_program *fp;
	int cutoff_per_direction[SCAP_DIRECTIONS];
	scap_cutoff_class_t *list;	//UNUSED
	int cutoff_type;		//UNUSED
	int chunk_size;
	int overlap;
	int flush_timeout;
	int thread_num;
} scap_conf_t;

//stream parts
typedef struct scap_stream_header {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
	uint8_t direction;
} stream_hdr_t;

typedef struct scap_stream_stats {
	struct timeval start;
	struct timeval end;
	uint64_t bytes;
	uint64_t bytes_dropped;
	uint64_t bytes_discarded;
	uint64_t bytes_captured;
	uint32_t pkts;
	uint32_t pkts_dropped;
	uint32_t pkts_discarded;
	uint32_t pkts_captured;
} stream_stats_t;

enum {
	STREAM_FREE = 0,
	STREAM_ACTIVE,
	STREAM_CLOSED,
	STREAM_CLOSED_STATS_ONLY,
	STREAM_CHUNK
}; //stream_status

enum {
	STREAM_NOT_DELIVERED = 0,
	STREAM_ACTIVE_CUTOFF,
	STREAM_ACTIVE_FLUSH_SIZE,
	STREAM_ACTIVE_FLUSH_TIMEOUT,
	STREAM_CLOSED_TIMEOUT,
	STREAM_CLOSED_TCP_FIN,
	STREAM_CLOSED_TCP_RST
}; //stream_status_detail

typedef struct scap_stream_internal {
//	scap_t *sc;
	struct scap_stream *flush_clone;
	uint32_t clone_offset;
	uint32_t stream_offset;
	uint32_t next_stream_offset;
//	uint64_t bytes_read;
//	uint32_t pkts_index; 
//	uint8_t break_packet_loop;
	uint8_t write_data;
//	uint8_t got_data;
//	uint8_t segmented;
//	uint32_t wait_len;
//	uint32_t prev_bytes;
//	uint32_t blocks_reduced;
//	uint32_t blocks_mapped;
	uint32_t id;
	struct timeval prev_flush_time;
//	void *sem;
} stream_internal_t;

enum {
	SCAP_TCP_ESTABLISHED = 0,
	SCAP_TCP_NO_ESTABLISHED,
	SCAP_TCP_ESTABLISHED_CONT
}; //tcp_stream_status

typedef struct scap_tcp_reassembly {
	uint8_t tcp_stream_status;
//tcp seq number
//XXX more tcp reassembly stats
} tcp_reassembly_t;

typedef struct scap_ip_defragmentation {
	int8_t checksum;
} ip_defragmentation_t;

typedef struct scap_chunk_header {
	char **block;	//start pointer
	struct scap_chunk_header *next_chunk;
	//struct scap_block_header *prev_block;
	uint32_t block_nr;
	uint32_t data_offset;
	uint32_t bytes_free;
	uint32_t write_offset;
	uint32_t chunk_size;
	uint8_t isfree;
} scap_chunk_header_t;

typedef struct scap_stream_data_storage {
	unsigned int chunk_nr;
	scap_chunk_header_t *curr_chunk;
} stream_data_storage_t;


enum {
	SCAP_EVENT_CREATION = 0,
	SCAP_EVENT_DATA_CHUNK,
	SCAP_EVENT_TERMINATION
}; 

typedef struct scap_stream_process {
	int chunk_size;
	int overlap;
	int flush_timeout;
	int thread_id;
	uint32_t data_offset;
	uint32_t chunk_len;
	uint8_t event;
} stream_process_t;

//basic stream struct
typedef struct scap_stream {
	stream_hdr_t stream_hdr;
	stream_stats_t stream_stats;
	stream_internal_t internal;
	stream_process_t process;
	stream_data_storage_t data_storage;
//	tcp_reassembly_t tcp_reassembly;
//	ip_defragmentation_t ip_defragmentation;
	uint8_t status;
	uint8_t status_detail;
	int cutoff;
	int priority;
	unsigned int hash;
	struct scap_stream *next;
	struct scap_stream *hashtable_next;
	struct scap_stream *hashtable_prev;
	struct scap_stream *access_next;
	struct scap_stream *access_prev;
	struct scap_stream *opposite;
} stream_t;


struct scap_pkthdr {
	struct timeval ts;
	uint32_t len;
};


typedef struct scap_stats_sock {
	uint32_t active_streams;
	uint32_t expired_streams;
	uint32_t total_streams;

	uint32_t used_chunks;
	uint32_t unused_chunks;
	uint32_t total_chunks;

	uint64_t bytes;
	uint64_t bytes_written;
	uint32_t pkts;
	uint64_t dropped_bytes;  
	uint32_t dropped_pkts;
	uint64_t discarded_bytes;
	uint32_t discarded_pkts;
	uint64_t filtered_bytes;
	uint32_t filtered_pkts;
} scap_stats_t;


#endif

