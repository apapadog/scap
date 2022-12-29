
/* 
  scap API and structs for scap user-level library
*/

#ifndef spcap_h
#define scap_h

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <sys/time.h>
#include <errno.h>
#include <poll.h>
#include <arpa/inet.h>
#include <semaphore.h>
#include <pthread.h>

#include "../common/scap_defs.h"

//structs - global vars - tables


typedef void (*scap_creation_handler)(stream_t *st);
typedef void (*scap_data_handler)(stream_t *st, unsigned int chunk_size, char *data);
typedef void (*scap_termination_handler)(stream_t *st);


struct scap_descr {
	int scap_sock;
	scap_conf_t conf;
	scap_creation_handler creation_callback;
	scap_data_handler data_callback;
	scap_termination_handler termination_callback;
//	void * user_data;
	char *scap_stats_buffer;
	char *scap_data_buffer;
	char *shared_q;
	pthread_t *workers;
};
//scap_t

//functions

scap_t *scap_create(const char *device, int cutoff, int timeout, int buffer_len, int reassembly_level, int need_packets);

//configure scap socket parameters
int scap_set_filter(scap_t *sc, char *bpf_filter);

int scap_set_cutoff(scap_t *sc, int cutoff);

int scap_set_timeout(scap_t *sc, int timeout);

int scap_set_worker_threads(scap_t *sc, int thread_num);

//set different cutoffs per direction with multiple calls
int scap_add_cutoff_direction(scap_t *sc, int cutoff, int direction);

//set different cutoffs for traffic subsets: bpf_filter - cutoff pairs
//with multiple calls of this function, one for each subset
int scap_add_cutoff_class(scap_t *sc, int cutoff, char* bpf_filter);

int scap_set_chunk_size(scap_t *sc, int chunk_size, int overlap, int flush_timeout);

//dispatch callbacks
int scap_dispatch_creation(scap_t *sc, scap_creation_handler creation_callback);
int scap_dispatch_data(scap_t *sc, scap_data_handler data_callback);
int scap_dispatch_termination(scap_t *sc, scap_termination_handler termination_callback);

//start/stop capturing streams from network
int scap_start_capture(scap_t *sc);
int scap_stop_capture(scap_t *sc);

//discard the rest of the stream data
void scap_discard_stream(scap_t *sc, stream_t *st);

int scap_set_stream_cutoff(scap_t *sc, stream_t *st, int cutoff);

int scap_set_stream_priority(scap_t *sc, stream_t *st, int priority);

int scap_set_stream_chunk_size(scap_t *sc, stream_t *st, int chunk_size, int overlap, int flush_timeout);

int scap_keep_stream_chunk(scap_t *sc, stream_t *st);

//for a first type of compatibility with apps that need packets
typedef void (*scap_packet_handler)(struct scap_pkthdr *h, char *data);
int scap_packet_loop(scap_t *sc, stream_t *st, int cnt, scap_packet_handler callback);
//NULL returned after last packet
char *scap_next_stream_packet(scap_t *sc, stream_t *st, struct scap_pkthdr *h);

int scap_get_stats(scap_t *sc, scap_stats_t *stats);

void scap_close(scap_t *sc);

//XXX 
//scap_dump
//scap_open_offline

#endif

