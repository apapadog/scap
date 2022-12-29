#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include "../libscap/scap.h"


scap_t *sc;

void terminate(int signo);
void update(int signo);

void stream_create(stream_t *st);
void stream_process(stream_t *st, unsigned int len, char *data);
void stream_close(stream_t *st);

int main() {

	signal(SIGINT, terminate);
	signal(SIGQUIT, terminate);
	signal(SIGTERM, terminate);

	signal(SIGALRM, update);
	alarm(10); 

	//create: no cutoff, 10 seconds timeout, 512M mem, fast reassembly, no packets
	sc=scap_create("eth0", -1, 10, 512000000, SCAP_TCP_FAST, 0);
	if (sc==NULL) {
		printf("error in scap create\n");
		exit(1);
	}
	printf("%d\n",sc->scap_sock);

	scap_set_worker_threads(sc, 1);

	//cutoff 0 bytes
	//scap_set_cutoff(sc,0);

	//scap_add_cutoff_direction(sc, 0, SCAP_CLIENT_TO_SERVER);
	//scap_add_cutoff_direction(sc, 0, SCAP_SERVER_TO_CLIENT);
	
	scap_set_chunk_size(sc, 16384, 0, -1);

	scap_dispatch_creation(sc, stream_create);
	scap_dispatch_data(sc, stream_process);
	scap_dispatch_termination(sc, stream_close);

	if (scap_start_capture(sc)<0)
		printf("error in scap start capture\n");

//      scap_close(sc);
}

void stream_create(stream_t *st) {
	printf("new stream [dst port: %u]\n",st->stream_hdr.dst_port);
}

void stream_process(stream_t *st, unsigned int len, char *data) {
	int i;

	printf("data chunk for stream [dst port: %u] [chunk len: %u]\n",st->stream_hdr.dst_port,len);

	printf("\nchunk={");
	for (i=0;i<len; i++) printf("%c",data[i]);
	printf("}\n\n");
}

void stream_close(stream_t *st) {
	printf("close stream [dst port: %u] [bytes: %lu]\n",st->stream_hdr.dst_port,st->stream_stats.bytes);
}


void terminate(int signo) {
	scap_stats_t stats;

	if ( scap_get_stats(sc, &stats) < 0 ) {
		printf("problem getting stats\n");
	}
	else {
		if (stats.pkts>0) printf("dropped packets: %lf %%\n",((double)stats.dropped_pkts/(double)stats.pkts)*100);
		if (stats.bytes>0) printf("dropped bytes: %lf %%\n",((double)stats.dropped_bytes/(double)stats.bytes)*100);
		printf("chunks used: %lf %% (%u)\n",((double)stats.used_chunks/(double)stats.total_chunks)*100, stats.used_chunks);
		printf("streams: %u\n",stats.total_streams);
	}

	scap_close(sc);
	exit(0);
}


void update(int signo) {
	scap_stats_t stats;

	if ( scap_get_stats(sc, &stats) < 0 ) {
		printf("problem getting stats\n");
	}
	else {
		printf("<<------------  \n");
		if (stats.pkts>0) printf("dropped packets: %lf %%\n",((double)stats.dropped_pkts/(double)stats.pkts)*100);
		if (stats.bytes>0) printf("dropped bytes: %lf %%\n",((double)stats.dropped_bytes/(double)stats.bytes)*100);
		printf("chunks used: %lf %% (%u)\n",((double)stats.used_chunks/(double)stats.total_chunks)*100, stats.used_chunks);
		printf("streams: %u\n",stats.total_streams);
		printf("  ------------>>\n");
	}

	alarm(10);
//      scap_close(sc);
//        exit(0);
}



