#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include "../libscap/scap.h"
#include <sys/time.h>
#include <sys/resource.h>


scap_t *sc;

void terminate(int signo);

void stream_create(stream_t *st);
void stream_process(stream_t *st, unsigned int len, char *data);
void stream_close(stream_t *st);

struct timeval start, end;
struct rusage start_u, end_u;

int main() {

	signal(SIGINT, terminate);
	signal(SIGQUIT, terminate);
	signal(SIGTERM, terminate);

	//create: no cutoff, 1 second timeout, 1024M mem, fast reassembly, no packets
	sc=scap_create("eth3", -1, 1, 1024000000, SCAP_TCP_FAST, 0);
	if (sc==NULL) {
		printf("error in scap create\n");
		exit(1);
	}
	printf("%d\n",sc->scap_sock);

	scap_set_worker_threads(sc, 1);

	scap_dispatch_creation(sc, stream_create);
	scap_dispatch_data(sc, stream_process);
	scap_dispatch_termination(sc, stream_close);

	gettimeofday(&start,NULL);
	getrusage(RUSAGE_SELF, &start_u);

	if (scap_start_capture(sc)<0)
		printf("error in scap start capture\n");

//      scap_close(sc);
}

void stream_create(stream_t *st) {
	//printf("new stream [dst port: %u]\n",st->stream_hdr.dst_port);
}

void stream_process(stream_t *st, unsigned int len, char *data) {
	//int i;

	//printf("data chunk for stream [dst port: %u] [chunk len: %u]\n",st->stream_hdr.dst_port,len);

	//printf("\nchunk={");
	//for (i=0;i<len; i++) printf("%c",data[i]);
	//printf("}\n\n");
}

void stream_close(stream_t *st) {
	//printf("close stream [dst port: %u] [bytes: %lu]\n",st->stream_hdr.dst_port,st->stream_stats.bytes);
}


void terminate(int signo) {
	scap_stats_t stats;
	double duration, user_time, sys_time;

	gettimeofday(&end,NULL);
	getrusage(RUSAGE_SELF, &end_u);

	if ( scap_get_stats(sc, &stats) < 0 ) {
		printf("problem getting stats\n");
	}
	else {
		if (stats.pkts>0) printf("dropped packets: %lf %%\n",((double)stats.dropped_pkts/(double)stats.pkts)*100);
		if (stats.bytes>0) printf("dropped bytes: %lf %%\n",((double)stats.dropped_bytes/(double)stats.bytes)*100);
		printf("chunks used: %lf %% (%u)\n",((double)stats.used_chunks/(double)stats.total_chunks)*100, stats.used_chunks);
		printf("streams: %u\n",stats.total_streams);
	}

	duration=((double)end.tv_sec+(double)end.tv_usec/1000000.0)-((double)start.tv_sec+(double)start.tv_usec/1000000.0);
	user_time=((double)end_u.ru_utime.tv_sec+(double)end_u.ru_utime.tv_usec/1000000.0)-((double)start_u.ru_utime.tv_sec+(double)start_u.ru_utime.tv_usec/1000000.0);
	sys_time=((double)end_u.ru_stime.tv_sec+(double)end_u.ru_stime.tv_usec/1000000.0)-((double)start_u.ru_stime.tv_sec+(double)start_u.ru_stime.tv_usec/1000000.0);	

	printf("rate received: %lf Mbps\n",((double)stats.bytes*8.0/1000000.0)/duration);
	printf("pkts received: %u   bytes received: %lu   duration: %lf sec\n",stats.pkts,stats.bytes,duration);
	printf("cpu: %lf %%\n",((user_time+sys_time)/duration)*100);

	scap_close(sc);
	exit(0);
}



