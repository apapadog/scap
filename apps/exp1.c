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

void stream_close(stream_t *st);

struct timeval start, end;
struct rusage start_u, end_u;

int main() {

	signal(SIGINT, terminate);
	signal(SIGQUIT, terminate);
	signal(SIGTERM, terminate);

	//create: zero bytes cutoff, 1 second timeout, 512M mem, fast reassembly, no packets
	sc=scap_create("eth0", 0, 1, 512000000, SCAP_TCP_FAST, 0);
	if (sc==NULL) {
		printf("error in scap create\n");
		exit(1);
	}
	printf("%d\n",sc->scap_sock);

	scap_set_worker_threads(sc, 1);

        //cutoff 0 bytes
        scap_set_cutoff(sc,0);

	scap_dispatch_termination(sc, stream_close);

	gettimeofday(&start,NULL);
	getrusage(RUSAGE_SELF, &start_u);

	if (scap_start_capture(sc)<0)
		printf("error in scap start capture\n");

//      scap_close(sc);
}


void stream_close(stream_t *st) {
	printf("flow %s[:%u] -> %s[:%u] bytes: %lu pkts: %u duration: %lf sec\n",
		inet_ntoa(*(struct in_addr*)&st->stream_hdr.src_ip), st->stream_hdr.src_port, 
		inet_ntoa(*(struct in_addr*)&st->stream_hdr.dst_ip), st->stream_hdr.dst_port,
		st->stream_stats.bytes, st->stream_stats.pkts,
		((double)st->stream_stats.end.tv_sec+(double)st->stream_stats.end.tv_usec/1000000.0) -
		((double)st->stream_stats.start.tv_sec+(double)st->stream_stats.start.tv_usec/1000000.0));
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



