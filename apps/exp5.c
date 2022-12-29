#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include "../libscap/scap.h"
#include <sys/time.h>
#include <sys/resource.h>
#include "acsmx.h"

scap_t *sc;

void terminate(int signo);

void stream_create(stream_t *st);
void stream_process(stream_t *st, unsigned int len, char *data);
void stream_close(stream_t *st);

struct timeval start, end;
struct rusage start_u, end_u;

ACSM_STRUCT * acsm;
unsigned long long matches=0;

int MatchFound (void *id, int index, void *data) 
{
  //fprintf (stdout, "match found: %s\n", (char *) id);
  matches++;
  return 0;
}

#define PATTERNS 2120

int main(int argc, char *argv[]) {
	int i;
	FILE *fp;
	char pattern[PATTERNS][300];
	int workers;

	if (argc!=2) {
		printf("usage: ./scap4 workers\n");
		exit(1);
	}
	workers=atoi(argv[1]);
	if (workers<=0) {
		printf("invalid number of threads\n");
		exit(1);
	}
	printf("using %d workers\n",workers);

	signal(SIGINT, terminate);
	signal(SIGQUIT, terminate);
	signal(SIGTERM, terminate);

	acsm = acsmNew ();
	//add patterns
	fp=fopen("patterns","r");
	if (fp==NULL) {
		printf("cannot open patterns file\n");
		exit(1);
	}

	for (i=0; i<PATTERNS; i++) {
		fscanf(fp, "%s\n",&pattern[i][0]);
		acsmAddPattern(acsm, &pattern[i][0], strlen(&pattern[i][0]), 0, 0, 0, &pattern[i][0], i);
	}
	printf("loaded %d patterns\n",i);

	acsmCompile(acsm);

	//create: no cutoff, 1 second timeout, 1024M mem, fast reassembly, no packets
	sc=scap_create("eth0", -1, 1, 256000000, SCAP_TCP_FAST, 0);
	if (sc==NULL) {
		printf("error in scap create\n");
		exit(1);
	}
	printf("%d\n",sc->scap_sock);

	scap_set_worker_threads(sc, workers);

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
	int state=0;

	//printf("data chunk for stream [dst port: %u] [chunk len: %u]\n",st->stream_hdr.dst_port,len);

	//printf("\nchunk={");
	//for (i=0;i<len; i++) printf("%c",data[i]);
	//printf("}\n\n");

	acsmSearch(acsm, data, len, MatchFound, (void *) 0, &state);
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

	printf("matches found: %llu\n",matches);

	scap_close(sc);
	acsmFree(acsm);
	exit(0);
}



