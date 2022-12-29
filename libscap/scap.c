#include <stdio.h>
#include <errno.h>

#include "scap.h"

#define START_P (sc->scap_stats_buffer)
#define STREAM_BY_OFFSET(x) ((stream_t *)(START_P+(x)))
#define STREAM_NEXT(st) STREAM_BY_OFFSET(st->internal.next_stream_offset)
#define GET_STREAM_OFFSET(st) (st->internal.stream_offset)
#define GET_NEXT_STREAM_OFFSET(st) (st->internal.next_stream_offset)
#define QUEUE_READ_OFFSET(id) *((unsigned int *)(sc->shared_q+((id)*12)))
#define QUEUE_LAST_OFFSET(id) *((unsigned int *)(sc->shared_q+4+((id)*12)))
#define QUEUE_FREE_OFFSET(id) *((unsigned int *)(sc->shared_q+8+((id)*12)))
#define QUEUE_READ_STREAM(id) STREAM_BY_OFFSET(QUEUE_READ_OFFSET(id))
#define QUEUE_LAST_STREAM(id) STREAM_BY_OFFSET(QUEUE_LAST_OFFSET(id))
#define QUEUE_FREE_STREAM(id) STREAM_BY_OFFSET(QUEUE_FREE_OFFSET(id))


scap_t *scap_create(const char *device, int cutoff, int timeout, int buffer_len, int reassembly_level, int need_packets)
{
	scap_t *sc;
	int i;

	sc=(scap_t*)malloc(sizeof(scap_t));
	memset(sc,0,sizeof(scap_t));

	if (strlen(device)>15) 
		return NULL;
	if (device!=NULL) 
		strncpy(sc->conf.device, device,sizeof(sc->conf.device));
	else 
		sc->conf.device[0]='\0';
	
	if (timeout<=0) timeout=10;
	sc->conf.timeout=timeout;
	if (cutoff<-1) cutoff=-1;
	sc->conf.cutoff=cutoff;

	for (i=0; i<SCAP_DIRECTIONS; i++)  
		sc->conf.cutoff_per_direction[i]=-2;

	if (buffer_len<=0) buffer_len=1024000000;
	//if (buffer_len<=0) buffer_len=256000000;
	sc->conf.data_block_size=getpagesize();
	sc->conf.data_block_nr=buffer_len/getpagesize();
	sc->conf.stats_block_size=getpagesize()*1024;
	sc->conf.stats_block_nr=32;

	//todo: check valid values
	sc->conf.reassembly_level=reassembly_level;
	sc->conf.need_packets=need_packets;

	sc->conf.chunk_size=16384;
	sc->conf.overlap=0;
	sc->conf.flush_timeout=0;
	sc->conf.thread_num=1;

	sc->scap_sock=socket(PF_SCAP, SOCK_SCAP, htons(ETH_P_ALL));

	if ( setsockopt(sc->scap_sock,0,CONFIGURE,&sc->conf,sizeof(scap_conf_t)) <0 ) {
		return NULL;
	}

	if ( (sc->shared_q=(char*)mmap(0, getpagesize(), PROT_READ|PROT_WRITE, MAP_SHARED, sc->scap_sock, 0)) == MAP_FAILED)
		return NULL;

	if ( (sc->scap_stats_buffer=(char*)mmap(0, sc->conf.stats_block_size*sc->conf.stats_block_nr, PROT_READ|PROT_WRITE, MAP_SHARED, sc->scap_sock, 0)) == MAP_FAILED)
		return NULL;
//	if ( (sc->scap_data_buffer=(char*)mmap(0, sc->conf.data_block_size*sc->conf.data_block_nr, PROT_READ|PROT_WRITE, MAP_SHARED, sc->scap_sock, 0)) == MAP_FAILED)
//		return NULL;


//	sc->user_data=NULL;
	sc->workers=NULL;

	sc->creation_callback=NULL;
	sc->data_callback=NULL;
	sc->termination_callback=NULL;

	return sc;
}

int scap_set_cutoff(scap_t *sc, int cutoff) {

	return setsockopt(sc->scap_sock,0,SET_CUTOFF,&cutoff,sizeof(int));

}

int scap_set_worker_threads(scap_t *sc, int thread_num) {

	sc->conf.thread_num=thread_num;
	if (thread_num>1) {
		sc->workers=(pthread_t*)malloc((thread_num-1)*sizeof(pthread_t));
	}

	return setsockopt(sc->scap_sock,0,SET_WORKERS,&thread_num,sizeof(int));

	return 1;
}

int scap_add_cutoff_direction(scap_t *sc, int cutoff, int direction) {
	int tmp[2];
	tmp[0]=cutoff;
	tmp[1]=direction;

	return setsockopt(sc->scap_sock,0,SET_CUTOFF_DIRECTION,&tmp[0],sizeof(int)*2);
}

int scap_set_chunk_size(scap_t *sc, int chunk_size, int overlap, int flush_timeout) {
	int tmp[3];
	tmp[0]=chunk_size;
	tmp[1]=overlap;
	tmp[2]=flush_timeout;

	return setsockopt(sc->scap_sock,0,SET_CHUNK_SIZE,&tmp[0],sizeof(int)*3);
}

int scap_dispatch_creation(scap_t *sc, scap_creation_handler creation_callback) {
	sc->creation_callback=creation_callback;
}

int scap_dispatch_data(scap_t *sc, scap_data_handler data_callback) {
	sc->data_callback=data_callback;
}

int scap_dispatch_termination(scap_t *sc, scap_termination_handler termination_callback) {
	sc->termination_callback=termination_callback;
}

struct worker_arg {
	scap_t *sc;
	int id;
};

void* scap_worker(void *arg){
	int id=((struct worker_arg*)arg)->id;
	scap_t *sc=((struct worker_arg*)arg)->sc;
	cpu_set_t mask;
	stream_t *st;
	int len;
	struct pollfd pfd;

	CPU_ZERO( &mask );
	CPU_SET( id, &mask );
	if( sched_setaffinity( 0, sizeof(mask), &mask ) == -1 ) {
		printf("WARNING: Could not set CPU Affinity, continuing...\n");
	}

	while (1) {
		pfd.fd=sc->scap_sock;
		pfd.revents=0;
		pfd.events= POLLIN;

		while (QUEUE_READ_OFFSET(id)==0) {
			poll(&pfd, 1, -1);
		}

		st=QUEUE_READ_STREAM(id);

		if (st->process.event==SCAP_EVENT_CREATION && sc->creation_callback!=NULL) 
			sc->creation_callback( st );

		else if (st->process.event==SCAP_EVENT_DATA_CHUNK && sc->data_callback!=NULL) {
			sc->data_callback( st, st->process.chunk_len, sc->scap_data_buffer+st->process.data_offset );
		}

		else if (st->process.event==SCAP_EVENT_TERMINATION && sc->termination_callback!=NULL) 
			sc->termination_callback( st );

		//else unknown event

		QUEUE_READ_OFFSET(id)=st->internal.next_stream_offset;
	}

	if (id>0) pthread_exit(NULL);

}

int scap_start_capture(scap_t *sc) {

	int i;
	pthread_attr_t attr;
	int ret;
	struct worker_arg w_arg[sc->conf.thread_num];

	ret=setsockopt(sc->scap_sock,0,START,NULL,0);
	if (ret<0)
		return ret;

	if ( (sc->scap_data_buffer=(char*)mmap(0, sc->conf.data_block_size*sc->conf.data_block_nr, PROT_READ|PROT_WRITE, MAP_SHARED, sc->scap_sock, 0)) == MAP_FAILED)
		return -1;

	for (i=1; i<sc->conf.thread_num; i++) {
		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, 16384);
		w_arg[i].sc=sc;
		w_arg[i].id=i;
		if ( pthread_create(&sc->workers[i-1], &attr, *scap_worker, (void*)&w_arg[i]) < 0 ) {
			printf("error on pthread_create\n");
			return -1;
		}
	}

	w_arg[0].sc=sc;
	w_arg[0].id=0;
	scap_worker((void*)&w_arg[0]);

	return 0;
}

void scap_discard_stream(scap_t *sc, stream_t *st) {
	st->internal.write_data=0;
	st->status_detail=STREAM_ACTIVE_CUTOFF;

	STREAM_BY_OFFSET(st->internal.clone_offset)->internal.write_data=0;
	STREAM_BY_OFFSET(st->internal.clone_offset)->status_detail=STREAM_ACTIVE_CUTOFF;
}

int scap_set_stream_cutoff(scap_t *sc, stream_t *st, int cutoff) {

	st->cutoff=cutoff;
	STREAM_BY_OFFSET(st->internal.clone_offset)->cutoff=cutoff;
}

int scap_set_stream_chunk_size(scap_t *sc, stream_t *st, int chunk_size, int overlap, int flush_timeout) {

	st->process.chunk_size=chunk_size;
	st->process.overlap=overlap;
	st->process.flush_timeout=flush_timeout;

	STREAM_BY_OFFSET(st->internal.clone_offset)->process.chunk_size=chunk_size;
	STREAM_BY_OFFSET(st->internal.clone_offset)->process.overlap=overlap;
	STREAM_BY_OFFSET(st->internal.clone_offset)->process.flush_timeout=flush_timeout;
}

int scap_get_stats(scap_t *sc, scap_stats_t *stats) {
	int len=sizeof(scap_stats_t);

	if (sc==NULL || stats==NULL) 
		return -1;

	return getsockopt(sc->scap_sock,0,GET_SCAP_STATS,stats,&len);
}

void scap_close(scap_t *sc) {
	int i;

	if ( munmap(sc->scap_data_buffer, sc->conf.data_block_size*sc->conf.data_block_nr) < 0 )
		printf("error when unmapping data buffer\n");
	if ( munmap(sc->scap_stats_buffer, sc->conf.stats_block_size*sc->conf.stats_block_nr) < 0 )
		printf("error when unmapping stats buffer\n");
	if ( munmap(sc->shared_q, getpagesize()) < 0 )
		printf("error when unmapping shared_q\n");

	if (sc->workers!=NULL) {
		for (i=1; i<sc->conf.thread_num; i++) 
			pthread_cancel(sc->workers[i-1]);
		free(sc->workers);
	}

	close(sc->scap_sock);
	free(sc);
}


