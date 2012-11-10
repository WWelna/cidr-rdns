/*
* Copyright (C) 2012, William H. Welna All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY William H. Welna ''AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL William H. Welna BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* Usage: cidr-rdns.exe 127.0.0.0/24 localrdns.txt */

#include <windows.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <pstdint.h>

#include "ares.h"

typedef struct {
	char ip_cstr[18];
	uint32_t ip;
	char hostname[128];
	void *n;
} list_struct;

typedef struct {
	uint32_t addr, addr_s, addr_e;
	char ip_s[18], ip_e[18];
	uint32_t mask;
	uint32_t total_ips;
	uint8_t prefix;
} subnet;

list_struct *IPS=NULL, *IPS_P=NULL;
ares_channel ares_chan;
int global_counter = 0, global_total;

void build_ips(uint32_t from, uint32_t to) {
	if(!IPS) {
		list_struct *p = calloc(1, sizeof(list_struct));
		uint32_t x;
		struct in_addr ip;
		IPS = p; IPS_P = p;
		for(x=from; x <= to-1; ++x, p=p->n)
			p->n = calloc(1, sizeof(list_struct));
		for(x=from, p=IPS_P; x <= to; ++x, p=p->n) {
			p->ip = htonl(x);
			ip.s_addr = p->ip;
			strcpy(p->ip_cstr, inet_ntoa(ip));
		}
	}
}

void rdns_callback(void *arg, int status, int timeouts, struct hostent *host) {
	list_struct *p = (list_struct *)arg;
	if(status == ARES_SUCCESS) {
		strcpy(p->hostname, host->h_name);
	} else {
		p->hostname[0] = '.';
	}
	++global_counter;
	if(IPS_P) { // when one is finished add another to the channel to be resolved
		ares_gethostbyaddr(ares_chan, &IPS_P->ip, 4, AF_INET, rdns_callback, IPS_P);
		IPS_P=IPS_P->n;
	}
}

void calculate_subnet(char *cidr_string, subnet *s) {
	char *p=cidr_string;
	struct in_addr ip;
	int x;
	for(x=0; x < strlen(cidr_string); ++x) {
		if(*p == '/')
			break;
		p++;
	} *p++ = '\0';
	s->prefix = atoi(p);
	s->addr = htonl(inet_addr(cidr_string));
	s->mask = 0x80000000;  
	s->mask = (int)s->mask >> (s->prefix-1);
	s->addr_s = s->addr & s->mask;
	s->addr_e = s->addr_s ^ (s->mask^0xffffffff);
	s->total_ips = s->addr_e - s->addr_s + 1;
	ip.s_addr = htonl(s->addr_s);
	strcpy(s->ip_s, inet_ntoa(ip));
	ip.s_addr = htonl(s->addr_e);
	strcpy(s->ip_e, inet_ntoa(ip));
}

void tehloop(void) {
	fd_set read, write;
	int nfds, count;
	struct timeval tv, *tvp;
	fprintf(stderr, "Starting...\n");
	tv.tv_usec = 100000;
	while(1) {
		FD_ZERO(&read); FD_ZERO(&write);
		nfds = ares_fds(ares_chan, &read, &write);
		if(nfds) {
			tvp = ares_timeout(ares_chan, NULL, &tv);
			count = select(nfds, &read, &write, NULL, tvp);
			ares_process(ares_chan, &read, &write);
			fprintf(stderr, "\rResolved %i of %i", global_counter, global_total);
		} else
			break;
	}
	fprintf(stderr, "\nFinished...\n");
}

void dump_results(char *file) {
	list_struct *p;
	FILE *f=fopen(file, "a+");
	if(f) {
		for(p=IPS; p!=NULL; p=p->n) {
			fprintf(f, "%s -> (%s)\n", p->ip_cstr, p->hostname);
		}
		fclose(f);
	} else
		fprintf(stderr, "Could not open %s for writting\n", file);
}

int main(int argc, char **argv) {
	WSADATA wsa;
	subnet sub;
	int ret, x;
	WSAStartup(0x22, &wsa);
	fprintf(stderr, "CIDR Reverse DNS - William Welna (Sanguinarious@OccultusTerra.com)\n\n");
	if(argc != 3) {
		fprintf(stderr, "No Range Specified and/or no output file or too many arguments\n");
		fprintf(stderr, "Usage: %s 127.0.0.0/24 localrdns.txt\n", argv[0]);
		exit(0);
	}
	if(ret=ares_library_init(ARES_LIB_INIT_ALL)!=ARES_SUCCESS) {
		fprintf(stderr, "ares_library_init() failed %i\n", ret);
		exit(0);
	}
	if(ret=ares_init(&ares_chan)!=ARES_SUCCESS) {
		fprintf(stderr, "ares_init() failed %i\n", ret);
		exit(0);
	}
	calculate_subnet(argv[1], &sub);
	build_ips(sub.addr_s, sub.addr_e);
	global_total = sub.total_ips;
	for(x=0; x < 60 && IPS_P != NULL; ++x, IPS_P=IPS_P->n)
		ares_gethostbyaddr(ares_chan, &IPS_P->ip, 4, AF_INET, rdns_callback, IPS_P);
	fprintf(stderr, "Resolving %s to %s (%i)\n", sub.ip_s, sub.ip_e, sub.total_ips);
	tehloop();
	dump_results(argv[2]);
	return 0;
}
