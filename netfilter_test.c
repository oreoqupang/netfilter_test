#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

struct ip_header {
		u_char ip_vhl;
		u_char ip_tos;
		u_short ip_len;
		u_short ip_id;
		u_short ip_off;
		u_char ip_ttl;
		u_char ip_p;
		u_short ip_sum;
		struct in_addr ip_src,ip_dst;
};

struct tcp_header {
		u_short th_sport;
		u_short th_dport;
		u_int th_seq;
		u_int th_ack;
		u_char th_offset;
		u_char th_flags;
		u_short th_win;
		u_short th_sum;
		u_short th_urp;
};

char * target_host;

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{

	uint32_t id, length, ip_len, tcp_len;
	uint16_t port;
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char * pkt, *http;
	struct ip_header *ip;
	struct tcp_header *tcp;
	char victim[100];

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
	}
	length = nfq_get_payload(nfa, &pkt);
	ip = (struct ip_header *)pkt;
	ip_len = ((ip->ip_vhl) & 0x0f)*4;
	tcp = (struct tcp_header *)(pkt + ip_len);
	tcp_len = (((tcp)->th_offset & 0xf0) >> 4)*4;
	port = ntohs(tcp->th_dport);

	if(port == 80){
		http = (pkt+ip_len+tcp_len);
		if( !memcmp(http, "GET", 3) || !memcmp(http, "POST", 4)){
			snprintf(victim, 100, "Host: %s", target_host);
			if(strstr(http, victim)) {
				printf("BLOCKED:::::\n%s\n", http);
			 	int ret = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
				if (ret<0) {
					printf("block fail...\n");
					return -1;
				}
				return ret;
			}
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if(argc!=2){
		printf("usage : sudo netfilter_test <host>");
		return -1;
	}

	system("iptables -F");
	system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
	system("iptables -A INPUT -j NFQUEUE --queue-num 0");
	target_host = argv[1];
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
