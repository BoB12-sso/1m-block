#include <iostream>
#include <cstring>
#include <fstream>
#include <unordered_set>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <libnet.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>

#define NF_DROP 0
#define NF_ACCEPT 1

using namespace std;

unordered_set<string> blocked_sites;

void load_blocked_sites(const char *filename) {
    ifstream file(filename);
    string line;
    while (getline(file, line)) {
        size_t comma_pos = line.find(",");
        if (comma_pos != string::npos) {
            blocked_sites.insert(line.substr(comma_pos + 1));
        }
    }
    file.close();
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

static u_int32_t print_pkt(struct nfq_data *tb) {
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(tb);
    return ntohl(ph->packet_id);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){

    u_int32_t id = print_pkt(nfa);
    unsigned int packetlen;
    unsigned char *packet;

    // 패킷 정상적으로 받았는지 확인
    if((packetlen = nfq_get_payload(nfa, &packet))<=0)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet);

    // TCP
    if(ip_hdr->ip_p != IPPROTO_TCP) // 0x06
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + ip_hdr->ip_hl*4);
    unsigned int tcp_hdr_len = tcp_hdr->th_off * 4;
    unsigned int total_hdr_len = ip_hdr->ip_hl * 4 + tcp_hdr_len;

    // Payload
    if(!(packetlen>total_hdr_len+4 && packet[total_hdr_len]=='G'&&packet[total_hdr_len+1]=='E'&&packet[total_hdr_len+2]=='T'))
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    char *findhost = strstr((char *)(packet + total_hdr_len), "Host: ");
    
    if(!findhost)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    findhost+=strlen("Host: ");
    char* hostend = strstr(findhost, "\r\n");

    if(!hostend)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    string hostname(findhost, hostend - findhost); 

    //site compare
    // not strstr..
    if(blocked_sites.find(hostname) != blocked_sites.end()){
        printf("block %s\n", hostname.c_str());
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void init_pro(){
    system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    system("iptables -A INPUT -j NFQUEUE --queue-num 0");
    return;
}

void sig_handler(int signum){
    system("iptables -F");
    printf("terminate system\n");
    exit(0);
}

void usage(){
    printf("syntax : 1m-block <site list file>\n");
    printf("sample : 1m-block top-1m.csv\n");
    return;
}

int main(int argc, char *argv[]) {

    printf("init for net-filter lib\n");
    init_pro();

    signal(SIGINT, sig_handler);

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    if (argc < 2){
        usage();
        return 0;
    } 

    load_blocked_sites(argv[1]);

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

    qh = nfq_create_queue(h, 0, cb, NULL);

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
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;

    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}