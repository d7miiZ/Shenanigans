#ifndef PA_GUARD
#define PA_GUARD

#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <tls.h>
#include <dns.h>

#define PROMISC_MODE         (0)
#define PCAP_MS_TIMEOUT      (-1)
#define PCAP_FILTER          ("ether proto \\ip and (tcp port 80 or tcp port 443 or udp port 53)")
#define PCAP_FILTER_OPTIMIZE (0)
#define PCAP_LOOP_CNT        (1000000)
#define UDP_HEADER_LEN       (8)
#define MIN_IP_HEADER_SIZE   (20)
#define MIN_TCP_HEADER_SIZE  (20)
#define MAX_DOMAIN_NAME      MAX_DNS_LABEL_LENGTH
#define ETHER_SIZE_ERR       ("Ether header is less than expected\n\0")
#define IP_SIZE_ERR          ("IP header is less than expected\n\0")
#define TCP_SIZE_ERR         ("TCP header is less than expected\n\0")
#define UDP_SIZE_ERR         ("UDP header is less than expected\n\0")
#define MAX_ERR_BUF          (100)
#define MAX_TRANSPORT_TYPE   (3)
#define MAX_APP_TYPE         (6)
#define TCP_LITERAL          ("TCP")
#define UDP_LITERAL          ("UDP")
#define HTTP_LITERAL         ("HTTP")
#define DNS_LITERAL          ("DNS")
#define TLS_LITERAL          ("TLS")

struct pa_packet_s {
    struct ether_header *ether_hdr;
    struct iphdr        *ip_header;
    union transport_hdr
    {
        struct tcphdr *tcp_header;
        struct udphdr *udp_header;
    } transport_hdr;
    union app_data
    {
        pa_tls_header_t *tls_header;
        pa_dns_header_t *dns_header;
        char            *http_hdr;
    }    app_data;
};

typedef struct pa_packet_s pa_packet_t;

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

#endif
