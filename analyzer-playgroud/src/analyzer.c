#include <analyzer.h>
#include <http.h>
#include <string.h>
#include <stats.h>
#include <stdlib.h>

uint8_t *
process_ether_hdr(uint8_t *data, uint8_t *data_end, struct ether_header **ether_hdr, char *errbuf)
{
    if (data_end - data < MIN_IP_HEADER_SIZE) {
        errbuf = ETHER_SIZE_ERR;
        return 0;
    }
    *ether_hdr = (struct ether_header *) data;
    return data + ETHER_HDR_LEN;
}

uint8_t *
process_ip_hdr(uint8_t *data, uint8_t *data_end, struct iphdr **iphdr, char *errbuf)
{
    if (data_end - data < MIN_IP_HEADER_SIZE) {
        errbuf = IP_SIZE_ERR;
        return 0;
    }
    *iphdr = (struct iphdr *) data;
    return data + (*iphdr)->ihl * 4;
}

uint8_t *
process_tcp_hdr(uint8_t *data, uint8_t *data_end, struct tcphdr **tcphdr, char *errbuf)
{
    if (data_end - data < MIN_TCP_HEADER_SIZE) {
        errbuf = TCP_SIZE_ERR;
        return 0;
    }
    *tcphdr = (struct tcphdr *) data;
    return data + (*tcphdr)->doff * 4;
}

uint8_t *
process_udp_hdr(uint8_t *data, uint8_t *data_end, struct udphdr **udphdr, char *errbuf)
{
    if (data_end - data < UDP_HEADER_LEN) {
        errbuf = UDP_SIZE_ERR;
        return 0;
    }
    *udphdr = (struct udphdr *) data;
    return data + UDP_HEADER_LEN;
}

void
process_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    pa_packet_t pa_packet;
    pa_stats_t  *stats = (pa_stats_t *) args;
    uint8_t     *p, *q, protocol;
    uint16_t    dest_port, source_port;
    char errbuf[MAX_ERR_BUF] = { 0 }, url[MAX_DOMAIN_NAME + 1] = { 0 }, ip[MAX_IP_ADDRESS + 1] = { 0 }, transport_type[MAX_TRANSPORT_TYPE + 1] = { 0 }, app_type[MAX_APP_TYPE + 1] = { 0 };

    p = (uint8_t *) packet;
    q = (uint8_t *) (packet + pkthdr->len);

    if (!(p = process_ether_hdr(p, q, &(pa_packet.ether_hdr), errbuf))) {
        printf("%s\n", errbuf);
        stats->n_skipped_packets++;
        return;
    }

    if (!(p = process_ip_hdr(p, q, &(pa_packet.ip_header), errbuf))) {
        printf("%s\n", errbuf);
        stats->n_skipped_packets++;
        return;
    }
    protocol = pa_packet.ip_header->protocol;

    // Too many branches?
    switch (protocol) {
    case IPPROTO_TCP:
        strcpy(transport_type, TCP_LITERAL);
        if (!(p = process_tcp_hdr(p, q, &(pa_packet.transport_hdr.tcp_header), errbuf))) {
            printf("%s\n", errbuf);
            stats->n_skipped_packets++;
            return;
        }
        stats->n_tcp_packets++;
        if (!pa_packet.transport_hdr.tcp_header->psh) {
            stats->n_skipped_packets++;
            break;
        }

        dest_port = ntohs(pa_packet.transport_hdr.tcp_header->dest);
        switch (dest_port) {
        case HTTP_PORT:
            strcpy(app_type, HTTP_LITERAL);
            if (parse_http(p, q, &(pa_packet.app_data.http_hdr), url, errbuf)) {
                printf("%s\n", errbuf);
                stats->n_skipped_packets++;
                return;
            }
            stats->n_http_packets++;
            break;
        case HTTPS_PORT:
            strcpy(app_type, TLS_LITERAL);
            if (parse_tls(p, q, &(pa_packet.app_data.tls_header), url, errbuf)) {
                printf("%s\n", errbuf);
                stats->n_skipped_packets++;
                return;
            }
            stats->n_tls_packets++;
            break;
        default:
            printf("Skipping TCP dest port: %u\n", dest_port);
            stats->n_skipped_packets++;
            break;
        }
        break;
    case IPPROTO_UDP:
        strcpy(transport_type, UDP_LITERAL);
        if (!(p = process_udp_hdr(p, q, &(pa_packet.transport_hdr.udp_header), errbuf))) {
            printf("%s\n", errbuf);
            stats->n_skipped_packets++;
            return;
        }
        stats->n_udp_packets++;
        dest_port = ntohs(pa_packet.transport_hdr.udp_header->dest);
        source_port = ntohs(pa_packet.transport_hdr.udp_header->source);

        if (dest_port == DNS_PORT || source_port == DNS_PORT) {
            strcpy(app_type, DNS_LITERAL);
            if (parse_dns(p, q, &(pa_packet.app_data.dns_header), ip, url, errbuf)) {
                printf("%s\n", errbuf);
                stats->n_skipped_packets++;
                return;
            }
            stats->n_dns_packets++;
        } else {
            printf("Skipping UDP dest port: %u\n", dest_port);
            stats->n_skipped_packets++;
        }
        break;
    default:
        printf("Skip protocol number: %u\n", protocol);
        stats->n_skipped_packets++;
        break;
    }

    stats->n_processed_packets++;
    printf(".%ld | Transport layer: %s | App layer: %s | URL: %s | IP: %s | Packet len: %d\n", stats->n_processed_packets, transport_type, app_type, url, ip, pkthdr->len);
    printf("-------------------------------------------------------------------------------------\n");
}
