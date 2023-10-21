#include <analyzer.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <stats.h>

#define MAX_PCAP_FILE_NAME (50)

int
main(int argc, char **argv)
{
    pcap_if_t   *alldevsp;
    pcap_t      *pcap_handler;
    bpf_u_int32 maskp, netp;
    struct bpf_program fp;
    pa_stats_t stats = { 0 };
    char errbuf[PCAP_ERRBUF_SIZE], file_name[MAX_PCAP_FILE_NAME] = { 0 };
    int  pcap_loop_cnt = PCAP_LOOP_CNT, opt;

    while ((opt = getopt(argc, argv, "f:n:")) != -1) {
        switch (opt) {
        case 'n':
            pcap_loop_cnt = atoi(optarg);
            break;
        case 'f':
            strcpy(file_name, optarg);
        default:
            break;
        }
    }

    if (pcap_findalldevs(&alldevsp, errbuf)) {
        printf("%s\n", errbuf);
        exit(1);
    }

    pcap_handler = strlen(file_name) ? pcap_open_offline(file_name, errbuf) : pcap_open_live(alldevsp->name, BUFSIZ, PROMISC_MODE, PCAP_MS_TIMEOUT, errbuf);
    if (pcap_handler == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }

    if (pcap_lookupnet(alldevsp->name, &netp, &maskp, errbuf)) { }

    if (pcap_compile(pcap_handler, &fp, PCAP_FILTER, PCAP_FILTER_OPTIMIZE, netp)) {
        printf("Error calling pcap_compile\n");
        exit(1);
    }

    if (pcap_setfilter(pcap_handler, &fp)) {
        printf("Error setting pcap_filter\n");
        exit(1);
    }

    pcap_loop(pcap_handler, pcap_loop_cnt, process_packet, (u_char *) &stats);

    printf("-------------Stats---------------\n");
    printf("Num processed packets: %lu\n", stats.n_processed_packets);
    printf("Num skipped packets: %lu\n",   stats.n_skipped_packets);
    printf("Num tcp packets: %lu\n",       stats.n_tcp_packets);
    printf("Num udp packets: %lu\n",       stats.n_udp_packets);
    printf("Num http packets: %lu\n",      stats.n_http_packets);
    printf("Num tls packets: %lu\n",       stats.n_tls_packets);
    printf("Num dns packets: %lu\n",       stats.n_dns_packets);
    printf("----------------------------------\n");
    return 0;
}
