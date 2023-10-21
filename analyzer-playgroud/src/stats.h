#ifndef PA_STATS
#define PA_STATS

struct pa_stats_s {
    size_t n_processed_packets;
    size_t n_skipped_packets;
    size_t n_tcp_packets;
    size_t n_udp_packets;
    size_t n_http_packets;
    size_t n_tls_packets;
    size_t n_dns_packets;
};

typedef struct pa_stats_s pa_stats_t;

#endif
