#ifndef DNS_GUARD
#define DNS_GUARD

#include <stdint.h>

// Avoid padding by explicitly defining the bytes
#define DNS_HEADER_BYTES             (12)
#define DNS_QUESTION_BYTES           (4)
#define DNS_RESOURCE_BYTES           (10)
#define DNS_ANSWER_CNAME_TYPE_NUMBER (5)
#define DNS_ANSWER_A_TYPE_NUMBER     (1)
#define DNS_LABEL_OFFSET_MARK        (0xc0)
#define MIN_DNS_HEADER_SIZE          (12)
#define MIN_DNS_QUESTION_SIZE        (5)
#define MIN_DNS_RR_SIZE              (13)
#define MAX_IP_ADDRESS               (15)
#define MAX_DNS_LABEL_LENGTH         (207)
#define DNS_PORT                     (53)
#define DNS_SIZE_ERR                 ("DNS header is less than expected\n\0")
#define DNS_QUESTION_SIZE_ERROR      ("DNS question is less than expected\n\0")
#define DNS_RR_SIZE_ERROR            ("DNS RR is less than expected\n\0")

struct pa_dns_header_s {
    uint16_t dns_id;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
};

struct pa_dns_question_s
{
    uint16_t qtype;
    uint16_t qclass;
};

struct pa_dns_resource_s
{
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
};

typedef struct pa_dns_header_s   pa_dns_header_t;
typedef struct pa_dns_question_s pa_dns_question_t;
typedef struct pa_dns_resource_s pa_dns_resource_t;

uint8_t parse_dns(uint8_t *data, uint8_t *end_data, pa_dns_header_t **, char *, char *, char *);

#endif
