#include <dns.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Definitely improve this. else branches needed?.
uint8_t *
process_labels(uint8_t *label_ptr, uint8_t *message_start, char *url)
{
    // first two bits are used to tell if this an offset or not, https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4.
    uint8_t label_len_mask = 0x3F, label_len = *label_ptr & label_len_mask, offset_mark = *label_ptr, *offset_start, offset;
    char    dns_label[MAX_DNS_LABEL_LENGTH + 1];
    int     i = 0, accumulator = 0;

    while (label_len || offset_mark == DNS_LABEL_OFFSET_MARK) {
        label_ptr += sizeof(uint8_t);
        if (offset_mark == DNS_LABEL_OFFSET_MARK) {
            offset = *label_ptr;
            offset_start = message_start;
            while (offset-- && offset_start++) { }
            process_labels(offset_start, message_start, url);
            return label_ptr += sizeof(uint8_t);
        } else {
            for (i = accumulator; i < label_len + accumulator; i++, label_ptr++) {
                dns_label[i] = *((char *) label_ptr);
            }
            accumulator += label_len;
            label_len = *label_ptr & label_len_mask;
            offset_mark = *label_ptr;
        }
    }
    dns_label[i] = '\0';
    strcat(url, dns_label);
    return label_ptr += sizeof(uint8_t);
}


uint8_t
parse_dns(uint8_t *data, uint8_t *data_end, pa_dns_header_t **dns_header, char *ip, char *question_url, char *errbuf)
{
    pa_dns_resource_t *dns_resource;
    uint8_t  *label_ptr;
    uint16_t qd_count, an_count, rdlenght, dns_resource_type;
    int      count;
    char     answer_url[MAX_DNS_LABEL_LENGTH + 1];

    if (data_end - data < MIN_DNS_HEADER_SIZE) {
        errbuf = DNS_SIZE_ERR;
        return 1;
    }

    *dns_header = (pa_dns_header_t *) data;
    qd_count = ntohs((*dns_header)->qd_count);
    an_count = ntohs((*dns_header)->an_count);

    data += DNS_HEADER_BYTES;
    if (data_end - data < MIN_DNS_QUESTION_SIZE) {
        errbuf = DNS_QUESTION_SIZE_ERROR;
        return 1;
    }

    label_ptr = (uint8_t *) data;
    if (qd_count > 0) {
        count = qd_count;
        while (count) {
            // Ignoring all questions domain names except last
            // When multiple (usually it's 1) question are present all domain names will be in one string, maybe fix this when needed.
            label_ptr  = process_labels(label_ptr, (uint8_t *) *dns_header, question_url);
            label_ptr += DNS_QUESTION_BYTES;
            count--;
        }
    }

    if (an_count > 0) {
        if (data_end - label_ptr < MIN_DNS_RR_SIZE) {
            errbuf = DNS_RR_SIZE_ERROR;
            return 1;
        }

        count = an_count;
        while (count) {
            // Skip offset
            label_ptr += sizeof(uint16_t);
            dns_resource = (pa_dns_resource_t *) (label_ptr);
            rdlenght = ntohs(dns_resource->rdlength);
            dns_resource_type = ntohs(dns_resource->type);
            label_ptr += DNS_RESOURCE_BYTES;
            switch (dns_resource_type) {
            case DNS_ANSWER_CNAME_TYPE_NUMBER:
                // Ignoring all answer domain names except last
                // When multiple answers are present all domain names will be in one string, maybe fix this when needed.
                label_ptr = process_labels(label_ptr, (u_int8_t *) *dns_header, answer_url);
                break;
            case DNS_ANSWER_A_TYPE_NUMBER:
                // Ignoring all answer IPs except last
                inet_ntop(AF_INET, label_ptr, ip, MAX_IP_ADDRESS);
                label_ptr += rdlenght;
                break;
            default:
                label_ptr += rdlenght;
                printf("Skipping DNS answer type with value %u\n", dns_resource_type);
                break;
            }
            count--;
        }
    }
    return 0;
}
