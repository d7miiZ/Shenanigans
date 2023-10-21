#ifndef HTTP_GUARD
#define HTTP_GUARD

#include <stdint.h>

#define MIN_HTTP_SIZE (26)
#define HTTP_PORT     (80)
#define HTTPS_PORT    (443)
#define HTTP_SIZE_ERR ("HTTP is less than expected\n\0")
#define HTTP_PATTERN  ("GET /(.*) HTTP/\\d\\.?\\d\r\nHost: (.*)\r\n")
#define NO_MATCH_ERR  ("No match found")
#define MATCHING_ERR  ("Error while matching")

uint8_t parse_http(uint8_t *, uint8_t *, char **, char *, char *);

#endif
