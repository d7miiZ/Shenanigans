#ifndef TLS_GUARD
#define TLS_GUARD

#include <stdint.h>

#define TLS_HANDSHAKE_NUMBER                  (22)
#define TLS_CLIENT_HELLO_NUMBER               (1)
#define TLS_SERVER_NAME_EXTENSION_TYPE_NUMBER (0)
#define MAX_SERVER_NAME                       (500)
#define TLS_HEADER_BYTES                      (5)
#define MIN_TLS_HEADER_SIZE                   (5)
#define TLS_SIZE_ERR                          ("TLS is less than expected\n\0")

struct pa_tls_header_s {
    uint8_t  tls_record_type;
    uint8_t  major;
    uint8_t  minor;
    uint16_t tls_len;
}  __attribute__ ((packed));

typedef struct pa_tls_header_s pa_tls_header_t;

uint8_t parse_tls(uint8_t *, uint8_t *, pa_tls_header_t **, char *, char *);

#endif
