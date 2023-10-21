#include <tls.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

uint8_t
parse_tls(uint8_t *data, uint8_t *data_end, pa_tls_header_t **tls_header, char *url, char *errbuf)
{
    uint8_t  *tls_ptr, tls_session_id_len;
    uint16_t extensions_byte_num, extension_type, extension_len, server_name_list_len, server_name_len;
    int      i;
    char     server_name[MAX_SERVER_NAME];

    if (data_end - data < MIN_TLS_HEADER_SIZE) {
        errbuf = TLS_SIZE_ERR;
        return 1;
    }

    *tls_header = (pa_tls_header_t *) data;

    if ((*tls_header)->tls_record_type != TLS_HANDSHAKE_NUMBER) {
        return 0;
    }

    tls_ptr = ((uint8_t *) *tls_header + TLS_HEADER_BYTES);

    if (*tls_ptr != TLS_CLIENT_HELLO_NUMBER) {
        return 0;
    }
    tls_ptr += sizeof(uint8_t);

    // Skip len
    tls_ptr += 3;

    tls_ptr += sizeof(uint8_t);

    tls_ptr += sizeof(uint8_t);

    // Skip random
    tls_ptr += sizeof(uint32_t) * 8;

    tls_session_id_len = *tls_ptr;
    tls_ptr += sizeof(uint8_t);

    // Skip session ID
    tls_ptr += tls_session_id_len;

    // Skip Cipher len & Cipher suites
    tls_ptr += (ntohs(*((uint16_t *) tls_ptr)) + sizeof(uint16_t));

    // Skip compression method lens & compression method list
    tls_ptr += (*tls_ptr + sizeof(uint8_t));

    extensions_byte_num = ntohs(*((uint16_t *) tls_ptr));
    tls_ptr += sizeof(uint16_t);

    while (extensions_byte_num) {
        extension_type = ntohs(*((uint16_t *) tls_ptr));
        tls_ptr += sizeof(uint16_t);

        extension_len = ntohs(*((uint16_t *) tls_ptr));
        tls_ptr += sizeof(uint16_t);

        if (extension_type == TLS_SERVER_NAME_EXTENSION_TYPE_NUMBER) {
            server_name_list_len = ntohs(*((uint16_t *) tls_ptr));
            tls_ptr += sizeof(uint16_t);

            while (server_name_list_len) {
                tls_ptr += sizeof(uint8_t);
                server_name_len = ntohs(*((uint16_t *) tls_ptr));
                tls_ptr += sizeof(uint16_t);

                for (i = 0; i < server_name_len; i++, tls_ptr++) {
                    server_name[i] = *tls_ptr;
                }
                server_name[i] = '\0';
                // Ignoring all server names except last one
                memcpy(url, server_name, strlen(server_name));
                memset(server_name, 0, sizeof(server_name));
                server_name_list_len -= (server_name_len + sizeof(uint8_t) + sizeof(uint16_t));
            }
            break;
        }

        tls_ptr += extension_len;
        extensions_byte_num -= (extension_len + (2 * sizeof(uint16_t)));
    }
    return 0;
}
