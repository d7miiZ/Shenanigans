#define PCRE2_CODE_UNIT_WIDTH 8
#define DOMAIN_INDEX 4

#include <http.h>
#include <stdio.h>
#include <string.h>
#include <pcre2.h>

// Inspired (stolen) from https://pcre2project.github.io/pcre2/doc/html/pcre2demo.html
uint8_t
parse_http(uint8_t *data, uint8_t *data_end, char **http_hdr, char *url, char *errbuf)
{
    pcre2_code *re;
    PCRE2_SPTR pattern = (PCRE2_SPTR) HTTP_PATTERN, subject, substring_start;
    int errornumber, rc;
    PCRE2_SIZE erroroffset, *ovector, subject_length, substring_length;
    pcre2_match_data *match_data;

    if (data_end - data < MIN_HTTP_SIZE) {
        errbuf = HTTP_SIZE_ERR;
        return 1;
    }

    *http_hdr = (char *) data;
    subject = (PCRE2_SPTR) (*http_hdr);
    subject_length = (PCRE2_SIZE) strlen((char *) subject);
    re = pcre2_compile(
            pattern,               /* the pattern */
            PCRE2_ZERO_TERMINATED, /* indicates pattern is zero-terminated */
            0,                     /* default options */
            &errornumber,          /* for error number */
            &erroroffset,          /* for error offset */
            NULL);                 /* use default compile context */

    if (re == NULL) {
        pcre2_get_error_message(errornumber, (PCRE2_UCHAR *) errbuf, sizeof(errbuf));
        return 1;
    }
    match_data = pcre2_match_data_create_from_pattern(re, NULL);
    rc = pcre2_match(
            re,                   /* the compiled pattern */
            subject,              /* the subject string */
            subject_length,       /* the length of the subject */
            0,                    /* start at offset 0 in the subject */
            0,                    /* default options */
            match_data,           /* block for storing the result */
            NULL);

    if (rc < 2) {
        switch (rc) {
        case PCRE2_ERROR_NOMATCH:
            errbuf = NO_MATCH_ERR;
            break;
        default:
            errbuf = MATCHING_ERR;
            break;
        }
        pcre2_match_data_free(match_data);
        pcre2_code_free(re);
        return 1;
    }

    ovector = pcre2_get_ovector_pointer(match_data);
    substring_start  = subject + ovector[DOMAIN_INDEX];
    substring_length = ovector[DOMAIN_INDEX + 1] - ovector[DOMAIN_INDEX];
    memcpy(url, substring_start, substring_length);
    pcre2_match_data_free(match_data);
    pcre2_code_free(re);
    return 0;
}
