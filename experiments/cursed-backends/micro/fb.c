#include "fbparse.h"
/* One exported entry per build; FB_NAME is fb_sse2 or fb_avx2. Same arguments as phr_parse_request. */
int FB_NAME(const char *buf, size_t len, const char **m, size_t *ml, const char **p, size_t *pl, int *minor,
            struct fb_header *h, size_t *nh) {
    return fb_parse_request(buf, len, m, ml, p, pl, minor, h, nh, 0);
}
