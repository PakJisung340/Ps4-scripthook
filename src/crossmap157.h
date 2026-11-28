#ifndef SHV_CROSSMAP157_H
#define SHV_CROSSMAP157_H
#include <stdint.h>
typedef struct { uint64_t canon, build; } shv_xpair;
extern const shv_xpair shv_xtab[];   /* terurut menurut canon */
extern const unsigned shv_xtab_n;
#endif
