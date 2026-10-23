#ifndef ANCHR_MEASUREMENTS_H
#define ANCHR_MEASUREMENTS_H

#include "anchr_common.h"

struct measurement_entry *create_measurement_entry(const char *event_name,
                                                   const char *event_data,
                                                   const char *dependencies,
                                                   const u8 *digest,
                                                   gfp_t gfp_flags);

#endif /* ANCHR_MEASUREMENTS_H */
