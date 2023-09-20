#ifndef RESULT_H
#define RESULT_H

#include "filter.h"

typedef enum	result_e {
	R_NONE,
	R_OPEN,
	R_CLOSE,
	R_FILTERED,
	R_UNFILTERED,
	R_OPEN_CLOSE,
	R_OPEN_FILTERED,
}				result_t;

typedef result_t	results_t[MAX_IPS][MAX_PORTS][SCANS_NB];

result_t	*result_ptr(in_addr_t ip, uint16_t targ_port, uint16_t local_port);

#endif
