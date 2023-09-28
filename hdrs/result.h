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

typedef struct	genh_s {
	uint16_t	source;
	uint16_t	dest;
}				genh_t;

typedef result_t	results_t[MAX_IPS][MAX_PORTS][SCANS_NB];

void	result_set(packet_t *pkt, result_t res);
void	result_print(void);

#endif
