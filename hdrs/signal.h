#ifndef SIGNAL_H
#define SIGNAL_H

#include "utils.h"

char			*handle_sig(void);
uint8_t			sig_catch(void);
void			sig_stop(int);

#endif
