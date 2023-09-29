#include "../hdrs/thrds.h"

int SIG_CATCH = 0;

static void		sig_action(int) {
	SIG_CATCH = 1;
}

char			*handle_sig() {
	sigset_t			mask;
	int					err;
	struct sigaction	act = { 
		.sa_handler = sig_action,
	};

	sigemptyset(&mask);
	act.sa_mask = mask;
	if ((err = sigaction(SIGINT, &act, NULL)))
		return (strerror(err));
	return (0);
}
