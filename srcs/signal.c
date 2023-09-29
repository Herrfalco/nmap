#include "../hdrs/thrds.h"

int SIG_CATCH = 0;

static void		sig_action(int) {
	SIG_CATCH = 1;
}

char			*handle_sig() {
	sigset_t			mask;
	int					err, i, sig[] = {
		SIGALRM, SIGHUP, SIGINT, SIGPIPE,
		SIGTERM, SIGUSR1, SIGUSR2, SIGQUIT
	};
	struct sigaction	act = { 
		.sa_handler = sig_action,
	};

	sigemptyset(&mask);
	act.sa_mask = mask;
	for (i = 0; i < 8; ++i)
		if ((err = sigaction(sig[i], &act, NULL)))
			return (strerror(err));
	return (0);
}
