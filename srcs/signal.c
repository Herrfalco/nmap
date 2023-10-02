#include "../hdrs/thrds.h"

static pthread_mutex_t		SIG_MUT = PTHREAD_MUTEX_INITIALIZER;
static int					SIG_CATCH = 0;

void			sig_stop(int) {
	pthread_mutex_lock(&SIG_MUT);
	SIG_CATCH = 1;
	pthread_mutex_unlock(&SIG_MUT);
}

uint8_t			sig_catch(void) {
	uint8_t		res;

	pthread_mutex_lock(&SIG_MUT);
	res = SIG_CATCH;
	pthread_mutex_unlock(&SIG_MUT);
	return (res);
}

char			*handle_sig() {
	sigset_t			mask;
	int					err, i, sig[] = {
		SIGALRM, SIGHUP, SIGINT, SIGPIPE,
		SIGTERM, SIGUSR1, SIGUSR2, SIGQUIT
	};
	struct sigaction	act = { 
		.sa_handler = sig_stop,
	};

	sigemptyset(&mask);
	act.sa_mask = mask;
	for (i = 0; i < 8; ++i)
		if ((err = sigaction(sig[i], &act, NULL)))
			return (strerror(err));
	return (NULL);
}
