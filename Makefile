NAME	=	ft_nmap
SRCS	=	srcs/main.c \
		srcs/parse.c \
		srcs/filter.c \
		srcs/utils.c \
		srcs/local.c \
		srcs/thrds.c \
		srcs/packet.c \
		srcs/result.c \
		srcs/signal.c
OBJS	=	$(SRCS:.c=.o)
CC	=	gcc
CFLAGS	=	-Wall -Wextra -Werror
LIBS	=	-lpcap -lpthread

all	:	$(NAME)

$(NAME)	:	$(OBJS)
		$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

%.o	:	%.c
		$(CC) $(CFLAGS) -c $< -o $@

clean	:
		$(RM) $(OBJS)

fclean	:	clean
		rm -rf $(NAME)

re	:	fclean all
