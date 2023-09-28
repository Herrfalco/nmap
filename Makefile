NAME	=	ft_nmap
SRCS	=	srcs/main.c \
		srcs/parse.c \
		srcs/filter.c \
		srcs/utils.c \
		srcs/local.c \
		srcs/thrds.c \
		srcs/packet.c \
		srcs/result.c
OBJS	=	$(SRCS:.c=.o)
CC	=	gcc
CFLAGS	=	-Wall -Wextra -Werror -lpcap -lpthread
LIBS = -lpcap

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
