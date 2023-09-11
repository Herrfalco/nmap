NAME	=	ft_nmap
SRCS	=	main.c \
		parse.c \
		utils.c
OBJS	=	$(SRCS:.c=.o)
CC	=	gcc
CFLAGS	=	-Wall -Wextra -Werror -lpcap
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
