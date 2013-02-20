DEBUG   = no
RM      = rm -f
NAME    = dta_extractor
CC	= gcc
D 	= -D_BSD_SOURCE -D_POSIX_SOURCE
CFLAGS = -W -Wall -Wextra -ansi -pedantic $(D) -O2

CFLAGS += -std=c99

SRC	=	dta_extractor.c \
		file.c

OBJ	=	$(SRC:.c=.o)

all:     $(NAME)

$(NAME): $(OBJ)
	 $(CC) $(CFLAGS) -o $(NAME) $(OBJ)

clean:
	 $(RM) $(OBJ) $(NAME) 

distclean:  clean
	 $(RM) $(NAME)

.PHONY: distclean clean all
