CC = gcc
CFLAGS = -Wall -Wextra -Werror

NAME = analyzer
MODIFIER = elf_modifier

SRC_ANALYZER = src/analyzer.c
SRC_MODIFIER = src/elf_modifier.c


INFECTOR = elf_infector
SRC_INFECTOR = src/elf_infector.c

all: $(NAME) $(MODIFIER) $(INFECTOR)

$(INFECTOR): $(SRC_INFECTOR)
	$(CC) $(CFLAGS) $(SRC_INFECTOR) -o $(INFECTOR)
all: $(NAME) $(MODIFIER)

$(NAME): $(SRC_ANALYZER)
	$(CC) $(CFLAGS) $(SRC_ANALYZER) -o $(NAME)

$(MODIFIER): $(SRC_MODIFIER)
	$(CC) $(CFLAGS) $(SRC_MODIFIER) -o $(MODIFIER)

clean:
	rm -f $(NAME) $(MODIFIER)

re: clean all
