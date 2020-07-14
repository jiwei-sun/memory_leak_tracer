CC	?= gcc
CFLAGS	= -g -Wall -rdynamic
ifeq ($(ARCH), arm32)
CFLAGS += -fno-omit-frame-pointer -mapcs -mno-sched-prolog
CFLAGS += -funwind-tables
endif
ifeq ($(ARCH), arm64)
CFLAGS += -fno-omit-frame-pointer
CFLAGS += -funwind-tables
endif
ifeq ($(ARCH), mips)
CFLAGS += -funwind-tables
endif

OBJ	:= $(patsubst %.c,%.elf,$(wildcard *.c))

%.elf: %.c
	$(CC) $(CFLAGS) -o $@ $<

all: $(OBJ)

clean:
	rm -f *.o *.elf
