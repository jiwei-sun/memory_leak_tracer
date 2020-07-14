CC	?= gcc
CFLAGS	= -c -fpic -g -Wall
LDFLAGS = -shared
LIBS	= -ldl -lpthread
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

OBJ	:= $(patsubst %.c,%.o,$(wildcard *.c))

%.o: %.c
	$(CC) $(CFLAGS) -o $@ $<

all: libmem_leak_tracer.so

libmem_leak_tracer.so: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f *.o *.so
