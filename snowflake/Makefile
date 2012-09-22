CC=gcc
CFLAGS= -O3 -funroll-loops -fomit-frame-pointer -fno-stack-protector -Wall
LDFLAGS = -pthread -ldl
OBJS = rand.o snowflake.o

LIB_CFLAGS = -D__CRACK_LIB__ -fPIC
LIB_LDFLAGS = -shared -Wl,-soname,$@.so.1 

all: snowflake

snowflake: $(OBJS)
	$(CC) -o ../release/$@ $^ $(LDFLAGS)
	rm -f *.o
	make -f Makefile.lib

%.o : %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o ../release/snowflake
	make -f Makefile.lib clean