CC=gcc
CFLAGS=-fPIC -O3 -funroll-loops -fomit-frame-pointer -fno-stack-protector 
LDFLAGS=-shared -Wl,-soname,$@.so.1 -export-dynamic
OBJS= md5.o mwikihash.o

all: hashlib0


hashlib0: $(OBJS)
	$(CC) $(LDFLAGS) -o ../release/$@.so $^
	cp ../release/$@.so ../exploits

%.o : %.c
	$(CC) $(CFLAGS) -c $<


clean:
	rm -f *.o ../release/hashlib0.so ../exploits/hashlib0.so
