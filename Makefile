all: rainbow hashlib

rainbow: 
	cd snowflake && make

hashlib: 
	cd hashlibs && make

clean:
	cd snowflake && make clean
	cd hashlibs && make clean
