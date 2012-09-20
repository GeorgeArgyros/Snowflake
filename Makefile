all: create_dir rainbow hashlib

create_dir:
	mkdir release

rainbow: 
	cd snowflake && make

hashlib: 
	cd hashlibs && make

clean:
	cd snowflake && make clean
	cd hashlibs && make clean
