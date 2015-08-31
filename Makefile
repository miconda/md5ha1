# build file for md5ha1 tool
#

all:
	gcc -o md5ha1 md5ha1.c md5.c

clean:
	rm -f *.o
	rm -f md5ha1
