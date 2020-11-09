CC = cc
LD = ld
UPX = upx
UPXFLAGS = 
CFLAGS = -O2 -fomit-frame-pointer -s -static -pipe -D_FORTIFY_SOURCE=2 -mtune=generic -flto

pidproxy:
	$(CC) $(CFLAGS) pidproxy.c -o pidproxy

pidproxy.upx:
	$(UPX) $(UPXFLAGS) pidproxy -o pidproxy.upx

clean:
	rm -rf *.o pidproxy pidproxy.upx

all: pidproxy pidproxy.upx
.PHONY: clean
