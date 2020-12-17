CC ?= cc
LD ?= ld
UPX ?= upx
UPXFLAGS ?=
CFLAGS ?= -O2 -fomit-frame-pointer -s -static -pipe -D_FORTIFY_SOURCE=2 -mtune=generic -flto

CODE = pidproxy.o user.o

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

pidproxy: $(CODE)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

pidproxy.upx: pidproxy
	$(UPX) $(UPXFLAGS) -o $@ $<

clean:
	rm -rf *.o pidproxy pidproxy.upx

all: pidproxy pidproxy.upx
.PHONY: clean
