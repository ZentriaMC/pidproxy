CC ?= cc
LD ?= ld
UPX ?= upx
UPXFLAGS ?=
CFLAGS ?= -O2 -fomit-frame-pointer -s -static -pipe -D_FORTIFY_SOURCE=2 -mtune=generic -flto -pie -fPIE -Wl,--build-id=none \
		-Wstack-protector -fstack-protector-all --param ssp-buffer-size=4 -Wl,-z,now -Wl,-z,relro -Wall -Wextra

CODE = pidproxy.o user.o

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

pidproxy: $(CODE)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

pidproxy.upx: pidproxy
	$(UPX) $(UPXFLAGS) -o $@ $<

clean:
	rm -rf *.o pidproxy pidproxy.upx

check: pidproxy
	./test/basic_monitor.sh ./pidproxy
	./test/basic_monitor_exit_hook.sh ./pidproxy

all: pidproxy pidproxy.upx
.PHONY: clean
