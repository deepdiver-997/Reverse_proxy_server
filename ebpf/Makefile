# ebpf/ — SK_REUSEPORT steering prototype (Phase 2b, Linux only)
# Run inside the quic-bpf container:  make && ./steer_loader

CLANG  ?= clang
CFLAGS  = -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu

all: quic_steer.bpf.o steer_loader

quic_steer.bpf.o: quic_steer.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

steer_loader: steer_loader.c
	gcc -O2 -Wall -o $@ $< -lbpf -lelf -lz

clean:
	rm -f quic_steer.bpf.o steer_loader
