package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror -I." Bpf counter.c -- -D__TARGET_ARCH_x86_64
