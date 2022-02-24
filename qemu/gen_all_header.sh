#!/bin/sh
for d in x86_64 arm armeb m68k aarch64 aarch64eb mips mipsel mips64 mips64el powerpc sparc sparc64 riscv32 riscv64; do
	python header_gen.py $d > $d.h
done
