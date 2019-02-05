#ifndef QEMU_MMAP_ALLOC_H
#define QEMU_MMAP_ALLOC_H

#include "qemu-common.h"

void *qemu_ram_mmap(int fd, size_t size, size_t align, bool shared);

void qemu_ram_munmap(int fd, void *ptr, size_t size);

#endif
