/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#ifndef QEMU_CRC32_H
#define QEMU_CRC32_H

#include "qemu-common.h"

uint32_t qemu_crc32(uint32_t crc, const uint8_t *data, unsigned int length);

#endif
