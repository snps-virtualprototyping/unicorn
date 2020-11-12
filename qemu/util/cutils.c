/*
 * Simple C functions to supplement the C library
 *
 * Copyright (c) 2006 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/host-utils.h"
#include "qemu/cutils.h"
#include <math.h>
#include <sys/mman.h>

#include "uc_priv.h"

void strpadcpy(char *buf, int buf_size, const char *str, char pad)
{
    int len = qemu_strnlen(str, buf_size);
    memcpy(buf, str, len);
    memset(buf + len, pad, buf_size - len);
}

void pstrcpy(char *buf, int buf_size, const char *str)
{
    int c;
    char *q = buf;

    if (buf_size <= 0)
        return;

    for(;;) {
        c = *str++;
        if (c == 0 || q >= buf + buf_size - 1)
            break;
        *q++ = c;
    }
    *q = '\0';
}

/* strcat and truncate. */
char *pstrcat(char *buf, int buf_size, const char *s)
{
    int len;
    len = strlen(buf);
    if (len < buf_size)
        pstrcpy(buf + len, buf_size - len, s);
    return buf;
}

int strstart(const char *str, const char *val, const char **ptr)
{
    const char *p, *q;
    p = str;
    q = val;
    while (*q != '\0') {
        if (*p != *q)
            return 0;
        p++;
        q++;
    }
    if (ptr)
        *ptr = p;
    return 1;
}

int stristart(const char *str, const char *val, const char **ptr)
{
    const char *p, *q;
    p = str;
    q = val;
    while (*q != '\0') {
        if (qemu_toupper(*p) != qemu_toupper(*q))
            return 0;
        p++;
        q++;
    }
    if (ptr)
        *ptr = p;
    return 1;
}

/* XXX: use host strnlen if available ? */
int qemu_strnlen(const char *s, int max_len)
{
    int i;

    for(i = 0; i < max_len; i++) {
        if (s[i] == '\0') {
            break;
        }
    }
    return i;
}

char *qemu_strsep(char **input, const char *delim)
{
    char *result = *input;
    if (result != NULL) {
        char *p;

        for (p = result; *p != '\0'; p++) {
            if (strchr(delim, *p)) {
                break;
            }
        }
        if (*p == '\0') {
            *input = NULL;
        } else {
            *p = '\0';
            *input = p + 1;
        }
    }
    return result;
}

static int64_t suffix_mul(char suffix, int64_t unit)
{
    switch (qemu_toupper(suffix)) {
    case 'B':
        return 1;
    case 'K':
        return unit;
    case 'M':
        return unit * unit;
    case 'G':
        return unit * unit * unit;
    case 'T':
        return unit * unit * unit * unit;
    case 'P':
        return unit * unit * unit * unit * unit;
    case 'E':
        return unit * unit * unit * unit * unit * unit;
    }
    return -1;
}

/*
 * Convert string to bytes, allowing either B/b for bytes, K/k for KB,
 * M/m for MB, G/g for GB or T/t for TB. End pointer will be returned
 * in *end, if not NULL. Return -ERANGE on overflow, and -EINVAL on
 * other error.
 */
static int do_strtosz(const char *nptr, const char **end,
                      const char default_suffix, int64_t unit,
                      uint64_t *result)
{
    int retval;
    const char *endptr;
    unsigned char c;
    int mul_required = 0;
    double val, mul, integral, fraction;

    retval = qemu_strtod_finite(nptr, &endptr, &val);
    if (retval) {
        goto out;
    }
    fraction = modf(val, &integral);
    if (fraction != 0) {
        mul_required = 1;
    }
    c = *endptr;
    mul = (double)suffix_mul(c, unit);
    if (mul >= 0) {
        endptr++;
    } else {
        mul = (double)suffix_mul(default_suffix, unit);
        assert(mul >= 0);
    }
    if (mul == 1 && mul_required) {
        retval = -EINVAL;
        goto out;
    }
    /*
     * Values >= 0xfffffffffffffc00 overflow uint64_t after their trip
     * through double (53 bits of precision).
     */
    if ((val * mul >= 0xfffffffffffffc00) || val < 0) {
        retval = -ERANGE;
        goto out;
    }
    *result = (int64_t)(val * mul);
    retval = 0;

out:
    if (end) {
        *end = endptr;
    } else if (*endptr) {
        retval = -EINVAL;
    }

    return retval;
}

int qemu_strtosz(const char *nptr, const char **end, uint64_t *result)
{
    return do_strtosz(nptr, end, 'B', 1024, result);
}

int qemu_strtosz_MiB(const char *nptr, const char **end, uint64_t *result)
{
    return do_strtosz(nptr, end, 'M', 1024, result);
}

int qemu_strtosz_metric(const char *nptr, const char **end, uint64_t *result)
{
    return do_strtosz(nptr, end, 'B', 1000, result);
}

/**
 * Helper function for error checking after strtol() and the like
 */
static int check_strtox_error(const char *nptr, char *ep,
                              const char **endptr, int libc_errno)
{
    if (endptr) {
        *endptr = ep;
    }

    /* Turn "no conversion" into an error */
    if (libc_errno == 0 && ep == nptr) {
        return -EINVAL;
    }

    /* Fail when we're expected to consume the string, but didn't */
    if (!endptr && *ep) {
        return -EINVAL;
    }

    return -libc_errno;
}

/**
 * Convert string @nptr to an integer, and store it in @result.
 *
 * This is a wrapper around strtol() that is harder to misuse.
 * Semantics of @nptr, @endptr, @base match strtol() with differences
 * noted below.
 *
 * @nptr may be null, and no conversion is performed then.
 *
 * If no conversion is performed, store @nptr in *@endptr and return
 * -EINVAL.
 *
 * If @endptr is null, and the string isn't fully converted, return
 * -EINVAL.  This is the case when the pointer that would be stored in
 * a non-null @endptr points to a character other than '\0'.
 *
 * If the conversion overflows @result, store INT_MAX in @result,
 * and return -ERANGE.
 *
 * If the conversion underflows @result, store INT_MIN in @result,
 * and return -ERANGE.
 *
 * Else store the converted value in @result, and return zero.
 */
int qemu_strtoi(const char *nptr, const char **endptr, int base,
                int *result)
{
    char *ep;
    long long lresult;

    if (!nptr) {
        if (endptr) {
            *endptr = nptr;
        }
        return -EINVAL;
    }

    errno = 0;
    lresult = strtoll(nptr, &ep, base);
    if (lresult < INT_MIN) {
        *result = INT_MIN;
        errno = ERANGE;
    } else if (lresult > INT_MAX) {
        *result = INT_MAX;
        errno = ERANGE;
    } else {
        *result = lresult;
    }
    return check_strtox_error(nptr, ep, endptr, errno);
}

/**
 * Convert string @nptr to an unsigned integer, and store it in @result.
 *
 * This is a wrapper around strtoul() that is harder to misuse.
 * Semantics of @nptr, @endptr, @base match strtoul() with differences
 * noted below.
 *
 * @nptr may be null, and no conversion is performed then.
 *
 * If no conversion is performed, store @nptr in *@endptr and return
 * -EINVAL.
 *
 * If @endptr is null, and the string isn't fully converted, return
 * -EINVAL.  This is the case when the pointer that would be stored in
 * a non-null @endptr points to a character other than '\0'.
 *
 * If the conversion overflows @result, store UINT_MAX in @result,
 * and return -ERANGE.
 *
 * Else store the converted value in @result, and return zero.
 *
 * Note that a number with a leading minus sign gets converted without
 * the minus sign, checked for overflow (see above), then negated (in
 * @result's type).  This is exactly how strtoul() works.
 */
int qemu_strtoui(const char *nptr, const char **endptr, int base,
                 unsigned int *result)
{
    char *ep;
    long long lresult;

    if (!nptr) {
        if (endptr) {
            *endptr = nptr;
        }
        return -EINVAL;
    }

    errno = 0;
    lresult = strtoull(nptr, &ep, base);

    /* Windows returns 1 for negative out-of-range values.  */
    if (errno == ERANGE) {
        *result = -1;
    } else {
        if (lresult > UINT_MAX) {
            *result = UINT_MAX;
            errno = ERANGE;
        } else if (lresult < INT_MIN) {
            *result = UINT_MAX;
            errno = ERANGE;
        } else {
            *result = lresult;
        }
    }
    return check_strtox_error(nptr, ep, endptr, errno);
}

/**
 * Convert string @nptr to a long integer, and store it in @result.
 *
 * This is a wrapper around strtol() that is harder to misuse.
 * Semantics of @nptr, @endptr, @base match strtol() with differences
 * noted below.
 *
 * @nptr may be null, and no conversion is performed then.
 *
 * If no conversion is performed, store @nptr in *@endptr and return
 * -EINVAL.
 *
 * If @endptr is null, and the string isn't fully converted, return
 * -EINVAL.  This is the case when the pointer that would be stored in
 * a non-null @endptr points to a character other than '\0'.
 *
 * If the conversion overflows @result, store LONG_MAX in @result,
 * and return -ERANGE.
 *
 * If the conversion underflows @result, store LONG_MIN in @result,
 * and return -ERANGE.
 *
 * Else store the converted value in @result, and return zero.
 */
int qemu_strtol(const char *nptr, const char **endptr, int base,
                long *result)
{
    char *ep;

    if (!nptr) {
        if (endptr) {
            *endptr = nptr;
        }
        return -EINVAL;
    }

    errno = 0;
    *result = strtol(nptr, &ep, base);
    return check_strtox_error(nptr, ep, endptr, errno);
}

/**
 * Convert string @nptr to an unsigned long, and store it in @result.
 *
 * This is a wrapper around strtoul() that is harder to misuse.
 * Semantics of @nptr, @endptr, @base match strtoul() with differences
 * noted below.
 *
 * @nptr may be null, and no conversion is performed then.
 *
 * If no conversion is performed, store @nptr in *@endptr and return
 * -EINVAL.
 *
 * If @endptr is null, and the string isn't fully converted, return
 * -EINVAL.  This is the case when the pointer that would be stored in
 * a non-null @endptr points to a character other than '\0'.
 *
 * If the conversion overflows @result, store ULONG_MAX in @result,
 * and return -ERANGE.
 *
 * Else store the converted value in @result, and return zero.
 *
 * Note that a number with a leading minus sign gets converted without
 * the minus sign, checked for overflow (see above), then negated (in
 * @result's type).  This is exactly how strtoul() works.
 */
int qemu_strtoul(const char *nptr, const char **endptr, int base,
                 unsigned long *result)
{
    char *ep;

    if (!nptr) {
        if (endptr) {
            *endptr = nptr;
        }
        return -EINVAL;
    }

    errno = 0;
    *result = strtoul(nptr, &ep, base);
    /* Windows returns 1 for negative out-of-range values.  */
    if (errno == ERANGE) {
        *result = -1;
    }
    return check_strtox_error(nptr, ep, endptr, errno);
}

/**
 * Convert string @nptr to an int64_t.
 *
 * Works like qemu_strtol(), except it stores INT64_MAX on overflow,
 * and INT64_MIN on underflow.
 */
int qemu_strtoi64(const char *nptr, const char **endptr, int base,
                  int64_t *result)
{
    char *ep;

    if (!nptr) {
        if (endptr) {
            *endptr = nptr;
        }
        return -EINVAL;
    }

    /* This assumes int64_t is long long TODO relax */
    QEMU_BUILD_BUG_ON(sizeof(int64_t) != sizeof(long long));
    errno = 0;
    *result = strtoll(nptr, &ep, base);
    return check_strtox_error(nptr, ep, endptr, errno);
}

/**
 * Convert string @nptr to an uint64_t.
 *
 * Works like qemu_strtoul(), except it stores UINT64_MAX on overflow.
 */
int qemu_strtou64(const char *nptr, const char **endptr, int base,
                  uint64_t *result)
{
    char *ep;

    if (!nptr) {
        if (endptr) {
            *endptr = nptr;
        }
        return -EINVAL;
    }

    /* This assumes uint64_t is unsigned long long TODO relax */
    QEMU_BUILD_BUG_ON(sizeof(uint64_t) != sizeof(unsigned long long));
    errno = 0;
    *result = strtoull(nptr, &ep, base);
    /* Windows returns 1 for negative out-of-range values.  */
    if (errno == ERANGE) {
        *result = -1;
    }
    return check_strtox_error(nptr, ep, endptr, errno);
}

/**
 * Convert string @nptr to a double.
 *
 * This is a wrapper around strtod() that is harder to misuse.
 * Semantics of @nptr and @endptr match strtod() with differences
 * noted below.
 *
 * @nptr may be null, and no conversion is performed then.
 *
 * If no conversion is performed, store @nptr in *@endptr and return
 * -EINVAL.
 *
 * If @endptr is null, and the string isn't fully converted, return
 * -EINVAL. This is the case when the pointer that would be stored in
 * a non-null @endptr points to a character other than '\0'.
 *
 * If the conversion overflows, store +/-HUGE_VAL in @result, depending
 * on the sign, and return -ERANGE.
 *
 * If the conversion underflows, store +/-0.0 in @result, depending on the
 * sign, and return -ERANGE.
 *
 * Else store the converted value in @result, and return zero.
 */
int qemu_strtod(const char *nptr, const char **endptr, double *result)
{
    char *ep;

    if (!nptr) {
        if (endptr) {
            *endptr = nptr;
        }
        return -EINVAL;
    }

    errno = 0;
    *result = strtod(nptr, &ep);
    return check_strtox_error(nptr, ep, endptr, errno);
}

/**
 * Convert string @nptr to a finite double.
 *
 * Works like qemu_strtod(), except that "NaN" and "inf" are rejected
 * with -EINVAL and no conversion is performed.
 */
int qemu_strtod_finite(const char *nptr, const char **endptr, double *result)
{
    double tmp;
    int ret;

    ret = qemu_strtod(nptr, endptr, &tmp);
    if (!ret && !isfinite(tmp)) {
        if (endptr) {
            *endptr = nptr;
        }
        ret = -EINVAL;
    }

    if (ret != -EINVAL) {
        *result = tmp;
    }
    return ret;
}

/*
 * Make sure data goes on disk, but if possible do not bother to
 * write out the inode just for timestamp updates.
 *
 * Unfortunately even in 2009 many operating systems do not support
 * fdatasync and have to fall back to fsync.
 */
int qemu_fdatasync(int fd)
{
#ifdef CONFIG_FDATASYNC
    return fdatasync(fd);
#else
    return fsync(fd);
#endif
}

/**
 * Sync changes made to the memory mapped file back to the backing
 * storage. For POSIX compliant systems this will fallback
 * to regular msync call. Otherwise it will trigger whole file sync
 * (including the metadata case there is no support to skip that otherwise)
 *
 * @addr   - start of the memory area to be synced
 * @length - length of the are to be synced
 * @fd     - file descriptor for the file to be synced
 *           (mandatory only for POSIX non-compliant systems)
 */
int qemu_msync(struct uc_struct *uc, void *addr, size_t length, int fd)
{
#ifdef CONFIG_POSIX
    size_t align_mask = ~(uc->qemu_real_host_page_size - 1);

    /**
     * There are no strict reqs as per the length of mapping
     * to be synced. Still the length needs to follow the address
     * alignment changes. Additionally - round the size to the multiple
     * of PAGE_SIZE
     */
    length += ((uintptr_t)addr & (uc->qemu_real_host_page_size - 1));
    length = (length + ~align_mask) & align_mask;

    addr = (void *)((uintptr_t)addr & align_mask);

    return msync(addr, length, MS_SYNC);
#else /* CONFIG_POSIX */
    /**
     * Perform the sync based on the file descriptor
     * The sync range will most probably be wider than the one
     * requested - but it will still get the job done
     */
    return qemu_fdatasync(fd);
#endif /* CONFIG_POSIX */
}
