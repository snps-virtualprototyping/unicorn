/*
 * QEMU Error Objects
 *
 * Copyright IBM, Corp. 2011
 * Copyright (C) 2011-2015 Red Hat, Inc.
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *  Markus Armbruster <armbru@redhat.com>,
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.  See
 * the COPYING.LIB file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "qapi/error.h"

struct Error
{
    char *msg;
    ErrorClass err_class;
    const char *src, *func;
    int line;
};

Error *error_abort;
Error *error_fatal;

static void error_handle_fatal(Error **errp, Error *err)
{
    if (errp == &error_abort) {
        fprintf(stderr, "Unexpected error in %s() at %s:%d:\n",
                err->func, err->src, err->line);
        error_free(err);
        abort();
    }
    if (errp == &error_fatal) {
        fprintf(stderr, "Unexpected error in %s() at %s:%d:\n",
                err->func, err->src, err->line);
        error_free(err);
        exit(1);
    }
}

static void error_setv(Error **errp,
                       const char *src, int line, const char *func,
                       ErrorClass err_class, const char *fmt, va_list ap,
                       const char *suffix)
{
    Error *err;
    int saved_errno = errno;

    if (errp == NULL) {
        return;
    }
    assert(*errp == NULL);

    err = g_malloc0(sizeof(*err));

    err->msg = g_strdup_vprintf(fmt, ap);
    if (suffix) {
        char *msg = err->msg;
        err->msg = g_strdup_printf("%s: %s", msg, suffix);
        g_free(msg);
    }
    err->err_class = err_class;
    err->src = src;
    err->line = line;
    err->func = func;

    error_handle_fatal(errp, err);
    *errp = err;

    errno = saved_errno;
}

void error_set_internal(Error **errp,
                        const char *src, int line, const char *func,
                        ErrorClass err_class, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    error_setv(errp, src, line, func, err_class, fmt, ap, NULL);
    va_end(ap);
}

void error_setg_internal(Error **errp,
                         const char *src, int line, const char *func,
                         const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    error_setv(errp, src, line, func, ERROR_CLASS_GENERIC_ERROR, fmt, ap, NULL);
    va_end(ap);
}

void error_setg_errno_internal(Error **errp,
                               const char *src, int line, const char *func,
                               int os_errno, const char *fmt, ...)
{
    va_list ap;
    int saved_errno = errno;

    if (errp == NULL) {
        return;
    }

    va_start(ap, fmt);
    error_setv(errp, src, line, func, ERROR_CLASS_GENERIC_ERROR, fmt, ap,
               os_errno != 0 ? strerror(os_errno) : NULL);
    va_end(ap);

    errno = saved_errno;
}

void error_setg_file_open_internal(Error **errp,
                                   const char *src, int line, const char *func,
                                   int os_errno, const char *filename)
{
    error_setg_errno_internal(errp, src, line, func, os_errno,
                              "Could not open '%s'", filename);
}

Error *error_copy(const Error *err)
{
    Error *err_new;

    err_new = g_malloc0(sizeof(*err));
    err_new->msg = g_strdup(err->msg);
    err_new->err_class = err->err_class;
    err_new->src = err->src;
    err_new->line = err->line;
    err_new->func = err->func;

    return err_new;
}

ErrorClass error_get_class(const Error *err)
{
    return err->err_class;
}

const char *error_get_pretty(Error *err)
{
    return err->msg;
}

void error_free(Error *err)
{
    if (err) {
        g_free(err->msg);
        g_free(err);
    }
}

void error_propagate(Error **dst_errp, Error *local_err)
{
    if (!local_err) {
        return;
    }
    error_handle_fatal(dst_errp, local_err);
    if (dst_errp && !*dst_errp) {
        *dst_errp = local_err;
    } else {
        error_free(local_err);
    }
}
