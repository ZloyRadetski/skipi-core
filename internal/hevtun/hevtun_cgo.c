// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

//go:build cgo && (android || (linux && skipi_hev))

// Glue between Go and hev-socks5-tunnel: the ready callback (a patch to hev, see
// third_party/patches/hev-socks5-tunnel) flips a flag under a mutex and wakes the Go waiter.

#include <errno.h>
#include <pthread.h>
#include <time.h>

#include "hev-main.h"
#include "hevtun_cgo.h"

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv;
static pthread_once_t cv_once = PTHREAD_ONCE_INIT;
static int ready;
static int exited;

static void
cv_init (void)
{
    pthread_condattr_t attr;

    pthread_condattr_init (&attr);
    pthread_condattr_setclock (&attr, CLOCK_MONOTONIC);
    pthread_cond_init (&cv, &attr);
    pthread_condattr_destroy (&attr);
}

static void
on_ready (void)
{
    pthread_mutex_lock (&mu);
    ready = 1;
    pthread_cond_broadcast (&cv);
    pthread_mutex_unlock (&mu);
}

void
skipi_hev_reset (void)
{
    pthread_once (&cv_once, cv_init);
    pthread_mutex_lock (&mu);
    ready = 0;
    exited = 0;
    pthread_mutex_unlock (&mu);
}

int
skipi_hev_run (const unsigned char *config, unsigned int len, int tun_fd)
{
    int res;

    pthread_once (&cv_once, cv_init);
    hev_socks5_tunnel_set_ready_callback (on_ready);
    res = hev_socks5_tunnel_main_from_str (config, len, tun_fd);
    hev_socks5_tunnel_set_ready_callback (NULL);

    pthread_mutex_lock (&mu);
    ready = 0;
    exited = 1;
    pthread_cond_broadcast (&cv);
    pthread_mutex_unlock (&mu);
    return res;
}

int
skipi_hev_wait_ready (int timeout_ms)
{
    struct timespec ts;
    int res = 0;

    pthread_once (&cv_once, cv_init);
    clock_gettime (CLOCK_MONOTONIC, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock (&mu);
    for (;;) {
        if (ready)
            res = 1;
        else if (exited)
            res = -1;
        if (res)
            break;
        if (pthread_cond_timedwait (&cv, &mu, &ts) == ETIMEDOUT) {
            if (ready)
                res = 1;
            else if (exited)
                res = -1;
            break;
        }
    }
    pthread_mutex_unlock (&mu);
    return res;
}

extern size_t hev_memory_usage (void);

unsigned long long
skipi_hev_memory_bytes (void)
{
    return (unsigned long long)hev_memory_usage ();
}
