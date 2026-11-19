// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

#ifndef SKIPI_HEVTUN_CGO_H
#define SKIPI_HEVTUN_CGO_H

void skipi_hev_reset (void);
/* Blocks until the hev main returns; returns its result. */
int skipi_hev_run (const unsigned char *config, unsigned int len, int tun_fd);
/* 1: ready, -1: main returned, 0: timeout. */
int skipi_hev_wait_ready (int timeout_ms);

#endif
