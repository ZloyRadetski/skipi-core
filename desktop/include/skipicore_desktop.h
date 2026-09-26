// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

#ifndef SKIPI_CORE_DESKTOP_H
#define SKIPI_CORE_DESKTOP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#define SKIPI_CORE_DESKTOP_API __declspec(dllimport)
#else
#define SKIPI_CORE_DESKTOP_API
#endif

#define SKIPI_CORE_DESKTOP_API_VERSION 1

/*
 * All returned char pointers are allocated by SKIPI Core and must be released
 * with SkipiCoreDesktopFreeString. Functions documented as returning an error
 * use NULL for success. Query functions use NULL for failure; inspect
 * SkipiCoreDesktopLastError for a diagnostic in that case.
 */
SKIPI_CORE_DESKTOP_API char *SkipiCoreDesktopApiVersion(void);
SKIPI_CORE_DESKTOP_API char *SkipiCoreDesktopCoreVersion(void);
SKIPI_CORE_DESKTOP_API char *SkipiCoreDesktopInitializeAssets(const char *directory);
SKIPI_CORE_DESKTOP_API uint64_t SkipiCoreDesktopCreateController(void);
SKIPI_CORE_DESKTOP_API char *SkipiCoreDesktopDestroyController(uint64_t handle);
SKIPI_CORE_DESKTOP_API char *SkipiCoreDesktopStart(uint64_t handle, const char *config_json, int64_t tun_fd);
SKIPI_CORE_DESKTOP_API char *SkipiCoreDesktopStop(uint64_t handle);
SKIPI_CORE_DESKTOP_API int32_t SkipiCoreDesktopIsRunning(uint64_t handle);
SKIPI_CORE_DESKTOP_API char *SkipiCoreDesktopQueryTrafficStats(uint64_t handle);
SKIPI_CORE_DESKTOP_API int64_t SkipiCoreDesktopMeasureDelay(uint64_t handle, const char *target_url);
SKIPI_CORE_DESKTOP_API char *SkipiCoreDesktopReadMemoryStats(void);
SKIPI_CORE_DESKTOP_API char *SkipiCoreDesktopForceFreeMemory(void);
SKIPI_CORE_DESKTOP_API char *SkipiCoreDesktopLastError(void);
SKIPI_CORE_DESKTOP_API void SkipiCoreDesktopFreeString(char *value);

#ifdef __cplusplus
}
#endif

#endif
