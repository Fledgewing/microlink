/**
 * @file ml_lite.h
 * @brief Small-memory client mode (CONFIG_ML_LITE) switches
 *
 * CONFIG_ML_LITE is for a client with no PSRAM and little internal RAM (an
 * ESP32-C3 reader that brings the tailnet up for one request and down
 * again). It is made of independent pieces, each with its own switch. Every
 * switch defaults to CONFIG_ML_LITE (undefined = 0) and can be set on its
 * own, e.g. a PSRAM board can take ML_LITE_TASKS but keep the direct path.
 *
 *   ML_LITE_TASKS        DERP I/O and the WireGuard manager share one task
 *                        (ml_tunnel), with smaller stacks and queues.
 *   ML_LITE_CONTEXT      microlink_t, the WireGuard device and the peer
 *                        caches sized for a couple of peers; no allocation
 *                        over ~8 KB.
 *   ML_LITE_NO_DIRECT    DERP only: no DISCO/WireGuard UDP socket, no STUN,
 *                        no direct-path DISCO pings or CallMeMaybe, no
 *                        net_io task.
 *   ML_LITE_SMALL_FILTER Packet filter tables sized for a client that only
 *                        takes replies to its own connections.
 */
#pragma once

#if defined(ESP_PLATFORM) || __has_include("sdkconfig.h")
#include "sdkconfig.h"
#endif

#if defined(CONFIG_ML_LITE) && CONFIG_ML_LITE
#define ML_LITE_DEFAULT 1
#else
#define ML_LITE_DEFAULT 0
#endif

#ifndef ML_LITE_TASKS
#define ML_LITE_TASKS ML_LITE_DEFAULT
#endif
#ifndef ML_LITE_CONTEXT
#define ML_LITE_CONTEXT ML_LITE_DEFAULT
#endif
#ifndef ML_LITE_NO_DIRECT
#define ML_LITE_NO_DIRECT ML_LITE_DEFAULT
#endif
#ifndef ML_LITE_SMALL_FILTER
#define ML_LITE_SMALL_FILTER ML_LITE_DEFAULT
#endif

/* Peers tracked with ML_LITE_CONTEXT: the one server the reader talks to,
 * plus a spare. Applies to the peer table, the WireGuard device and the
 * peer queue; never more than CONFIG_ML_MAX_PEERS. */
/* Trim the DERP region table to the regions in use (home + peers') after
 * each control session; the next DERPMap grows it back. Off by default
 * (measurement builds). */
#ifndef ML_LITE_DERP_TRIM
#define ML_LITE_DERP_TRIM 0
#endif

#ifndef ML_LITE_MAX_PEERS
#define ML_LITE_MAX_PEERS 2
#endif
