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

/* ML_LITE_DERP_LAZY: no DERP region table at microlink_init(); the first
 * DERPMap allocates it (ML_MAX_DERP_REGIONS entries, trimmed after the
 * session with ML_LITE_DERP_TRIM), a cached start (ML_LITE_CACHED_START)
 * allocates the home region only. Needs ML_LITE_CONTEXT. */
#ifndef ML_LITE_DERP_LAZY
#define ML_LITE_DERP_LAZY ML_LITE_DEFAULT
#endif

/* ML_LITE_DERP_FRAME_CAP: the largest DERP frame payload that is read into
 * memory. A relayed WireGuard/DISCO packet is at most 32 (key) + 1420 (MTU)
 * + 32 (WireGuard overhead) bytes; DERP's own frames (ServerInfo, Ping,
 * PeerGone, Health...) are smaller. Anything larger (the protocol allows
 * 64 KB) is read and dropped in small pieces, never allocated. 0 = no cap. */
#ifndef ML_LITE_DERP_FRAME_CAP
#define ML_LITE_DERP_FRAME_CAP 4096
#endif

/* ML_LITE_RX_ONEBUF: relayed WireGuard packets are read straight into the
 * lwIP pbuf that WireGuard decrypts in place (the MAC is checked first), and
 * outgoing DERP packets are built once as [frame header | key | payload].
 * Was: three copies on receive (frame, payload, pbuf) plus the plaintext
 * pbuf, two on send. */
#ifndef ML_LITE_RX_ONEBUF
#define ML_LITE_RX_ONEBUF ML_LITE_DEFAULT
#endif

/* ML_LITE_SMALL_QUEUES: queue depths for one server peer over DERP
 * (wg_rx 4, derp_tx 4, disco 1, peer_update 4). Needs ML_LITE_TASKS. */
#ifndef ML_LITE_SMALL_QUEUES
#define ML_LITE_SMALL_QUEUES 0
#endif

/* ML_LITE_NACL_CACHE_SLOTS: DISCO shared-key cache entries (nacl_box.c);
 * one per peer is enough. 0 = the upstream 24. */
#ifndef ML_LITE_NACL_CACHE_SLOTS
#define ML_LITE_NACL_CACHE_SLOTS 0
#endif
