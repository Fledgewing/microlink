/**
 * @file ml_coord_lite.h
 * @brief Small-memory switches for the control (coordination) connection
 *
 * Each behaviour has its own switch so a board can take one without the
 * others; all default to CONFIG_ML_LITE (off when it is undefined or 0).
 *
 *   ML_LITE_CONTROL_PLAIN    Noise over plain HTTP on port 80 first (as
 *                            tailscaled does), TLS on 443 only as the
 *                            fallback when 80 fails. The fallback's TLS state
 *                            is allocated only while it is in use. Ignored
 *                            with CONFIG_ML_CTRL_TLS (always TLS).
 *   ML_LITE_CONTROL_ONESHOT  Control then close: one session registers,
 *                            fetches one map, reports our endpoints and home
 *                            relay, then closes the connection and the coord
 *                            task exits (its stack and buffers are freed).
 *                            No long-poll and no automatic reconnect once a
 *                            session has succeeded; microlink_control_refresh()
 *                            runs another session on demand.
 *   ML_LITE_STREAM_MAP       Parse the MapResponse as it arrives
 *                            (ml_map_stream.c) instead of buffering all of it
 *                            (ML_H2_BUFFER_SIZE) and building one cJSON DOM.
 */
#pragma once

#include "sdkconfig.h"
#include "microlink_internal.h"

#if defined(CONFIG_ML_LITE) && CONFIG_ML_LITE
#define ML_LITE_DEFAULT 1
#else
#define ML_LITE_DEFAULT 0
#endif

#ifndef ML_LITE_CONTROL_PLAIN
#define ML_LITE_CONTROL_PLAIN ML_LITE_DEFAULT
#endif
#ifndef ML_LITE_CONTROL_ONESHOT
#define ML_LITE_CONTROL_ONESHOT ML_LITE_DEFAULT
#endif
#ifndef ML_LITE_STREAM_MAP
#define ML_LITE_STREAM_MAP ML_LITE_DEFAULT
#endif

/*   ML_LITE_REG_ONEBUF       The RegisterResponse is read into one buffer
 *                            (4 KB, grown only for a larger frame), each
 *                            Noise frame decrypted in place, the H2 DATA
 *                            compacted in place. Was 16 + 8 + 4 KB plus a
 *                            ciphertext copy per frame. On for every build:
 *                            same bytes parsed, same limits. */
#ifndef ML_LITE_REG_ONEBUF
#define ML_LITE_REG_ONEBUF 1
#endif

/*   ML_LITE_DERP_AFTER_CONTROL  One-shot sessions: report endpoints (with the
 *                            home region already picked), close, end the
 *                            coord task, and only then connect the home
 *                            relay. The session no longer holds its stack
 *                            and buffers while the relay's TLS handshake
 *                            runs. CONNECTED is reported once DERP is up.
 *                            Needs ML_LITE_CONTROL_ONESHOT. */
#ifndef ML_LITE_DERP_AFTER_CONTROL
#define ML_LITE_DERP_AFTER_CONTROL ML_LITE_DEFAULT
#endif

/*   ML_LITE_CACHED_START     Skip the control session at start when the
 *                            state the last full session left is still good
 *                            (ml_ctl_cache.c): our node key (not within
 *                            ML_CACHED_KEY_MARGIN_S of expiry), VPN IP, the
 *                            home relay node we reported as PreferredDERP,
 *                            and the peer the host needs (in the peer
 *                            cache). Falls back to a control session when
 *                            any is missing, DERP does not connect, or the
 *                            host asks for one (microlink_control_refresh).
 *                            Needs ML_LITE_CONTROL_ONESHOT. */
#ifndef ML_LITE_CACHED_START
#define ML_LITE_CACHED_START ML_LITE_DEFAULT
#endif

#if !ML_LITE_CONTROL_ONESHOT
#undef ML_LITE_DERP_AFTER_CONTROL
#define ML_LITE_DERP_AFTER_CONTROL 0
#undef ML_LITE_CACHED_START
#define ML_LITE_CACHED_START 0
#endif

/* Port 80 with a TLS fallback on 443 (TLS state on the heap, in use only
 * while connected over 443). */
#if ML_LITE_CONTROL_PLAIN && !defined(CONFIG_ML_CTRL_TLS)
#define ML_COORD_TLS_FALLBACK 1
#else
#define ML_COORD_TLS_FALLBACK 0
#endif

#if ML_COORD_TLS_FALLBACK
/* microlink_internal.h declares these only for CONFIG_ML_CTRL_TLS. */
int ml_coord_tls_handshake(microlink_t *ml, const char *hostname);
int ml_coord_tls_send(microlink_t *ml, const uint8_t *data, size_t len);
int ml_coord_tls_recv(microlink_t *ml, uint8_t *buf, size_t len);
size_t ml_coord_tls_pending(microlink_t *ml);
void ml_coord_tls_free(microlink_t *ml);
#endif

#if defined(CONFIG_ML_CTRL_TLS) || ML_COORD_TLS_FALLBACK
/* True while the coord connection runs inside TLS. */
bool ml_coord_tls_active(microlink_t *ml);
#endif
