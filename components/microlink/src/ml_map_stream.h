/**
 * @file ml_map_stream.h
 * @brief Streaming splitter for a MapResponse body (ML_LITE_STREAM_MAP)
 *
 * The Stream=false MapResponse is one JSON object, tens of KB on a real
 * tailnet (the DERPMap alone is ~10 KB). Buffering it and building a cJSON
 * DOM of all of it costs several times its size in RAM. This splitter is fed
 * the body as it arrives and hands back, one at a time, only the parts the
 * client uses, each as a small NUL-terminated JSON text the caller can parse
 * on its own:
 *
 *   Node                        -> ML_MAP_ITEM_NODE (the object)
 *   Peers[i]                    -> ML_MAP_ITEM_PEER (each element)
 *   DERPMap.Regions.<id>        -> ML_MAP_ITEM_DERP_REGION (each region)
 *   PacketFilter                -> ML_MAP_ITEM_PACKET_FILTER (the array)
 *   PacketFilters               -> ML_MAP_ITEM_PACKET_FILTERS (the object)
 *
 * plus ML_MAP_ITEM_PEERS_BEGIN / ML_MAP_ITEM_DERP_REGIONS_BEGIN (json NULL)
 * when those containers open. Everything else is skipped without being kept.
 * An item larger than max_item is reported with json == NULL (dropped).
 *
 * No ESP-IDF dependencies, so it is unit-tested on the host
 * (test/host/test_map_stream.c). Memory: one capture buffer that grows to
 * the largest item handed back, never past max_item.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    ML_MAP_ITEM_NODE = 1,
    ML_MAP_ITEM_PEERS_BEGIN,
    ML_MAP_ITEM_PEER,
    ML_MAP_ITEM_DERP_REGIONS_BEGIN,
    ML_MAP_ITEM_DERP_REGION,
    ML_MAP_ITEM_PACKET_FILTER,
    ML_MAP_ITEM_PACKET_FILTERS,
} ml_map_item_t;

/* json is NUL-terminated and writable until the callback returns; NULL for
 * the *_BEGIN events and for an item over max_item (len = its size so far). */
typedef void (*ml_map_item_cb_t)(void *ctx, ml_map_item_t kind, char *json, size_t len);

#define ML_MAP_STREAM_KEY_MAX 24
#define ML_MAP_STREAM_TRACK   5     /* container levels whose type/key are tracked */

typedef struct {
    int state;                      /* see ml_map_stream.c */
    uint8_t prefix[5];
    int prefix_len;
    size_t body_max;                /* plausible upper bound for the length prefix */

    int depth;                      /* 0 = outside the top-level object */
    char ctype[ML_MAP_STREAM_TRACK];          /* '{' or '[' for depth 1..4 */
    bool expect_key[ML_MAP_STREAM_TRACK];
    char key[ML_MAP_STREAM_TRACK][ML_MAP_STREAM_KEY_MAX];
    bool in_str, esc, str_is_key;
    int key_len;

    int cap_depth;                  /* depth of the container being captured, 0 = none */
    ml_map_item_t cap_kind;
    char *buf;
    size_t len, cap, max_item;
    bool overflow;

    ml_map_item_cb_t cb;
    void *ctx;

    uint32_t items, dropped;        /* handed back / over max_item */
    size_t body_bytes;              /* JSON bytes seen */
} ml_map_stream_t;

/* body_max: largest believable message length (bounds the 4-byte prefix
 * check); max_item: largest item kept (bigger ones are dropped). */
void ml_map_stream_init(ml_map_stream_t *s, ml_map_item_cb_t cb, void *ctx,
                        size_t max_item, size_t body_max);

/* Feed body bytes (the 4-byte length prefix included). Returns 0, or -1 if
 * the body is not a JSON object or a buffer could not be allocated. Bytes
 * after the top-level object are ignored. */
int ml_map_stream_feed(ml_map_stream_t *s, const uint8_t *data, size_t len);

/* True once the top-level object has closed. */
bool ml_map_stream_done(const ml_map_stream_t *s);

/* True once any JSON byte has been seen. */
bool ml_map_stream_started(const ml_map_stream_t *s);

/* Free the capture buffer. */
void ml_map_stream_free(ml_map_stream_t *s);
