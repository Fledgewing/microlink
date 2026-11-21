/**
 * @file ml_map_stream.c
 * @brief Streaming splitter for a MapResponse body; see ml_map_stream.h
 *
 * A byte-at-a-time scanner that tracks only what it needs to recognise the
 * items it hands back: the nesting depth, whether it is inside a string,
 * and for the outer few levels the container type and the current key. It
 * does not validate the JSON; each item handed back is parsed (and so
 * validated) by the caller.
 */

#include "ml_map_stream.h"

#include <stdlib.h>
#include <string.h>

enum { ST_PREFIX = 0, ST_JSON, ST_DONE, ST_ERROR };

#define CAP_START 1024

void ml_map_stream_init(ml_map_stream_t *s, ml_map_item_cb_t cb, void *ctx,
                        size_t max_item, size_t body_max) {
    memset(s, 0, sizeof(*s));
    s->cb = cb;
    s->ctx = ctx;
    s->max_item = max_item;
    s->body_max = body_max;
}

void ml_map_stream_free(ml_map_stream_t *s) {
    free(s->buf);
    s->buf = NULL;
    s->cap = s->len = 0;
}

bool ml_map_stream_done(const ml_map_stream_t *s) { return s->state == ST_DONE; }

bool ml_map_stream_started(const ml_map_stream_t *s) { return s->body_bytes > 0; }

/* Append one byte to the capture; false only when out of memory. */
static bool cap_put(ml_map_stream_t *s, char c) {
    if (s->overflow) return true;
    if (s->len + 2 > s->max_item) {          /* keep room for the NUL */
        s->overflow = true;
        return true;
    }
    if (s->len + 2 > s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : CAP_START;
        if (ncap > s->max_item) ncap = s->max_item;
        char *nb = realloc(s->buf, ncap);
        if (!nb) return false;
        s->buf = nb;
        s->cap = ncap;
    }
    s->buf[s->len++] = c;
    return true;
}

static bool key_is(const ml_map_stream_t *s, int depth, const char *k) {
    return depth > 0 && depth < ML_MAP_STREAM_TRACK && s->ctype[depth] == '{' &&
           strcmp(s->key[depth], k) == 0;
}

/* Item that a container opening at new_depth (with c = '{' or '[') is, or 0. */
static ml_map_item_t classify(const ml_map_stream_t *s, int new_depth, char c) {
    switch (new_depth) {
    case 2:
        if (key_is(s, 1, "Node") && c == '{') return ML_MAP_ITEM_NODE;
        if (key_is(s, 1, "PacketFilter") && c == '[') return ML_MAP_ITEM_PACKET_FILTER;
        if (key_is(s, 1, "PacketFilters") && c == '{') return ML_MAP_ITEM_PACKET_FILTERS;
        return 0;
    case 3:
        if (key_is(s, 1, "Peers") && s->ctype[2] == '[' && c == '{') return ML_MAP_ITEM_PEER;
        return 0;
    case 4:
        if (key_is(s, 1, "DERPMap") && key_is(s, 2, "Regions") && s->ctype[3] == '{' && c == '{')
            return ML_MAP_ITEM_DERP_REGION;
        return 0;
    default:
        return 0;
    }
}

static int scan_byte(ml_map_stream_t *s, char c) {
    s->body_bytes++;
    if (s->cap_depth && !cap_put(s, c)) return -1;

    if (s->in_str) {
        if (s->esc) {
            s->esc = false;
        } else if (c == '\\') {
            s->esc = true;
            return 0;
        } else if (c == '"') {
            s->in_str = false;
            if (s->str_is_key) s->key[s->depth][s->key_len] = '\0';
            return 0;
        }
        if (s->str_is_key && s->key_len < ML_MAP_STREAM_KEY_MAX - 1) {
            s->key[s->depth][s->key_len++] = c;
        }
        return 0;
    }

    switch (c) {
    case '"':
        s->in_str = true;
        s->str_is_key = s->depth > 0 && s->depth < ML_MAP_STREAM_TRACK &&
                        s->ctype[s->depth] == '{' && s->expect_key[s->depth];
        if (s->str_is_key) {
            s->key_len = 0;
            s->expect_key[s->depth] = false;
        }
        return 0;

    case '{':
    case '[': {
        if (s->depth == 0 && c != '{') return -1;   /* the body must be an object */
        int nd = s->depth + 1;
        if (!s->cap_depth) {
            ml_map_item_t kind = classify(s, nd, c);
            if (kind) {
                s->cap_depth = nd;
                s->cap_kind = kind;
                s->len = 0;
                s->overflow = false;
                if (!cap_put(s, c)) return -1;
            } else if (nd == 2 && c == '[' && key_is(s, 1, "Peers")) {
                s->cb(s->ctx, ML_MAP_ITEM_PEERS_BEGIN, NULL, 0);
            } else if (nd == 3 && c == '{' && key_is(s, 1, "DERPMap") && key_is(s, 2, "Regions")) {
                s->cb(s->ctx, ML_MAP_ITEM_DERP_REGIONS_BEGIN, NULL, 0);
            }
        }
        s->depth = nd;
        if (nd < ML_MAP_STREAM_TRACK) {
            s->ctype[nd] = c;
            s->expect_key[nd] = (c == '{');
            s->key[nd][0] = '\0';
        }
        return 0;
    }

    case '}':
    case ']':
        if (s->depth <= 0) return -1;
        if (s->cap_depth == s->depth) {
            s->cap_depth = 0;
            if (s->overflow) {
                s->dropped++;
                s->cb(s->ctx, s->cap_kind, NULL, s->len);
            } else {
                s->buf[s->len] = '\0';
                s->items++;
                s->cb(s->ctx, s->cap_kind, s->buf, s->len);
            }
            s->len = 0;
        }
        s->depth--;
        if (s->depth == 0) s->state = ST_DONE;
        return 0;

    case ',':
        if (s->depth > 0 && s->depth < ML_MAP_STREAM_TRACK && s->ctype[s->depth] == '{') {
            s->expect_key[s->depth] = true;
        }
        return 0;

    default:
        if (s->depth == 0 && c != ' ' && c != '\t' && c != '\r' && c != '\n') return -1;
        return 0;
    }
}

int ml_map_stream_feed(ml_map_stream_t *s, const uint8_t *data, size_t len) {
    size_t i = 0;
    while (i < len) {
        switch (s->state) {
        case ST_DONE:
            return 0;
        case ST_ERROR:
            return -1;
        case ST_PREFIX:
            /* 4-byte message length (little- or big-endian) before the JSON,
             * or plain JSON. Never decided by looking for '{' alone: the
             * length's low byte is '{' when length % 256 == 123. */
            s->prefix[s->prefix_len++] = data[i++];
            if (s->prefix_len < 5) break;
            {
                const uint8_t *b = s->prefix;
                size_t le = (size_t)b[0] | ((size_t)b[1] << 8) | ((size_t)b[2] << 16) | ((size_t)b[3] << 24);
                size_t be = ((size_t)b[0] << 24) | ((size_t)b[1] << 16) | ((size_t)b[2] << 8) | (size_t)b[3];
                int from;
                if (b[4] == '{' && ((le > 0 && le < s->body_max) || (be > 0 && be < s->body_max))) {
                    from = 4;
                } else if (b[0] == '{') {
                    from = 0;
                } else {
                    s->state = ST_ERROR;
                    return -1;
                }
                s->state = ST_JSON;
                for (int k = from; k < 5 && s->state == ST_JSON; k++) {
                    if (scan_byte(s, (char)b[k]) < 0) {
                        s->state = ST_ERROR;
                        return -1;
                    }
                }
            }
            break;
        case ST_JSON:
            if (scan_byte(s, (char)data[i++]) < 0) {
                s->state = ST_ERROR;
                return -1;
            }
            break;
        }
    }
    return s->state == ST_ERROR ? -1 : 0;
}
