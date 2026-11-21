/* Host tests for the streaming MapResponse splitter (ml_map_stream.c). */
#include "ml_map_stream.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

typedef struct {
    int n;
    ml_map_item_t kind[32];
    char json[32][256];
    int dropped;
} got_t;

static void cb(void *ctx, ml_map_item_t kind, char *json, size_t len) {
    got_t *g = ctx;
    if (g->n >= 32) return;
    g->kind[g->n] = kind;
    if (json) {
        snprintf(g->json[g->n], sizeof(g->json[0]), "%s", json);
        CHECK(strlen(json) == len);
    } else {
        g->json[g->n][0] = '\0';
        if (kind != ML_MAP_ITEM_PEERS_BEGIN && kind != ML_MAP_ITEM_DERP_REGIONS_BEGIN) g->dropped++;
    }
    g->n++;
}

static const char *MAP =
    "{\"KeepAlive\":false,\"Node\":{\"ID\":1,\"Addresses\":[\"100.64.0.1/32\"],"
    "\"Name\":\"r{e}a\\\"der\",\"CapMap\":{\"Peers\":[{\"x\":1}]}},"
    "\"DERPMap\":{\"HomeParams\":{\"RegionScore\":{\"1\":1}},\"Regions\":{"
    "\"1\":{\"RegionID\":1,\"RegionCode\":\"nyc\",\"Nodes\":[{\"HostName\":\"a\"}]},"
    "\"2\":{\"RegionID\":2,\"RegionCode\":\"sfo\",\"Nodes\":[]}}},"
    "\"Peers\":[{\"ID\":2,\"Name\":\"bookorbit.\",\"Tags\":[\"]\",\"}\"]},"
    "{\"ID\":3,\"Name\":\"other\"}],"
    "\"DNSConfig\":{\"Peers\":[{\"no\":1}],\"Node\":{\"no\":2}},"
    "\"PacketFilter\":[{\"SrcIPs\":[\"*\"]}],\"UserProfiles\":[{\"ID\":5}]}";

static void run(const uint8_t *body, size_t len, size_t chunk, got_t *g, size_t max_item) {
    ml_map_stream_t s;
    memset(g, 0, sizeof(*g));
    ml_map_stream_init(&s, cb, g, max_item, 1 << 20);
    for (size_t i = 0; i < len; i += chunk) {
        size_t n = len - i < chunk ? len - i : chunk;
        CHECK(ml_map_stream_feed(&s, body + i, n) == 0);
    }
    CHECK(ml_map_stream_done(&s));
    ml_map_stream_free(&s);
}

static void test_split(size_t chunk, int prefixed) {
    size_t jl = strlen(MAP);
    uint8_t *body = malloc(jl + 4);
    size_t off = 0;
    if (prefixed) {
        body[0] = jl & 0xff; body[1] = (jl >> 8) & 0xff; body[2] = 0; body[3] = 0;
        off = 4;
    }
    memcpy(body + off, MAP, jl);
    got_t g;
    run(body, jl + off, chunk, &g, 4096);
    free(body);

    CHECK(g.n == 8);
    CHECK(g.kind[0] == ML_MAP_ITEM_NODE);
    CHECK(strncmp(g.json[0], "{\"ID\":1,", 8) == 0);
    CHECK(strstr(g.json[0], "\"CapMap\":{\"Peers\":[{\"x\":1}]}}") != NULL);
    CHECK(g.kind[1] == ML_MAP_ITEM_DERP_REGIONS_BEGIN);
    CHECK(g.kind[2] == ML_MAP_ITEM_DERP_REGION);
    CHECK(strcmp(g.json[2], "{\"RegionID\":1,\"RegionCode\":\"nyc\",\"Nodes\":[{\"HostName\":\"a\"}]}") == 0);
    CHECK(g.kind[3] == ML_MAP_ITEM_DERP_REGION);
    CHECK(g.kind[4] == ML_MAP_ITEM_PEERS_BEGIN);
    CHECK(g.kind[5] == ML_MAP_ITEM_PEER);
    CHECK(strcmp(g.json[5], "{\"ID\":2,\"Name\":\"bookorbit.\",\"Tags\":[\"]\",\"}\"]}") == 0);
    CHECK(g.kind[6] == ML_MAP_ITEM_PEER);
    CHECK(strcmp(g.json[6], "{\"ID\":3,\"Name\":\"other\"}") == 0);
    CHECK(g.kind[7] == ML_MAP_ITEM_PACKET_FILTER);
    CHECK(strcmp(g.json[7], "[{\"SrcIPs\":[\"*\"]}]") == 0);
}

/* The length's low byte is '{' (0x7b): the prefix must still be skipped. */
static void test_prefix_brace(void) {
    char json[200];
    memset(json, ' ', sizeof(json));
    const char *head = "{\"Peers\":[{\"ID\":7}],\"Pad\":\"";
    memcpy(json, head, strlen(head));
    size_t jl = 0x7b;
    memcpy(json + jl - 2, "\"}", 2);
    uint8_t body[4 + 0x7b];
    body[0] = 0x7b; body[1] = 0; body[2] = 0; body[3] = 0;
    memcpy(body + 4, json, jl);
    got_t g;
    run(body, sizeof(body), 7, &g, 4096);
    CHECK(g.n == 2);
    CHECK(g.kind[1] == ML_MAP_ITEM_PEER && strcmp(g.json[1], "{\"ID\":7}") == 0);
}

static void test_overflow(void) {
    const char *m = "{\"Peers\":[{\"ID\":1,\"Name\":\"a-very-long-name-indeed\"},{\"ID\":2}]}";
    got_t g;
    run((const uint8_t *)m, strlen(m), 3, &g, 16);
    CHECK(g.n == 3);
    CHECK(g.kind[1] == ML_MAP_ITEM_PEER && g.dropped == 1);
    CHECK(g.kind[2] == ML_MAP_ITEM_PEER && strcmp(g.json[2], "{\"ID\":2}") == 0);
}

static void test_garbage(void) {
    ml_map_stream_t s;
    got_t g = {0};
    ml_map_stream_init(&s, cb, &g, 1024, 1 << 20);
    CHECK(ml_map_stream_feed(&s, (const uint8_t *)"\x01\x02\x03\x04[1]", 7) == -1);
    ml_map_stream_free(&s);

    /* Bytes after the object (a second message) are ignored. */
    const char *m = "{\"Node\":{\"ID\":1}}{\"Node\":{\"ID\":2}}";
    run((const uint8_t *)m, strlen(m), 5, &g, 1024);
    CHECK(g.n == 1);
}

int main(void) {
    size_t chunks[] = {1, 2, 3, 7, 64, 4096};
    for (size_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
        test_split(chunks[i], 0);
        test_split(chunks[i], 1);
    }
    test_prefix_brace();
    test_overflow();
    test_garbage();
    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("map_stream: all tests passed\n");
    return 0;
}
