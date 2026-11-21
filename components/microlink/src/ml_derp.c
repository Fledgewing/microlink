/**
 * @file ml_derp.c
 * @brief Unified DERP I/O Task + Connection Management
 *
 * Single task handles BOTH reading and writing to DERP TLS connection.
 * This eliminates the need for a TLS mutex since only one task touches
 * the SSL context. Matches v1's single-threaded DERP model.
 *
 * Architecture:
 * - Poll for incoming DERP frames (TLS read) every iteration
 * - Drain TX queue between reads (TLS write)
 * - No mutex needed — single task owns the SSL context exclusively
 *
 * Backpressure strategy (from tailscaled):
 * When queue is full, dequeue oldest packet and retry up to 3 times.
 * If still full, drop the new packet.
 *
 * Reference: tailscale/wgengine/magicsock/derp.go (runDerpWriter)
 *            tailscale/derp/derphttp/derphttp_client.go
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "esp_vfs_eventfd.h"
#include <sys/select.h>
#include <unistd.h>
#include <time.h>
#if ML_LITE_DERP_WOLFSSL
/* Built with the application's wolfSSL (WOLFSSL_USER_SETTINGS); the build
 * passes its include path and defines. */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#else
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#if CONFIG_ML_DERP_VERIFY_CERT
#include "esp_crt_bundle.h"
#elif !defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE)
/* ML_DERP_VERIFY_CERT depends on the bundle, so turning the bundle off
 * silently turns relay certificate checking off as well. Say so. */
#warning "MBEDTLS_CERTIFICATE_BUNDLE is disabled: DERP relay TLS certificates will not be verified (ML_DERP_VERIFY_CERT unavailable)"
#endif
#endif /* ML_LITE_DERP_WOLFSSL */
#include "nacl_box.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>

static const char *TAG = "ml_derp";

/* Timeout for DERP connection handshake operations */
#define DERP_CONNECT_TIMEOUT_MS  10000

/* ============================================================================
 * DERP TLS transport
 *
 * Everything that touches the TLS library goes through these functions:
 *   derp_tls_start()   - TLS setup + handshake on a connected socket
 *   derp_tls_recv()    - read up to len bytes
 *   derp_tls_send()    - write up to len bytes
 *   derp_tls_pending() - decrypted bytes buffered inside the TLS session
 *   derp_tls_close()   - close_notify + free the session (not the socket)
 *   derp_tls_abort()   - free the session and close the socket (failure path)
 * recv/send return the byte count, DERP_TLS_AGAIN when the socket timed out
 * (retry), DERP_TLS_CLOSED on the peer's close_notify and another negative
 * value on errors.
 *
 * Backends: mbedTLS (ESP-IDF's prebuilt one, default) and, when
 * ML_LITE_DERP_WOLFSSL, wolfSSL.
 * ========================================================================== */

#define DERP_TLS_AGAIN   (-0x10000)
#define DERP_TLS_CLOSED  (-0x10001)

#if !ML_LITE_DERP_WOLFSSL

/* ============================================================================
 * Custom BIO callbacks for TLS I/O
 *
 * These wrap the socket layer (ml_read_sock/ml_write_sock) so that both
 * lwIP and AT socket backends work transparently.
 *
 * recv is provided as a blocking recv (f_recv). With the recv_timeout BIO
 * (f_recv_timeout) combined with mbedtls_ssl_conf_read_timeout, the TLS 1.3
 * handshake fails with MBEDTLS_ERR_SSL_BAD_INPUT_DATA (Bad input
 * parameters), so we align with the scheme that already works on the
 * control plane side (coord_bio_recv in ml_coord_tls.c). Timeouts are
 * enforced by SO_RCVTIMEO on the socket; a timeout surfaces as EAGAIN ->
 * MBEDTLS_ERR_SSL_WANT_READ.
 * ========================================================================== */

/**
 * Custom blocking recv for mbedtls BIO (f_recv signature, no timeout arg).
 * SO_RCVTIMEO on the socket bounds the wait; a timeout surfaces as
 * EAGAIN/EWOULDBLOCK which we map to MBEDTLS_ERR_SSL_WANT_READ.
 */
static int ml_derp_bio_recv(void *ctx, unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    if (fd < 0) return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    int ret = (int)ml_read_sock(fd, buf, len);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        if (errno == EPIPE || errno == ECONNRESET) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }
        if (errno == EINTR) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    if (ret == 0) {
        return MBEDTLS_ERR_NET_CONN_RESET;
    }
    return ret;
}

/**
 * Custom send for mbedtls BIO.
 */
static int ml_derp_bio_send(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    if (fd < 0) return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    int ret = (int)ml_write_sock(fd, buf, len);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        if (errno == EPIPE || errno == ECONNRESET) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }
        if (errno == EINTR) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return ret;
}

/**
 * Common cleanup for failure paths in ml_derp_connect() after TLS init.
 *
 * Previously we only closed the socket and never freed the mbedTLS
 * contexts, leaking entropy/ctr_drbg/ssl_conf on every connection failure,
 * and — for failures after a successful ssl_setup — the ~20KB TLS I/O
 * buffers as well (internal RAM, since CONFIG_MBEDTLS_INTERNAL_MEM_ALLOC=y).
 * Combined with infinite retries, internal RAM shrank monotonically,
 * making mbedtls_ssl_setup's ALLOC_FAILED -> handshake's Bad input
 * parameters progressively worse on its own. So always free everything.
 *
 * mbedtls_*_free() zeroizes the structs after freeing, so a later
 * ml_derp_disconnect() freeing the same contexts is not a double free.
 */
static void derp_tls_abort(ml_derp_conn_t *c, int sock) {
    mbedtls_ssl_free(&c->ssl);
    mbedtls_ssl_config_free(&c->ssl_conf);
#if ML_TLS_LEGACY_RNG
    mbedtls_ctr_drbg_free(&c->ctr_drbg);
    mbedtls_entropy_free(&c->entropy);
#endif
    if (sock >= 0) {
        ml_close_sock(sock);
    }
    c->sockfd = -1;
}

static int derp_tls_map(int ret) {
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
        ret == MBEDTLS_ERR_SSL_TIMEOUT) {
        return DERP_TLS_AGAIN;
    }
    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return DERP_TLS_CLOSED;
    return ret;
}

static int derp_tls_recv(ml_derp_conn_t *c, uint8_t *buf, size_t len) {
    return derp_tls_map(mbedtls_ssl_read(&c->ssl, buf, len));
}

static int derp_tls_send(ml_derp_conn_t *c, const uint8_t *buf, size_t len) {
    return derp_tls_map(mbedtls_ssl_write(&c->ssl, buf, len));
}

static size_t derp_tls_pending(ml_derp_conn_t *c) {
    return mbedtls_ssl_get_bytes_avail(&c->ssl);
}

static void derp_tls_close(ml_derp_conn_t *c) {
    mbedtls_ssl_close_notify(&c->ssl);
    mbedtls_ssl_free(&c->ssl);
    mbedtls_ssl_config_free(&c->ssl_conf);
#if ML_TLS_LEGACY_RNG
    mbedtls_ctr_drbg_free(&c->ctr_drbg);
    mbedtls_entropy_free(&c->entropy);
#endif
}

/* TLS setup + handshake over the connected socket `sock`. On failure the
 * session is freed and the socket closed. */
static esp_err_t derp_tls_start(microlink_t *ml, ml_derp_conn_t *c, int sock,
                                const char *derp_host) {
    /* TLS setup */
    mbedtls_ssl_init(&c->ssl);
    mbedtls_ssl_config_init(&c->ssl_conf);
#if ML_TLS_LEGACY_RNG
    mbedtls_entropy_init(&c->entropy);
    mbedtls_ctr_drbg_init(&c->ctr_drbg);
#endif

    /* Always check the return values of the mbedTLS setup functions and
     * abort immediately on failure instead of proceeding to the handshake.
     * On failure (typically ALLOC_FAILED), mbedtls_ssl_setup resets
     * ssl->conf to NULL in its error label, so ignoring the error and
     * proceeding to the handshake trips the sanity check with
     * MBEDTLS_ERR_SSL_BAD_INPUT_DATA — misreported as "Bad input
     * parameters" when the real cause is out-of-memory. */
    int cfg_ret;
#if ML_TLS_LEGACY_RNG
    cfg_ret = mbedtls_ctr_drbg_seed(&c->ctr_drbg, mbedtls_entropy_func,
                           &c->entropy, NULL, 0);
    if (cfg_ret != 0) {
        ESP_LOGE(TAG, "ctr_drbg_seed failed: -0x%04x", -cfg_ret);
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }
#endif

    cfg_ret = mbedtls_ssl_config_defaults(&c->ssl_conf,
                                 MBEDTLS_SSL_IS_CLIENT,
                                 MBEDTLS_SSL_TRANSPORT_STREAM,
                                 MBEDTLS_SSL_PRESET_DEFAULT);
    if (cfg_ret != 0) {
        ESP_LOGE(TAG, "ssl_config_defaults failed: -0x%04x", -cfg_ret);
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }
#if CONFIG_ML_DERP_VERIFY_CERT
    /* Verify the relay certificate against ESP-IDF's CA bundle; the host name
     * is checked via mbedtls_ssl_set_hostname() below. */
    mbedtls_ssl_conf_authmode(&c->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    if (esp_crt_bundle_attach(&c->ssl_conf) != ESP_OK) {
        ESP_LOGE(TAG, "TLS setup failed: could not attach the CA bundle");
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }
#else
    {
        static bool s_warned;
        if (!s_warned) {
            s_warned = true;
            ESP_LOGW(TAG, "DERP TLS certificates are not verified (%s)",
#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE)
                     "CONFIG_ML_DERP_VERIFY_CERT=n"
#else
                     "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=n"
#endif
                     );
        }
    }
    mbedtls_ssl_conf_authmode(&c->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
#endif
#if ML_TLS_LEGACY_RNG
    mbedtls_ssl_conf_rng(&c->ssl_conf, mbedtls_ctr_drbg_random, &c->ctr_drbg);
#endif
    /* Pin the DERP connection to TLS 1.2. When the DERP relay uses a
     * Let's Encrypt ECDSA certificate, the ESP-IDF mbedTLS TLS 1.3 path
     * cannot interpret the certificate's signature algorithm OID and fails
     * with "X509 - Signature algorithm (oid) is unsupported" (even with
     * authmode=VERIFY_NONE, TLS 1.3 cannot skip certificate processing).
     * DERP also accepts TLS 1.2, so pin to 1.2 to bypass the 1.3
     * certificate path. */
    mbedtls_ssl_conf_max_tls_version(&c->ssl_conf, MBEDTLS_SSL_VERSION_TLS1_2);

    cfg_ret = mbedtls_ssl_setup(&c->ssl, &c->ssl_conf);
    if (cfg_ret != 0) {
        /* -0x7F00 (ALLOC_FAILED) means internal RAM exhaustion. To allocate
         * the ~20KB TLS I/O buffers from PSRAM instead, set
         * CONFIG_MBEDTLS_EXTERNAL_MEM_ALLOC=y. */
        ESP_LOGE(TAG, "mbedtls_ssl_setup failed: -0x%04x", -cfg_ret);
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }
    cfg_ret = mbedtls_ssl_set_hostname(&c->ssl, derp_host);
    if (cfg_ret != 0) {
        ESP_LOGE(TAG, "ssl_set_hostname failed: -0x%04x", -cfg_ret);
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }
    /* Store socket fd BEFORE setting bio.
     * Use custom BIO callbacks that route through ml_read_sock/ml_write_sock,
     * which transparently support both lwIP and AT socket backends.
     * Timeout is handled via SO_RCVTIMEO. */
    c->sockfd = sock;
    /* Pass a blocking recv as f_recv and set f_recv_timeout to NULL
     * (same scheme as the control plane; avoids the TLS 1.3 Bad input
     * data failure). */
    mbedtls_ssl_set_bio(&c->ssl, &c->sockfd,
                         ml_derp_bio_send, ml_derp_bio_recv, NULL);

    /* TLS handshake - socket has 10s SO_RCVTIMEO from connect phase; the
     * overall deadline stops a relay that accepts TCP and then stalls from
     * hanging this task forever. */
    int ret;
    const int64_t hs_deadline_us = esp_timer_get_time() + 20LL * 1000 * 1000;
    while ((ret = mbedtls_ssl_handshake(&c->ssl)) != 0) {
        if ((ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) &&
            esp_timer_get_time() < hs_deadline_us && !ml_shutdown_requested(ml)) {
            continue;
        }
        char err_buf[128];
#if defined(MBEDTLS_ERROR_C)
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
#else
        /* CONFIG_MBEDTLS_ERROR_STRINGS=n: mbedTLS 4 has no strerror stub */
        snprintf(err_buf, sizeof(err_buf), "-0x%04x", (unsigned)-ret);
#endif
        ESP_LOGE(TAG, "TLS handshake failed: %s", err_buf);
#if CONFIG_ML_DERP_VERIFY_CERT
        uint32_t vflags = mbedtls_ssl_get_verify_result(&c->ssl);
        if (vflags != 0 && vflags != (uint32_t)-1) {
            char why[160];
            mbedtls_x509_crt_verify_info(why, sizeof(why), "", vflags);
            ESP_LOGE(TAG, "DERP certificate for %s not accepted: %s", derp_host, why);
        }
#endif
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }
    return ESP_OK;
}

#else /* ML_LITE_DERP_WOLFSSL */

/* ============================================================================
 * wolfSSL backend
 *
 * The prebuilt mbedTLS has 16 KB in and out record buffers (~37 KB a
 * session, not reconfigurable). wolfSSL sizes its buffers to the records it
 * actually sends and receives: measured from the host against
 * derp1/2/10.tailscale.com with the application's settings, ~5.4 KB stays
 * allocated once connected and the TLS 1.3 handshake peaks at ~24 KB.
 *
 * Certificates: Tailscale's relays serve Let's Encrypt ECDSA chains
 * (leaf P-256 <- YE1/YE2 P-384 <- Root YE, cross-signed by ISRG Root X2,
 * itself cross-signed by ISRG Root X1), followed by a self-signed Ed25519
 * "derpkey..." certificate that carries the relay's DERP key. The trust
 * anchor is ISRG Root X2. derp_tls_verify_cb() then settles the two
 * expected failures in that chain without trusting anything new:
 *  - a chain certificate that is not a CA (the derpkey one) is ignored:
 *    wolfSSL only adds verified CA certificates as signers, so the leaf
 *    must still chain to the anchor;
 *  - a CA certificate carrying a trust anchor's own public key (ISRG Root
 *    X2 cross-signed by X1) is accepted: its signatures are the anchor's.
 * Verifying through X1 instead costs an RSA-4096 operation (+11 KB peak).
 * ========================================================================== */

/* ISRG Root X2 (ECDSA P-384, valid to 2040-09-17), DER.
 * SHA-256 69:72:9B:8E:15:A8:6E:FC:17:7A:57:AF:B7:17:1D:FC:
 *         64:AD:D2:8C:2F:CA:8C:F1:50:7E:34:45:3C:CB:14:70 */
static const unsigned char k_derp_root_isrg_x2[] = {
    0x30, 0x82, 0x02, 0x1b, 0x30, 0x82, 0x01, 0xa1, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x41,
    0xd2, 0x9d, 0xd1, 0x72, 0xea, 0xee, 0xa7, 0x80, 0xc1, 0x2c, 0x6c, 0xe9, 0x2f, 0x87, 0x52, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30, 0x4f, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03,
    0x55, 0x04, 0x0a, 0x13, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x53, 0x65,
    0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x20,
    0x47, 0x72, 0x6f, 0x75, 0x70, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0c,
    0x49, 0x53, 0x52, 0x47, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x58, 0x32, 0x30, 0x1e, 0x17, 0x0d,
    0x32, 0x30, 0x30, 0x39, 0x30, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x34,
    0x30, 0x30, 0x39, 0x31, 0x37, 0x31, 0x36, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x4f, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x29, 0x30, 0x27, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x13, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x53,
    0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68,
    0x20, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
    0x0c, 0x49, 0x53, 0x52, 0x47, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x58, 0x32, 0x30, 0x76, 0x30,
    0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00,
    0x22, 0x03, 0x62, 0x00, 0x04, 0xcd, 0x9b, 0xd5, 0x9f, 0x80, 0x83, 0x0a, 0xec, 0x09, 0x4a, 0xf3,
    0x16, 0x4a, 0x3e, 0x5c, 0xcf, 0x77, 0xac, 0xde, 0x67, 0x05, 0x0d, 0x1d, 0x07, 0xb6, 0xdc, 0x16,
    0xfb, 0x5a, 0x8b, 0x14, 0xdb, 0xe2, 0x71, 0x60, 0xc4, 0xba, 0x45, 0x95, 0x11, 0x89, 0x8e, 0xea,
    0x06, 0xdf, 0xf7, 0x2a, 0x16, 0x1c, 0xa4, 0xb9, 0xc5, 0xc5, 0x32, 0xe0, 0x03, 0xe0, 0x1e, 0x82,
    0x18, 0x38, 0x8b, 0xd7, 0x45, 0xd8, 0x0a, 0x6a, 0x6e, 0xe6, 0x00, 0x77, 0xfb, 0x02, 0x51, 0x7d,
    0x22, 0xd8, 0x0a, 0x6e, 0x9a, 0x5b, 0x77, 0xdf, 0xf0, 0xfa, 0x41, 0xec, 0x39, 0xdc, 0x75, 0xca,
    0x68, 0x07, 0x0c, 0x1f, 0xea, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f,
    0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13,
    0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
    0x0e, 0x04, 0x16, 0x04, 0x14, 0x7c, 0x42, 0x96, 0xae, 0xde, 0x4b, 0x48, 0x3b, 0xfa, 0x92, 0xf8,
    0x9e, 0x8c, 0xcf, 0x6d, 0x8b, 0xa9, 0x72, 0x37, 0x95, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x30, 0x7b, 0x79, 0x4e, 0x46,
    0x50, 0x84, 0xc2, 0x44, 0x87, 0x46, 0x1b, 0x45, 0x70, 0xff, 0x58, 0x99, 0xde, 0xf4, 0xfd, 0xa4,
    0xd2, 0x55, 0xa6, 0x20, 0x2d, 0x74, 0xd6, 0x34, 0xbc, 0x41, 0xa3, 0x50, 0x5f, 0x01, 0x27, 0x56,
    0xb4, 0xbe, 0x27, 0x75, 0x06, 0xaf, 0x12, 0x2e, 0x75, 0x98, 0x8d, 0xfc, 0x02, 0x31, 0x00, 0x8b,
    0xf5, 0x77, 0x6c, 0xd4, 0xc8, 0x65, 0xaa, 0xe0, 0x0b, 0x2c, 0xee, 0x14, 0x9d, 0x27, 0x37, 0xa4,
    0xf9, 0x53, 0xa5, 0x51, 0xe4, 0x29, 0x83, 0xd7, 0xf8, 0x90, 0x31, 0x5b, 0x42, 0x9f, 0x0a, 0xf5,
    0xfe, 0xae, 0x00, 0x68, 0xe7, 0x8c, 0x49, 0x0f, 0xb6, 0x6f, 0x5b, 0x5b, 0x15, 0xf2, 0xe7,
};

/* Before this the clock has not been set (no SNTP/RTC time yet). */
#define DERP_TLS_CLOCK_VALID_AFTER  1735689600  /* 2025-01-01 */

static int derp_wolf_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    int fd = *(int *)ctx;
    if (fd < 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    int ret = (int)ml_read_sock(fd, buf, sz);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
        if (errno == EPIPE || errno == ECONNRESET) return WOLFSSL_CBIO_ERR_CONN_RST;
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    if (ret == 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return ret;
}

static int derp_wolf_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    int fd = *(int *)ctx;
    if (fd < 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    int ret = (int)ml_write_sock(fd, buf, sz);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        }
        if (errno == EPIPE || errno == ECONNRESET) return WOLFSSL_CBIO_ERR_CONN_RST;
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    return ret;
}

#if CONFIG_ML_DERP_VERIFY_CERT
/* See the backend comment above. Called only for certificates wolfSSL
 * rejected (preverify == 0); returning 1 overrides that one error. */
static int derp_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX *store) {
    if (preverify) return 1;
    const int err = store->error;
    const int depth = store->error_depth;

    /* The prebuilt mbedTLS never checks validity dates
     * (MBEDTLS_HAVE_TIME_DATE is off). Match it while the clock is unset;
     * once it is set, dates are enforced. wolfSSL reports a date error only
     * after the signature checked out. */
    if ((err == ASN_BEFORE_DATE_E || err == ASN_AFTER_DATE_E) &&
        time(NULL) < DERP_TLS_CLOCK_VALID_AFTER) {
        ESP_LOGW(TAG, "DERP cert %d (%s): dates not checked, clock unset", depth,
                 store->domain ? store->domain : "");
        return 1;
    }
    if (depth <= 0 || depth >= store->totalCerts || store->certs == NULL) goto reject;

    DecodedCert *dc = malloc(2 * sizeof(DecodedCert));
    if (!dc) goto reject;
    int accept = 0;
    const char *why = "";
    wc_InitDecodedCert(&dc[0], store->certs[depth].buffer, store->certs[depth].length, NULL);
    /* NO_VERIFY: only reads the fields. A certificate whose key wolfSSL
     * can't parse (Ed25519 here) stops before its extensions, as it did in
     * the handshake, so isCA stays 0 there too and it is never a signer. */
    (void)wc_ParseCert(&dc[0], CERT_TYPE, NO_VERIFY, NULL);
    if (!dc[0].isCA) {
        accept = 1;
        why = "not a CA, ignored";
    } else if (dc[0].publicKey != NULL) {
        wc_InitDecodedCert(&dc[1], k_derp_root_isrg_x2, sizeof(k_derp_root_isrg_x2), NULL);
        if (wc_ParseCert(&dc[1], CA_TYPE, NO_VERIFY, NULL) == 0 &&
            dc[1].publicKey != NULL && dc[0].pubKeySize == dc[1].pubKeySize &&
            memcmp(dc[0].publicKey, dc[1].publicKey, dc[1].pubKeySize) == 0) {
            accept = 1;
            why = "trust anchor key";
        }
        wc_FreeDecodedCert(&dc[1]);
    }
    wc_FreeDecodedCert(&dc[0]);
    free(dc);
    if (accept) {
        ESP_LOGD(TAG, "DERP chain cert %d (%s): error %d, %s", depth,
                 store->domain ? store->domain : "", err, why);
        return 1;
    }
reject:
    ESP_LOGE(TAG, "DERP certificate %d (%s) not accepted: error %d", depth,
             store->domain ? store->domain : "", err);
    return 0;
}
#endif /* CONFIG_ML_DERP_VERIFY_CERT */

static void derp_tls_free(ml_derp_conn_t *c) {
    if (c->wssl) {
        wolfSSL_free((WOLFSSL *)c->wssl);
        c->wssl = NULL;
    }
    if (c->wctx) {
        wolfSSL_CTX_free((WOLFSSL_CTX *)c->wctx);
        c->wctx = NULL;
    }
}

static void derp_tls_abort(ml_derp_conn_t *c, int sock) {
    derp_tls_free(c);
    if (sock >= 0) {
        ml_close_sock(sock);
    }
    c->sockfd = -1;
}

static int derp_tls_map(ml_derp_conn_t *c, int ret) {
    if (ret > 0) return ret;
    const int err = wolfSSL_get_error((WOLFSSL *)c->wssl, ret);
    if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) return DERP_TLS_AGAIN;
    if (err == WOLFSSL_ERROR_ZERO_RETURN) return DERP_TLS_CLOSED;
    /* A dropped socket (SOCKET_PEER_CLOSED_E) is an error, as with mbedTLS
     * (its BIO maps a 0-byte read to CONN_RESET). */
    return err < 0 ? err : -1;
}

static int derp_tls_recv(ml_derp_conn_t *c, uint8_t *buf, size_t len) {
    if (!c->wssl) return -1;
    return derp_tls_map(c, wolfSSL_read((WOLFSSL *)c->wssl, buf, (int)len));
}

static int derp_tls_send(ml_derp_conn_t *c, const uint8_t *buf, size_t len) {
    if (!c->wssl) return -1;
    if (len == 0) return 0;
    return derp_tls_map(c, wolfSSL_write((WOLFSSL *)c->wssl, buf, (int)len));
}

static size_t derp_tls_pending(ml_derp_conn_t *c) {
    if (!c->wssl) return 0;
    int n = wolfSSL_pending((WOLFSSL *)c->wssl);
    return n > 0 ? (size_t)n : 0;
}

static void derp_tls_close(ml_derp_conn_t *c) {
    if (c->wssl) wolfSSL_shutdown((WOLFSSL *)c->wssl);
    derp_tls_free(c);
}

static void derp_tls_log_error(const char *what, int err) {
    char why[80];
    wolfSSL_ERR_error_string_n((unsigned long)err, why, sizeof(why));
    ESP_LOGE(TAG, "%s: %d (%s), free heap %u, largest block %u", what, err, why,
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
}

/* TLS setup + handshake over the connected socket `sock`. On failure the
 * session is freed and the socket closed. */
static esp_err_t derp_tls_start(microlink_t *ml, ml_derp_conn_t *c, int sock,
                                const char *derp_host) {
    c->wctx = NULL;
    c->wssl = NULL;
    /* TLS 1.2 or 1.3; Tailscale's relays (Go crypto/tls) pick 1.3. */
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (!ctx) {
        derp_tls_log_error("DERP TLS context alloc failed", MEMORY_E);
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }
    c->wctx = ctx;
    /* No resumption: the client session cache is global and unlocked
     * (SINGLE_THREADED), and the application's own TLS uses it. */
    wolfSSL_CTX_set_session_cache_mode(ctx, WOLFSSL_SESS_CACHE_OFF);
#if CONFIG_ML_DERP_VERIFY_CERT
    int lret = wolfSSL_CTX_load_verify_buffer(ctx, k_derp_root_isrg_x2,
                                              sizeof(k_derp_root_isrg_x2),
                                              WOLFSSL_FILETYPE_ASN1);
    if (lret != WOLFSSL_SUCCESS) {
        derp_tls_log_error("DERP TLS: loading the root certificate failed", lret);
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, derp_tls_verify_cb);
#else
    {
        static bool s_warned;
        if (!s_warned) {
            s_warned = true;
            ESP_LOGW(TAG, "DERP TLS certificates are not verified (CONFIG_ML_DERP_VERIFY_CERT=n)");
        }
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
#endif
    wolfSSL_SetIORecv(ctx, derp_wolf_recv);
    wolfSSL_SetIOSend(ctx, derp_wolf_send);

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl) {
        derp_tls_log_error("DERP TLS session alloc failed", MEMORY_E);
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }
    c->wssl = ssl;
    c->sockfd = sock;
    wolfSSL_SetIOReadCtx(ssl, &c->sockfd);
    wolfSSL_SetIOWriteCtx(ssl, &c->sockfd);
    wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, derp_host, (unsigned short)strlen(derp_host));
#if CONFIG_ML_DERP_VERIFY_CERT
    if (wolfSSL_check_domain_name(ssl, derp_host) != WOLFSSL_SUCCESS) {
        derp_tls_log_error("DERP TLS: setting the host name failed", MEMORY_E);
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }
#endif
#if defined(WOLFSSL_TLS13) && defined(HAVE_CURVE25519)
    /* One X25519 key share: no bignum temporaries, and Go offers it first. */
    wolfSSL_UseKeyShare(ssl, WOLFSSL_ECC_X25519);
#endif

    /* Socket has 10s SO_RCVTIMEO from the connect phase; the overall
     * deadline stops a relay that accepts TCP and then stalls. */
    const int64_t hs_deadline_us = esp_timer_get_time() + 20LL * 1000 * 1000;
    int ret;
    while ((ret = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, ret);
        if ((err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) &&
            esp_timer_get_time() < hs_deadline_us && !ml_shutdown_requested(ml)) {
            continue;
        }
        derp_tls_log_error("TLS handshake failed", err);
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "DERP TLS (wolfSSL) %s %s, free heap %u", wolfSSL_get_version(ssl),
             wolfSSL_get_cipher(ssl), (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    return ESP_OK;
}

#endif /* ML_LITE_DERP_WOLFSSL */

/* DERP frame types */
#define DERP_FRAME_SERVER_KEY   0x01
#define DERP_FRAME_CLIENT_INFO  0x02
#define DERP_FRAME_SERVER_INFO  0x03
#define DERP_FRAME_SEND_PACKET  0x04
#define DERP_FRAME_RECV_PACKET  0x05
#define DERP_FRAME_KEEP_ALIVE   0x06
#define DERP_FRAME_NOTE_PREFERRED 0x07
#define DERP_FRAME_PEER_GONE    0x08
#define DERP_FRAME_PING         0x12
#define DERP_FRAME_PONG         0x13

static esp_err_t derp_conn_open(microlink_t *ml, ml_derp_conn_t *c, const char *derp_host,
                                int derp_port, uint16_t derp_region_used, bool preferred);
static void derp_conn_close(ml_derp_conn_t *c);

/* DISCO magic bytes: "TS" + sparkles emoji UTF-8 */
static const uint8_t DISCO_MAGIC[6] = { 'T', 'S', 0xf0, 0x9f, 0x92, 0xac };

/* ============================================================================
 * TLS Read/Write Helpers
 * ========================================================================== */

/**
 * Read exactly `len` bytes via TLS with timeout and WANT_READ retry.
 * Returns number of bytes read on success, -1 on error, -2 on timeout.
 */
static int derp_tls_read_all(ml_derp_conn_t *c, uint8_t *data, size_t len, int timeout_ms) {
    size_t received = 0;
    uint64_t start_ms = ml_get_time_ms();

    while (received < len) {
        if (timeout_ms > 0 && (ml_get_time_ms() - start_ms) > (uint64_t)timeout_ms) {
            ESP_LOGW(TAG, "derp_tls_read_all timeout (%d/%d bytes in %dms)",
                     (int)received, (int)len, timeout_ms);
            return -2;
        }

        int ret = derp_tls_recv(c, data + received, len - received);
        if (ret < 0) {
            if (ret == DERP_TLS_AGAIN) {
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            if (ret == DERP_TLS_CLOSED) {
                ESP_LOGW(TAG, "DERP server closed connection");
                return -1;
            }
            ESP_LOGE(TAG, "TLS read failed: -0x%04x", -ret);
            return -1;
        }
        if (ret == 0) {
            ESP_LOGW(TAG, "TLS connection closed by peer (%d/%d bytes)",
                     (int)received, (int)len);
            return -1;
        }
        received += ret;
    }
    return (int)received;
}

/**
 * Read a DERP frame header (5 bytes: type + 4-byte BE length) with timeout.
 */
static esp_err_t derp_recv_frame_header(ml_derp_conn_t *c, uint8_t *type,
                                          uint32_t *len, int timeout_ms) {
    uint8_t header[5];
    int ret = derp_tls_read_all(c, header, 5, timeout_ms);
    if (ret < 0) {
        return (ret == -2) ? ESP_ERR_TIMEOUT : ESP_FAIL;
    }

    *type = header[0];
    *len = ((uint32_t)header[1] << 24) |
           ((uint32_t)header[2] << 16) |
           ((uint32_t)header[3] << 8) |
           (uint32_t)header[4];

    return ESP_OK;
}

/**
 * Write exactly `len` bytes via TLS with WANT_WRITE retry.
 * Returns bytes written on success, -1 on error.
 * No mutex needed — called only from the DERP I/O task.
 */
static int derp_tls_write_all(ml_derp_conn_t *c, const uint8_t *data, size_t len) {
    size_t written = 0;
    int retries = 0;
    const int max_retries = 50;  /* 50 * 10ms = 500ms max */

    while (written < len) {
        int ret = derp_tls_send(c, data + written, len - written);
        if (ret < 0) {
            if (ret == DERP_TLS_AGAIN) {
                vTaskDelay(pdMS_TO_TICKS(10));
                if (++retries > max_retries) {
                    ESP_LOGW(TAG, "TLS write timeout after %d retries", retries);
                    return -1;
                }
                continue;
            }
            ESP_LOGE(TAG, "TLS write failed: -0x%04x", -ret);
            return -1;
        }
        written += ret;
        retries = 0;
    }
    return (int)written;
}

/* Write a complete DERP frame via TLS */
static int derp_write_frame(ml_derp_conn_t *c, uint8_t type,
                             const uint8_t *payload, uint32_t len) {
    /* 5-byte header: 1 type + 4 length (big-endian) */
    uint8_t header[5];
    header[0] = type;
    header[1] = (len >> 24) & 0xFF;
    header[2] = (len >> 16) & 0xFF;
    header[3] = (len >> 8) & 0xFF;
    header[4] = len & 0xFF;

    if (derp_tls_write_all(c, header, 5) < 0) return -1;

    if (len > 0 && payload) {
        if (derp_tls_write_all(c, payload, len) < 0) return -1;
    }
    return 0;
}

/* Send a packet to a peer via DERP */
static int derp_send_packet(ml_derp_conn_t *c, const uint8_t *dest_key,
                              const uint8_t *data, size_t len) {
    /* SendPacket frame: 32-byte dest key + payload */
    size_t frame_len = 32 + len;
    uint8_t *frame = malloc(frame_len);
    if (!frame) return -1;

    memcpy(frame, dest_key, 32);
    memcpy(frame + 32, data, len);

    int ret = derp_write_frame(c, DERP_FRAME_SEND_PACKET, frame, frame_len);
    if (ret < 0) {
        ESP_LOGW(TAG, "derp_send_packet FAILED: dest=%02x%02x%02x%02x len=%d",
                 dest_key[0], dest_key[1], dest_key[2], dest_key[3], (int)len);
    }
    free(frame);
    return ret;
}

/* ============================================================================
 * DERP Frame Reading and Dispatch (runs on DERP I/O task)
 * ========================================================================== */

/* Packet classification */
typedef enum {
    PKT_DISCO,
    PKT_STUN,
    PKT_WIREGUARD,
    PKT_UNKNOWN,
} pkt_type_t;

static pkt_type_t classify_packet(const uint8_t *data, size_t len) {
    if (len >= 20 && (data[0] == 0x00 || data[0] == 0x01) && data[1] == 0x01) {
        return PKT_STUN;
    }
    if (len >= 62 && memcmp(data, DISCO_MAGIC, 6) == 0) {
        return PKT_DISCO;
    }
    if (len >= 4) {
        return PKT_WIREGUARD;
    }
    return PKT_UNKNOWN;
}

static void route_derp_packet(microlink_t *ml, uint8_t *data, size_t len,
                               const uint8_t *src_pubkey) {
    pkt_type_t type = classify_packet(data, len);

    ml_rx_packet_t pkt = {
        .data = data,
        .len = len,
        .via_derp = true,
    };
    memcpy(pkt.src_pubkey, src_pubkey, 32);

    QueueHandle_t target = (type == PKT_DISCO) ? ml->disco_rx_queue : ml->wg_rx_queue;
    if (xQueueSend(target, &pkt, 0) != pdTRUE) {
        free(data);
    } else {
        ml_wg_mgr_wake(ml);
    }
}

/* Dispatch a received DERP frame */
static void dispatch_derp_frame(microlink_t *ml, ml_derp_conn_t *c, uint8_t frame_type,
                                 uint8_t *src_key, uint8_t *payload, size_t payload_len) {
    switch (frame_type) {
    case DERP_FRAME_RECV_PACKET:
        if (payload) {
            ESP_LOGD(TAG, "DERP RecvPacket: %d bytes from %02x%02x%02x%02x, hdr=%02x",
                     (int)payload_len,
                     src_key[0], src_key[1], src_key[2], src_key[3],
                     payload_len > 0 ? payload[0] : 0xFF);
            route_derp_packet(ml, payload, payload_len, src_key);
            return;  /* payload ownership transferred */
        }
        break;

    case DERP_FRAME_KEEP_ALIVE:
        ESP_LOGD(TAG, "DERP KeepAlive received");
        break;

    case DERP_FRAME_PING:
        /* Echo ping data back as PONG directly (single-threaded, safe to write) */
        if (payload && payload_len > 0) {
            ESP_LOGD(TAG, "DERP PING received, sending PONG");
            derp_write_frame(c, DERP_FRAME_PONG, payload, payload_len);
        }
        break;

    case DERP_FRAME_PONG:
        ESP_LOGD(TAG, "DERP PONG received");
        break;

    case DERP_FRAME_PEER_GONE:
        if (payload && payload_len >= 32) {
            ESP_LOGD(TAG, "DERP PeerGone: %02x%02x%02x%02x (len=%d)",
                     payload[0], payload[1], payload[2], payload[3],
                     (int)payload_len);
        }
        break;

    default:
        ESP_LOGD(TAG, "DERP frame type 0x%02x ignored (%d bytes)",
                 frame_type, (int)payload_len);
        break;
    }

    if (payload) free(payload);
}

/**
 * Try to read one DERP frame.
 * SO_RCVTIMEO on the socket bounds each read, so ssl_read never blocks
 * indefinitely (timeout surfaces as WANT_READ from the blocking-recv BIO).
 * Returns: 1 = frame read and dispatched, 0 = timeout (no data), <0 = error
 */
static int poll_derp_read(microlink_t *ml, ml_derp_conn_t *c) {
    if (!c->connected || c->sockfd < 0) return -1;

    /* Read 5-byte frame header.
     * SO_RCVTIMEO=100ms ensures read() returns within 100ms if no data. */
    uint8_t header[5];
    int n = derp_tls_recv(c, header, 5);
    if (n == DERP_TLS_AGAIN) {
        return 0;  /* No data available / timeout */
    }
    if (n <= 0) {
        ESP_LOGW(TAG, "DERP header read returned %d (0x%04x)", n, n < 0 ? -n : 0);
        return n;
    }
    if (n < 5) {
        /* ssl_read returns at most the rest of the current TLS record, and
         * a relay may split a frame header across records. Finish it; the
         * stream is only misaligned if the rest never arrives. Same 5 s
         * as the payload: the next record can be slow on the AT bridge. */
        if (derp_tls_read_all(c, header + n, 5 - n, 5000) < 0) {
            ESP_LOGW(TAG, "DERP partial header: got %d of 5 bytes", n);
            return -1;
        }
    }

    uint8_t frame_type = header[0];
    uint32_t len = (header[1] << 24) | (header[2] << 16) | (header[3] << 8) | header[4];

    uint8_t src_key[32] = {0};
    uint8_t *payload = NULL;
    size_t payload_len = 0;

    if (len == 0) {
        dispatch_derp_frame(ml, c, frame_type, src_key, NULL, 0);
        return 1;
    }

    if (len > 65536) {
        ESP_LOGW(TAG, "DERP frame too large: %lu", (unsigned long)len);
        return -1;
    }

    /* Read frame payload - we already got the header so payload should follow.
     * Use longer timeout (2s) since we KNOW data is coming. */
    uint8_t *buf = ml_psram_malloc(len);
    if (!buf) return -1;

    size_t total_read = 0;
    uint64_t payload_start = ml_get_time_ms();
    while (total_read < len) {
        /* Safety timeout: 5 seconds for payload */
        if (ml_get_time_ms() - payload_start > 5000) {
            ESP_LOGW(TAG, "DERP payload timeout at %d/%lu bytes",
                     (int)total_read, (unsigned long)len);
            free(buf);
            return -1;
        }
        n = derp_tls_recv(c, buf + total_read, len - total_read);
        if (n == DERP_TLS_AGAIN) {
            vTaskDelay(pdMS_TO_TICKS(5));
            continue;
        }
        if (n <= 0) {
            ESP_LOGW(TAG, "DERP payload read error: %d (0x%04x) at %d/%lu bytes",
                     n, n < 0 ? -n : 0, (int)total_read, (unsigned long)len);
            free(buf);
            return n;
        }
        total_read += n;
    }

    /* For RecvPacket (0x05): first 32 bytes are sender's public key */
    if (frame_type == DERP_FRAME_RECV_PACKET && len <= 32) {
        /* Too short to carry a source key + payload: drop rather than route
         * it with an all-zero source key. */
        free(buf);
        return 1;
    }
    if (frame_type == DERP_FRAME_RECV_PACKET) {
        memcpy(src_key, buf, 32);
        payload = malloc(len - 32);
        if (payload) {
            memcpy(payload, buf + 32, len - 32);
            payload_len = len - 32;
        }
        free(buf);
    } else {
        payload = buf;
        payload_len = len;
    }

    dispatch_derp_frame(ml, c, frame_type, src_key, payload, payload_len);
    return 1;
}

/* ============================================================================
 * DERP TX Queue Processing
 * ========================================================================== */

/* ============================================================================
 * Idle waiting (no fixed-interval polling)
 *
 * The DERP I/O task used to spin with vTaskDelay(1) (~1000 wakeups/s while
 * idle), which also kept the chip out of light sleep. It now blocks in
 * select() on the DERP socket plus an eventfd that ml_derp_queue_send()
 * signals, so it wakes for incoming data, outgoing packets, or a periodic
 * timeout. The AT-socket bridge has no real fd: there it waits on the TX
 * queue with a short timeout (incoming data is polled at that rate).
 * Approach after TailTiny's idle work (Asimmimx/tailtiny 6335e77, bfa95f3).
 * ========================================================================== */

#define DERP_IDLE_WAIT_MS     250   /* upper bound: keepalives/reconnects are slower */
#define DERP_AT_POLL_MS       20

static void derp_wake(microlink_t *ml) {
    int fd = ml->derp_wake_fd;
    if (fd >= 0) {
        uint64_t one = 1;
        (void)write(fd, &one, sizeof(one));
    }
}

static void derp_wake_init(microlink_t *ml) {
    if (ml->derp_wake_fd >= 0) return;
    esp_vfs_eventfd_config_t cfg = ESP_VFS_EVENTD_CONFIG_DEFAULT();
    esp_err_t err = esp_vfs_eventfd_register(&cfg);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {   /* INVALID_STATE: already registered */
        ESP_LOGW(TAG, "eventfd unavailable (%s); DERP task will poll", esp_err_to_name(err));
        return;
    }
    int fd = eventfd(0, 0);
    if (fd < 0) {
        ESP_LOGW(TAG, "eventfd() failed (errno %d); DERP task will poll", errno);
        return;
    }
    ml->derp_wake_fd = fd;
}

void ml_derp_idle_wait(microlink_t *ml, uint32_t max_ms) {
    if (uxQueueMessagesWaiting(ml->derp_tx_queue) > 0) return;
    if (ml->derp.connected && derp_tls_pending(&ml->derp) > 0) return;
    for (int i = 0; i < ML_DERP_EXTRA_CONNS; i++) {
        ml_derp_conn_t *x = &ml->derp_extra[i];
        if (x->connected && derp_tls_pending(x) > 0) return;
    }

    int sock = ml->derp.sockfd;
    int wfd = ml->derp_wake_fd;
    if (sock >= 0 && wfd >= 0 && !ml_at_socket_is_at_fd(sock)) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        FD_SET(wfd, &rfds);
        int maxfd = sock > wfd ? sock : wfd;
        for (int i = 0; i < ML_DERP_EXTRA_CONNS; i++) {
            int xfd = ml->derp_extra[i].sockfd;
            if (ml->derp_extra[i].connected && xfd >= 0) {
                FD_SET(xfd, &rfds);
                if (xfd > maxfd) maxfd = xfd;
            }
        }
        struct timeval tv = { .tv_sec = 0, .tv_usec = max_ms * 1000 };
        int n = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (n > 0 && FD_ISSET(wfd, &rfds)) {
            uint64_t v;
            (void)read(wfd, &v, sizeof(v));
        } else if (n < 0) {
            vTaskDelay(pdMS_TO_TICKS(10));   /* never spin on a select error */
        }
    } else {
        ml_derp_tx_item_t peek;
        (void)xQueuePeek(ml->derp_tx_queue, &peek,
                         pdMS_TO_TICKS(max_ms < DERP_AT_POLL_MS ? max_ms : DERP_AT_POLL_MS));
    }
}

/* Home relay region of the peer with this node key (0 = unknown: use ours).
 * peers[] is owned by wg_mgr and this also runs on the tcpip thread (the
 * WireGuard output callback); a read racing a slot being replaced can only
 * pick the wrong relay for one packet, which WireGuard retransmits. */
static uint16_t derp_region_of_peer(microlink_t *ml, const uint8_t *key) {
    for (int i = 0; i < ML_MAX_PEERS; i++) {
        const ml_peer_t *p = &ml->peers[i];
        if (p->active && memcmp(p->public_key, key, 32) == 0) return p->derp_region;
    }
    return 0;
}

/* The connection a packet for `region` goes out on: ours when it is our home
 * region (or unknown), else one to that region, opened on demand. Falls back
 * to the home connection while a region cannot be reached. DERP task only. */
static ml_derp_conn_t *derp_conn_for_region(microlink_t *ml, uint16_t region) {
    if (region == 0 || region == ml->derp.region || ML_DERP_EXTRA_CONNS <= 0) return &ml->derp;
    uint64_t now = ml_get_time_ms();
    ml_derp_conn_t *slot = NULL;
    for (int i = 0; i < ML_DERP_EXTRA_CONNS; i++) {
        ml_derp_conn_t *x = &ml->derp_extra[i];
        if (x->region != region) continue;
        if (x->connected) { x->last_tx_ms = now; return x; }
        if (now < x->retry_after_ms) return &ml->derp;   /* backing off */
        slot = x;
        break;
    }
    if (!slot) {
        /* A free slot, else the one idle longest. */
        for (int i = 0; i < ML_DERP_EXTRA_CONNS; i++) {
            ml_derp_conn_t *x = &ml->derp_extra[i];
            if (!x->connected && now >= x->retry_after_ms) { slot = x; break; }
            if (x->connected && (!slot || x->last_tx_ms < slot->last_tx_ms)) slot = x;
        }
        if (!slot) return &ml->derp;
        if (slot->connected) {
            ESP_LOGI(TAG, "Closing DERP region %d connection for region %d", slot->region, region);
        }
        derp_conn_close(slot);
    }

    const ml_derp_region_t *r = NULL;
    for (int i = 0; i < ml->derp_region_count; i++) {
        if (ml->derp_regions[i].region_id == region) { r = &ml->derp_regions[i]; break; }
    }
    const ml_derp_node_t *node = NULL;
    for (int j = 0; r && j < r->node_count; j++) {
        if (!r->nodes[j].stun_only && r->nodes[j].hostname[0]) { node = &r->nodes[j]; break; }
    }
    slot->region = region;
    if (!node || ml_shutdown_requested(ml)) {
        slot->retry_after_ms = now + ML_DERP_EXTRA_RETRY_MS;
        return &ml->derp;
    }
    int port = node->derp_port > 0 ? node->derp_port : ML_DERP_PORT;
    if (derp_conn_open(ml, slot, node->hostname, port, region, false) != ESP_OK) {
        ESP_LOGW(TAG, "DERP region %d unreachable; using home region %d for now", region,
                 ml->derp.region);
        slot->region = region;
        slot->retry_after_ms = ml_get_time_ms() + ML_DERP_EXTRA_RETRY_MS;
        return &ml->derp;
    }
    slot->retry_after_ms = 0;
    return slot;
}

/* Queue a packet for DERP TX with backpressure */
esp_err_t ml_derp_queue_send(microlink_t *ml, const uint8_t *dest_key,
                              const uint8_t *data, size_t len) {
    if (!ml || !dest_key || !data || len == 0) return ESP_ERR_INVALID_ARG;

    uint8_t *pkt_data = malloc(len);
    if (!pkt_data) return ESP_ERR_NO_MEM;
    memcpy(pkt_data, data, len);

    ml_derp_tx_item_t item = {
        .data = pkt_data,
        .len = len,
        .frame_type = DERP_FRAME_SEND_PACKET,
        .region = derp_region_of_peer(ml, dest_key),
    };
    memcpy(item.dest_pubkey, dest_key, 32);

    /* WG handshake packets (type 1=init, 2=response) get priority — front of queue.
     * This ensures handshake responses aren't delayed behind DISCO pings. */
    bool is_wg_handshake = (len >= 4 && (data[0] == 0x01 || data[0] == 0x02));

    /* Try to send to queue */
    if ((is_wg_handshake ? xQueueSendToFront(ml->derp_tx_queue, &item, 0)
                         : xQueueSend(ml->derp_tx_queue, &item, 0)) == pdTRUE) {
        derp_wake(ml);
        return ESP_OK;
    }

    /* Queue full - backpressure: drop oldest, retry up to 3 times */
    for (int i = 0; i < 3; i++) {
        ml_derp_tx_item_t dropped;
        if (xQueueReceive(ml->derp_tx_queue, &dropped, 0) == pdTRUE) {
            free(dropped.data);  /* Drop oldest */
        }
        if (xQueueSend(ml->derp_tx_queue, &item, 0) == pdTRUE) {
            derp_wake(ml);
            return ESP_OK;
        }
    }

    /* Still full after 3 attempts, drop new packet */
    free(pkt_data);
    return ESP_ERR_TIMEOUT;
}

/* ============================================================================
 * Unified DERP I/O Task
 * ========================================================================== */

void ml_derp_io_begin(microlink_t *ml, ml_derp_io_t *io) {
    memset(io, 0, sizeof(*io));
    derp_wake_init(ml);
}

ml_derp_step_t ml_derp_io_step(microlink_t *ml, ml_derp_io_t *io) {
    io->loop_count++;
    uint64_t loop_start = ml_get_time_ms();

    /* Unconditional heartbeat - proves task is alive */
    if (loop_start - io->last_heartbeat_ms > 5000) {
        ESP_LOGD(TAG, "HEARTBEAT: loop=%lu conn=%d rx=%lu tx=%lu stack_free=%lu",
                 (unsigned long)io->loop_count, ml->derp.connected,
                 (unsigned long)io->frames_rx, (unsigned long)io->frames_tx,
                 (unsigned long)uxTaskGetStackHighWaterMark(NULL));
        io->last_heartbeat_ms = loop_start;
    }

    /* ---- Periodic status logging (always, even when disconnected) ---- */
    {
        uint64_t now_ms = loop_start;
        if (now_ms - io->last_status_ms > 10000) {
            ESP_LOGD(TAG, "DERP status: connected=%d fd=%d rx=%lu tx=%lu loops=%lu",
                     ml->derp.connected, ml->derp.sockfd,
                     (unsigned long)io->frames_rx, (unsigned long)io->frames_tx,
                     (unsigned long)io->loop_count);
            io->last_status_ms = now_ms;
        }
    }

    /* ---- Handle DERP connect request from coord task ---- */
    {
        EventBits_t bits = xEventGroupGetBits(ml->events);
        /* Always consume a connect request. One that arrives while we
         * are connected (or reconnecting) is already satisfied; left
         * set, it would fire after the next read/write error and run a
         * connect over the failed, not yet freed session. A pending
         * RECONNECT does the full disconnect + connect itself. */
        if (bits & ML_EVT_DERP_CONNECT_REQ) {
            xEventGroupClearBits(ml->events, ML_EVT_DERP_CONNECT_REQ);
        }
        if ((bits & ML_EVT_DERP_CONNECT_REQ) && !ml->derp.connected &&
            !(bits & ML_EVT_DERP_RECONNECT)) {
            /* Retry up to 3 times with 2s backoff */
            for (int attempt = 0; attempt < 3 && !ml->derp.connected; attempt++) {
                if (attempt > 0) {
                    ESP_LOGW(TAG, "DERP connect retry %d/3 in 2s...", attempt + 1);
                    vTaskDelay(pdMS_TO_TICKS(2000));
                } else {
                    ESP_LOGI(TAG, "DERP connect requested, connecting from I/O task");
                }
                /* Each attempt can cost a DNS timeout plus a 20 s TLS
                 * handshake; don't start one that stop will discard. */
                if (ml_shutdown_requested(ml)) break;
                if (ml_derp_connect(ml) == ESP_OK) {
                    io->connected_since_ms = ml_get_time_ms();
                    io->verbose_phase = true;
                    break;
                }
                ESP_LOGW(TAG, "DERP connect attempt %d failed", attempt + 1);
            }
        }
        if (bits & ML_EVT_DERP_RECONNECT) {
            xEventGroupClearBits(ml->events, ML_EVT_DERP_RECONNECT);
            ESP_LOGW(TAG, "DERP reconnect requested (was %s)",
                     ml->derp.connected ? "connected" : "disconnected");
            ml_derp_disconnect(ml);
            io->verbose_phase = false;
            /* Auto-reconnect after disconnect */
            vTaskDelay(pdMS_TO_TICKS(1000));
            for (int attempt = 0; attempt < 3 && !ml->derp.connected; attempt++) {
                if (attempt > 0) {
                    ESP_LOGW(TAG, "DERP reconnect retry %d/3 in 2s...", attempt + 1);
                    vTaskDelay(pdMS_TO_TICKS(2000));
                }
                if (ml_shutdown_requested(ml)) break;
                if (ml_derp_connect(ml) == ESP_OK) {
                    io->connected_since_ms = ml_get_time_ms();
                    io->verbose_phase = true;
                    break;
                }
                ESP_LOGW(TAG, "DERP reconnect attempt %d failed", attempt + 1);
            }
        }
    }

    /* Disable verbose logging after 15s */
    if (io->verbose_phase && ml_get_time_ms() - io->connected_since_ms > 15000) {
        io->verbose_phase = false;
    }

    if (!ml->derp.connected) {
        return ML_DERP_STEP_DISCONNECTED;
    }

    /* ---- Phase 1: Drain TX queue FIRST (prioritize outgoing) ---- */
    {
        for (int tx_count = 0; tx_count < 8; tx_count++) {
            ml_derp_tx_item_t item;
            if (xQueueReceive(ml->derp_tx_queue, &item, 0) != pdTRUE) {
                break;
            }
            if (!ml->derp.connected) {
                free(item.data);
                continue;
            }
            int ret;
            ml_derp_conn_t *c = &ml->derp;
            if (item.frame_type == DERP_FRAME_SEND_PACKET) {
                c = derp_conn_for_region(ml, item.region);
                ESP_LOGD(TAG, "DERP TX: SendPacket %d bytes, dest=%02x%02x%02x%02x, hdr=%02x, region=%d",
                         (int)item.len, item.dest_pubkey[0], item.dest_pubkey[1],
                         item.dest_pubkey[2], item.dest_pubkey[3],
                         item.data[0], c->region);
                ret = derp_send_packet(c, item.dest_pubkey, item.data, item.len);
            } else {
                ret = derp_write_frame(c, item.frame_type, item.data, item.len);
            }
            if (ret < 0 && c != &ml->derp) {
                ESP_LOGW(TAG, "DERP region %d write failed; closing it", c->region);
                derp_conn_close(c);
            } else if (ret < 0) {
                ESP_LOGW(TAG, "DERP write failed");
                ml->derp.connected = false;
                xEventGroupSetBits(ml->events, ML_EVT_DERP_RECONNECT);
            } else {
                io->frames_tx++;
            }
            free(item.data);
        }
    }

    if (!ml->derp.connected) return ML_DERP_STEP_AGAIN;

    /* ---- Phase 2: Poll for incoming DERP frames ---- */
    {
        int burst;
        for (burst = 0; burst < 4; burst++) {
            int ret = poll_derp_read(ml, &ml->derp);
            if (ret > 0) {
                io->frames_rx++;
                ml->derp.last_recv_ms = ml_get_time_ms();
            } else if (ret == 0) {
                break;  /* No more data / timeout */
            } else {
                ESP_LOGW(TAG, "DERP read error: %d", ret);
                ml->derp.connected = false;
                xEventGroupSetBits(ml->events, ML_EVT_DERP_RECONNECT);
                break;
            }
        }
    }

    /* ---- Phase 3: other peers' relay regions ---- */
    for (int i = 0; i < ML_DERP_EXTRA_CONNS; i++) {
        ml_derp_conn_t *x = &ml->derp_extra[i];
        if (!x->connected) continue;
        for (int burst = 0; burst < 4; burst++) {
            int ret = poll_derp_read(ml, x);
            if (ret > 0) {
                io->frames_rx++;
                x->last_recv_ms = ml_get_time_ms();
            } else if (ret == 0) {
                break;
            } else {
                ESP_LOGW(TAG, "DERP region %d read error: %d; closing it", x->region, ret);
                derp_conn_close(x);
                break;
            }
        }
        if (x->connected && ml_get_time_ms() - x->last_tx_ms > ML_DERP_EXTRA_IDLE_MS) {
            ESP_LOGI(TAG, "DERP region %d idle; closing it", x->region);
            derp_conn_close(x);
        }
    }

    return ML_DERP_STEP_IDLE;
}

void ml_derp_io_end(microlink_t *ml) {
    /* Release the TLS session, the socket and any packets still queued for
     * TX. Nobody else may: the connection is owned by this task. */
    ML_HEAP_TRACE("derp_tx: exit begin");
    ml_derp_close_extras(ml);
    ml_derp_disconnect(ml);
    ML_HEAP_TRACE("derp_tx: TLS + socket freed");
}

void ml_derp_tx_task(void *arg) {
    microlink_t *ml = (microlink_t *)arg;
    ESP_LOGI(TAG, "DERP I/O task started (Core %d)", xPortGetCoreID());
    ml_derp_io_t io;
    ml_derp_io_begin(ml, &io);

    while (!(xEventGroupGetBits(ml->events) & ML_EVT_SHUTDOWN_REQUEST)) {
        switch (ml_derp_io_step(ml, &io)) {
        case ML_DERP_STEP_DISCONNECTED:
            /* Not connected - just wait and check again */
            vTaskDelay(pdMS_TO_TICKS(100));
            break;
        case ML_DERP_STEP_AGAIN:
            break;
        case ML_DERP_STEP_IDLE:
            /* Block until there is work (incoming data, queued TX) or a timeout */
            ml_derp_idle_wait(ml, DERP_IDLE_WAIT_MS);
            break;
        }
    }

    ml_derp_io_end(ml);
    ESP_LOGI(TAG, "DERP I/O task exiting");
    ml_task_exit(ml, ML_TASK_BIT_DERP_TX);
}

/* ============================================================================
 * DERP Connection Management (called from coord task)
 * ========================================================================== */

esp_err_t ml_derp_connect(microlink_t *ml) {
    /* A failed session is only marked (connected=false) by the read/write
     * error paths. Free it before the TLS contexts and sockfd below are
     * re-initialised, or its TLS buffers and lwIP socket leak. */
    if (ml->derp.sockfd >= 0) {
        ESP_LOGW(TAG, "DERP connect over an open session (fd=%d); closing it first",
                 ml->derp.sockfd);
        ml_derp_disconnect(ml);
    }

    /* Determine DERP host/port from DERPMap with node failover.
     * Always start from node 0 (the first/preferred node in the DERPMap).
     * Only rotate to a different node after a SUCCESSFUL connection drops,
     * NOT on connection failure (to avoid bouncing between nodes). */
    const char *derp_host = ML_DERP_HOST;
    int derp_port = ML_DERP_PORT;
    /* Track the region actually used, for logging (differs from HomeDERP on fallback) */
    uint16_t derp_region_used = ml->derp_home_region ? ml->derp_home_region : ML_DERP_REGION;
    bool node_selected = false;

    if (ml->derp_region_count > 0 && ml->derp_home_region > 0) {
        for (int i = 0; i < ml->derp_region_count; i++) {
            if (ml->derp_regions[i].region_id == ml->derp_home_region) {
                /* Always use the first non-stun-only node (preferred node).
                 * This ensures we connect to the same node as most peers. */
                for (int attempt = 0; attempt < ml->derp_regions[i].node_count; attempt++) {
                    if (!ml->derp_regions[i].nodes[attempt].stun_only &&
                        ml->derp_regions[i].nodes[attempt].hostname[0]) {
                        derp_host = ml->derp_regions[i].nodes[attempt].hostname;
                        if (ml->derp_regions[i].nodes[attempt].derp_port > 0) {
                            derp_port = ml->derp_regions[i].nodes[attempt].derp_port;
                        }
                        node_selected = true;
                        break;
                    }
                }
                break;
            }
        }
    }

    /* Fallback for when HomeDERP is not present in the DERPMap.
     * With headscale-based controllers (e.g. ZTL), HomeDERP may still point
     * at an official Tailscale region (e.g. 9) while the DERPMap only
     * contains their own region (e.g. 900). Falling back to the default
     * ML_DERP_HOST (official) in that case is a dead end — neither auth nor
     * TLS succeeds against the official DERP — so instead pick the first
     * usable node (not avoid, not stun-only, has a hostname) from the
     * DERPMap the controller handed out. In the normal official-Tailscale
     * case, HomeDERP is in the DERPMap so node_selected is set and this
     * branch is never taken; behavior is unchanged. */
    if (!node_selected && ml->derp_region_count > 0) {
        for (int i = 0; i < ml->derp_region_count && !node_selected; i++) {
            ml_derp_region_t *r = &ml->derp_regions[i];
            if (r->avoid) continue;
            for (int j = 0; j < r->node_count; j++) {
                if (!r->nodes[j].stun_only && r->nodes[j].hostname[0]) {
                    derp_host = r->nodes[j].hostname;
                    derp_port = (r->nodes[j].derp_port > 0) ? r->nodes[j].derp_port
                                                            : ML_DERP_PORT;
                    derp_region_used = r->region_id;
                    node_selected = true;
                    ESP_LOGW(TAG, "Home DERP region %d not in DERPMap, falling back to region %d (%s)",
                             ml->derp_home_region, derp_region_used, derp_host);
                    break;
                }
            }
        }
    }

    esp_err_t err = derp_conn_open(ml, &ml->derp, derp_host, derp_port, derp_region_used, true);
    if (err == ESP_OK) {
        xEventGroupSetBits(ml->events, ML_EVT_DERP_CONNECTED);
    }
    return err;
}

/* Open a DERP connection to one relay node. `preferred` marks it as our home
 * relay (NotePreferred), which only the home connection may claim. */
static esp_err_t derp_conn_open(microlink_t *ml, ml_derp_conn_t *c, const char *derp_host,
                                int derp_port, uint16_t derp_region_used, bool preferred) {
    int64_t t_derp_start = esp_timer_get_time();

    ESP_LOGI(TAG, "Connecting to DERP %s:%d (region %d%s)",
             derp_host, derp_port, derp_region_used, preferred ? ", home" : "");

    /* DNS resolve — accept IPv4 or IPv6 (carrier may be IPv6-only) */
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", derp_port);

    if (ml_getaddrinfo(derp_host, port_str, &hints, &res) != 0 || !res) {
        ESP_LOGE(TAG, "DNS resolve failed for %s", derp_host);
        return ESP_FAIL;
    }

    int64_t t_derp_dns = esp_timer_get_time();
    ESP_LOGD(TAG, "[TIMING] DERP DNS: %ld ms", (long)((t_derp_dns - t_derp_start) / 1000));

    /* TCP connect — use address family from DNS result */
    int sock = ml_socket(res->ai_family, SOCK_STREAM, 0);
    if (sock < 0) {
        ml_freeaddrinfo(res);
        return ESP_FAIL;
    }

    /* Set connect timeout */
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    ml_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    ml_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (ml_connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        ESP_LOGE(TAG, "TCP connect failed: %d", errno);
        ml_close_sock(sock);
        ml_freeaddrinfo(res);
        return ESP_FAIL;
    }
    ml_freeaddrinfo(res);

    int64_t t_derp_tcp = esp_timer_get_time();
    ESP_LOGD(TAG, "[TIMING] DERP TCP connect: %ld ms", (long)((t_derp_tcp - t_derp_dns) / 1000));

    if (derp_tls_start(ml, c, sock, derp_host) != ESP_OK) {
        return ESP_FAIL;
    }

    int64_t t_derp_tls = esp_timer_get_time();
    ESP_LOGD(TAG, "[TIMING] DERP TLS handshake: %ld ms", (long)((t_derp_tls - t_derp_tcp) / 1000));
    ESP_LOGD(TAG, "TLS connected to DERP");

    /* HTTP Upgrade: GET /derp with Upgrade: DERP header */
    char upgrade_req[256];
    snprintf(upgrade_req, sizeof(upgrade_req),
             "GET /derp HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: Upgrade\r\n"
             "Upgrade: DERP\r\n"
             "\r\n",
             derp_host);

    int ret = derp_tls_send(c, (const uint8_t *)upgrade_req, strlen(upgrade_req));
    if (ret < 0) {
        ESP_LOGE(TAG, "Failed to send HTTP upgrade");
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }

    /* Read HTTP response byte-by-byte until \r\n\r\n to avoid over-reading
     * into the DERP binary frame stream (matching v1 approach) */
    {
        uint8_t resp_buf[512];
        int resp_len = 0;
        bool found_end = false;
        uint64_t http_start = ml_get_time_ms();

        while (resp_len < (int)sizeof(resp_buf) - 1) {
            if (ml_get_time_ms() - http_start > DERP_CONNECT_TIMEOUT_MS) {
                ESP_LOGE(TAG, "HTTP upgrade response timeout");
                derp_tls_abort(c, sock);
                return ESP_FAIL;
            }

            ret = derp_tls_recv(c, resp_buf + resp_len, 1);
            if (ret < 0) {
                if (ret == DERP_TLS_AGAIN) {
                    vTaskDelay(pdMS_TO_TICKS(10));
                    continue;
                }
                ESP_LOGE(TAG, "HTTP upgrade read failed: -0x%04x", -ret);
                derp_tls_abort(c, sock);
                return ESP_FAIL;
            }
            if (ret == 0) {
                ESP_LOGE(TAG, "Connection closed during HTTP upgrade");
                derp_tls_abort(c, sock);
                return ESP_FAIL;
            }
            resp_len++;

            /* Check for \r\n\r\n */
            if (resp_len >= 4 &&
                resp_buf[resp_len - 4] == '\r' && resp_buf[resp_len - 3] == '\n' &&
                resp_buf[resp_len - 2] == '\r' && resp_buf[resp_len - 1] == '\n') {
                found_end = true;
                break;
            }
        }

        resp_buf[resp_len] = '\0';

        if (!found_end || strncmp((char *)resp_buf, "HTTP/1.1 101", 12) != 0) {
            ESP_LOGE(TAG, "DERP upgrade rejected: %.100s", resp_buf);
            derp_tls_abort(c, sock);
            return ESP_FAIL;
        }
        ESP_LOGD(TAG, "HTTP 101 Switching Protocols received");
    }

    /* Match v1 exactly: O_NONBLOCK + short SO_RCVTIMEO + SO_SNDTIMEO.
     * O_NONBLOCK ensures read()/write() never block indefinitely.
     * SO_RCVTIMEO provides 100ms polling rhythm for reads.
     * SO_SNDTIMEO prevents writes from blocking too long. */
    {
        int flags = ml_fcntl(sock, F_GETFL, 0);
        if (flags >= 0) {
            ml_fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        }
        struct timeval io_tv = { .tv_sec = 0, .tv_usec = 100000 };  /* 100ms */
        ml_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &io_tv, sizeof(io_tv));
        ml_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &io_tv, sizeof(io_tv));
    }

    /* ========================================================
     * DERP Handshake: ServerKey -> ClientInfo -> ServerInfo
     * ======================================================== */

    /* Step 1: Read ServerKey frame header using reliable read helper */
    uint8_t frame_type;
    uint32_t frame_len;
    esp_err_t err = derp_recv_frame_header(c, &frame_type, &frame_len, DERP_CONNECT_TIMEOUT_MS);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read ServerKey frame header (err=%d)", err);
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }

    if (frame_type != DERP_FRAME_SERVER_KEY || frame_len < 40) {
        ESP_LOGE(TAG, "Expected ServerKey frame (0x01), got 0x%02x len=%lu",
                 frame_type, (unsigned long)frame_len);
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }

    /* Read and verify 8-byte magic */
    uint8_t magic[8];
    static const uint8_t DERP_MAGIC[8] = {0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91};
    if (derp_tls_read_all(c, magic, 8, DERP_CONNECT_TIMEOUT_MS) < 0) {
        ESP_LOGE(TAG, "Failed to read ServerKey magic");
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }

    if (memcmp(magic, DERP_MAGIC, 8) != 0) {
        ESP_LOGE(TAG, "Invalid DERP magic: %02x%02x%02x%02x%02x%02x%02x%02x",
                 magic[0], magic[1], magic[2], magic[3],
                 magic[4], magic[5], magic[6], magic[7]);
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }
    ESP_LOGD(TAG, "DERP magic verified");

    /* Read 32-byte server public key */
    uint8_t derp_server_key[32];
    if (derp_tls_read_all(c, derp_server_key, 32, DERP_CONNECT_TIMEOUT_MS) < 0) {
        ESP_LOGE(TAG, "Failed to read server key");
        derp_tls_abort(c, sock);
        return ESP_FAIL;
    }

    ESP_LOGD(TAG, "DERP server key received (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             derp_server_key[0], derp_server_key[1], derp_server_key[2], derp_server_key[3],
             derp_server_key[4], derp_server_key[5], derp_server_key[6], derp_server_key[7]);

    /* Skip remaining bytes if frame_len > 40 */
    if (frame_len > 40) {
        uint8_t skip_buf[64];
        size_t remaining = frame_len - 40;
        while (remaining > 0) {
            size_t chunk = remaining > sizeof(skip_buf) ? sizeof(skip_buf) : remaining;
            if (derp_tls_read_all(c, skip_buf, chunk, DERP_CONNECT_TIMEOUT_MS) < 0) break;
            remaining -= chunk;
        }
    }

    /* Step 2: Send ClientInfo frame (type 0x02)
     * Payload: [our_nodekey(32)][nonce(24)][nacl_box(JSON)] */
    {
        const char *client_info_json = "{\"Version\":2,\"CanAckPings\":true,\"IsProber\":false}";
        size_t json_len = strlen(client_info_json);

        /* Generate random nonce */
        uint8_t nonce[NACL_BOX_NONCEBYTES];
        esp_fill_random(nonce, NACL_BOX_NONCEBYTES);

        /* Encrypt JSON with NaCl box: our WG private key -> DERP server public key */
        size_t ciphertext_len = json_len + NACL_BOX_MACBYTES;
        uint8_t *ciphertext = malloc(ciphertext_len);
        if (!ciphertext) {
            derp_tls_abort(c, sock);
            return ESP_FAIL;
        }

        if (nacl_box(ciphertext,
                     (const uint8_t *)client_info_json, json_len,
                     nonce,
                     derp_server_key,       /* recipient: DERP server */
                     ml->wg_private_key     /* sender: our WG node key */
                     ) != 0) {
            ESP_LOGE(TAG, "NaCl box encrypt failed");
            free(ciphertext);
            derp_tls_abort(c, sock);
            return ESP_FAIL;
        }

        /* Build ClientInfo frame payload: nodekey(32) + nonce(24) + ciphertext */
        size_t ci_payload_len = 32 + NACL_BOX_NONCEBYTES + ciphertext_len;
        uint8_t *ci_payload = malloc(ci_payload_len);
        if (!ci_payload) {
            free(ciphertext);
            derp_tls_abort(c, sock);
            return ESP_FAIL;
        }

        memcpy(ci_payload, ml->wg_public_key, 32);
        memcpy(ci_payload + 32, nonce, NACL_BOX_NONCEBYTES);
        memcpy(ci_payload + 32 + NACL_BOX_NONCEBYTES, ciphertext, ciphertext_len);
        free(ciphertext);

        ESP_LOGD(TAG, "DERP ClientInfo node_key=%02x%02x%02x%02x%02x%02x%02x%02x",
                 ml->wg_public_key[0], ml->wg_public_key[1],
                 ml->wg_public_key[2], ml->wg_public_key[3],
                 ml->wg_public_key[4], ml->wg_public_key[5],
                 ml->wg_public_key[6], ml->wg_public_key[7]);

        /* Send ClientInfo frame */
        if (derp_write_frame(c, DERP_FRAME_CLIENT_INFO, ci_payload, ci_payload_len) < 0) {
            ESP_LOGE(TAG, "Failed to send ClientInfo");
            free(ci_payload);
            derp_tls_abort(c, sock);
            return ESP_FAIL;
        }
        free(ci_payload);

        ESP_LOGD(TAG, "ClientInfo sent");
    }

    /* Step 3: Read ServerInfo frame (type 0x03) */
    {
        uint8_t si_type;
        uint32_t si_len;
        err = derp_recv_frame_header(c, &si_type, &si_len, DERP_CONNECT_TIMEOUT_MS);
        if (err == ESP_OK && si_type == DERP_FRAME_SERVER_INFO && si_len > 0) {
            /* Read and discard ServerInfo payload */
            uint8_t *si_buf = malloc(si_len);
            if (si_buf) {
                derp_tls_read_all(c, si_buf, si_len, DERP_CONNECT_TIMEOUT_MS);
                free(si_buf);
            }
            ESP_LOGD(TAG, "ServerInfo received (discarded)");
        } else if (err != ESP_OK) {
            ESP_LOGW(TAG, "No ServerInfo frame (continuing anyway)");
        }
    }

    /* Send NotePreferred (type 0x07): whether this is our home DERP */
    {
        uint8_t note = preferred ? 0x01 : 0x00;
        derp_write_frame(c, DERP_FRAME_NOTE_PREFERRED, &note, 1);
    }

    /* Switch socket to short timeout for data phase.
     * Long timeout was needed for TLS handshake, but polling must be fast.
     * conf_read_timeout is deliberately not called: recv uses the f_recv
     * (blocking) scheme, so only SO_RCVTIMEO takes effect (with
     * f_recv_timeout unused, conf_read_timeout would be a no-op; same
     * policy as the TLS 1.3 Bad input data workaround). */
    {
        struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };  /* 200ms */
        ml_setsockopt(c->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    c->connected = true;
    c->region = derp_region_used;
    c->last_recv_ms = ml_get_time_ms();
    c->last_tx_ms = c->last_recv_ms;

    int64_t t_derp_done = esp_timer_get_time();
    ESP_LOGI(TAG, "[TIMING] DERP total: %ld ms (DNS=%ld, TCP=%ld, TLS=%ld, proto=%ld)",
             (long)((t_derp_done - t_derp_start) / 1000),
             (long)((t_derp_dns - t_derp_start) / 1000),
             (long)((t_derp_tcp - t_derp_dns) / 1000),
             (long)((t_derp_tls - t_derp_tcp) / 1000),
             (long)((t_derp_done - t_derp_tls) / 1000));
    ESP_LOGI(TAG, "DERP handshake complete, connected");
    return ESP_OK;
}

static void derp_conn_close(ml_derp_conn_t *c) {
    c->connected = false;
    if (c->sockfd >= 0) {
        derp_tls_close(c);
        ml_close_sock(c->sockfd);
        c->sockfd = -1;
    }
}

/* Close every connection to another peer's relay region (DERP task only). */
void ml_derp_close_extras(microlink_t *ml) {
    for (int i = 0; i < ML_DERP_EXTRA_CONNS; i++) {
        if (ml->derp_extra[i].sockfd >= 0) {
            ESP_LOGI(TAG, "Closing DERP region %d connection", ml->derp_extra[i].region);
        }
        derp_conn_close(&ml->derp_extra[i]);
        ml->derp_extra[i].region = 0;
        ml->derp_extra[i].retry_after_ms = 0;
    }
}

void ml_derp_disconnect(microlink_t *ml) {
    xEventGroupClearBits(ml->events, ML_EVT_DERP_CONNECTED);
    derp_conn_close(&ml->derp);

    /* Drain TX queue */
    ml_derp_tx_item_t item;
    while (xQueueReceive(ml->derp_tx_queue, &item, 0) == pdTRUE) {
        free(item.data);
    }

    ESP_LOGI(TAG, "DERP disconnected");
}
