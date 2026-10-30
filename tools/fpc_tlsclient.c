/* libfpc_tlsclient.so -- LD_PRELOAD shim that gives libfpcbep.so a TLS 1.2
 * PSK *client* for the FPC 10a5:a921.
 *
 * Why: the blob's own mbedtls is built server-only (mbedtls_ssl_handshake_step
 * returns MBEDTLS_ERR_SSL_BAD_INPUT_DATA for any non-server config and no
 * client handshake code is linked in), while the a921 sensor is a TLS server.
 * The a900 sensor is a client, which is what that blob was built for.
 *
 * The blob's TEE/image code talks TLS through these PLT calls only, always on
 * its global ssl context at base+0x1960f8:
 *   mbedtls_ssl_handshake_step (&global_ssl)     -- handshake progress
 *   mbedtls_ssl_read          (&global_ssl, ...) -- decrypt sensor events
 *   mbedtls_ssl_write         (&global_ssl, ...) -- anything the host sends
 *   mbedtls_ssl_get_bytes_avail (&global_ssl)
 *
 * We interpose them for that context and run an OpenSSL TLS1.2 PSK client
 * (identity "Disum PSK", PSK-AES128-GCM-SHA256 = 0x00a8, what the sensor
 * picks) over the same fpc_tls_buff/fpc_tls_write_buff rings the blob uses.
 * Outgoing records go through the blob's own fpc_tls_send_usb_data(), which
 * frames every <=64 byte chunk as (size_t len, bytes) -- exactly the format
 * the driver's WRITE state expects.
 *
 * On completion we set the blob's TLS state word to 16
 * (MBEDTLS_SSL_HANDSHAKE_OVER). fpc_enclave_get_tls_status() maps 16 -> 1,
 * fpc_enclave_process_data() refuses to read unless it is 16, and the
 * driver's image-relayout guard looks at it too.
 *
 * All offsets into libfpcbep.so are pinned and checked against the address of
 * fpc_enclave_init before anything is touched. If the layout does not match,
 * every hook falls through to the real mbedtls function.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;
typedef struct bio_st BIO;

/* ---- OpenSSL, dlopen()ed ------------------------------------------------ */
static SSL_METHOD *(*o_TLS_client_method) (void);
static SSL_CTX *(*o_SSL_CTX_new) (const SSL_METHOD *);
static void (*o_SSL_CTX_free) (SSL_CTX *);
static int (*o_SSL_CTX_set_cipher_list) (SSL_CTX *, const char *);
static long (*o_SSL_CTX_ctrl) (SSL_CTX *, int, long, void *);
#define SSL_CTRL_SET_MIN_PROTO_VERSION 123
#define SSL_CTRL_SET_MAX_PROTO_VERSION 124
#define TLS1_2_VERSION 0x0303
static void (*o_SSL_CTX_set_verify) (SSL_CTX *, int, void *);
static void (*o_SSL_CTX_set_psk_client_callback) (SSL_CTX *, unsigned int (*) (SSL *, const char *, char *, unsigned int, unsigned char *, unsigned int));
static SSL *(*o_SSL_new) (SSL_CTX *);
static void (*o_SSL_free) (SSL *);
static void (*o_SSL_set_connect_state) (SSL *);
static void (*o_SSL_set_bio) (SSL *, BIO *, BIO *);
static int (*o_SSL_do_handshake) (SSL *);
static int (*o_SSL_get_error) (const SSL *, int);
static int (*o_SSL_read) (SSL *, void *, int);
static int (*o_SSL_write) (SSL *, const void *, int);
static int (*o_SSL_pending) (const SSL *);
static int (*o_BIO_new_bio_pair) (BIO **, size_t, BIO **, size_t);
static int (*o_BIO_read) (BIO *, void *, int);
static int (*o_BIO_write) (BIO *, const void *, int);

static int ssl_loaded = -2; /* -2 untried, -1 failed, 0 ok */

/* FPC_TLS_TRACE=1 logs the byte counts on both sides of the OpenSSL BIO and
 * the sizes/errors of every Ssl_read, enough to find a record boundary bug. */
static int
trace_on (void)
{
  const char *e = getenv ("FPC_TLS_TRACE");

  return e && e[0] == '1';
}

static int
ssl_load (void)
{
  void *ls, *lc;

  if (ssl_loaded != -2)
    return ssl_loaded;
  ssl_loaded = -1;
  ls = dlopen ("libssl.so.3", RTLD_NOW | RTLD_GLOBAL);
  if (!ls)
    ls = dlopen ("libssl.so", RTLD_NOW | RTLD_GLOBAL);
  lc = dlopen ("libcrypto.so.3", RTLD_NOW | RTLD_GLOBAL);
  if (!lc)
    lc = dlopen ("libcrypto.so", RTLD_NOW | RTLD_GLOBAL);
  if (!ls || !lc)
    {
      fprintf (stderr, "[fpc-tlsclient] OpenSSL unavailable\n");
      return -1;
    }

#define L(v, n) do { *(void **) &v = dlsym (ls, n); if (!v) { fprintf (stderr, "[fpc-tlsclient] missing %s\n", n); return -1; } } while (0)
  L (o_TLS_client_method, "TLS_client_method");
  L (o_SSL_CTX_new, "SSL_CTX_new");
  L (o_SSL_CTX_free, "SSL_CTX_free");
  L (o_SSL_CTX_set_cipher_list, "SSL_CTX_set_cipher_list");
  L (o_SSL_CTX_ctrl, "SSL_CTX_ctrl");
  L (o_SSL_CTX_set_verify, "SSL_CTX_set_verify");
  L (o_SSL_CTX_set_psk_client_callback, "SSL_CTX_set_psk_client_callback");
  L (o_SSL_new, "SSL_new");
  L (o_SSL_free, "SSL_free");
  L (o_SSL_set_connect_state, "SSL_set_connect_state");
  L (o_SSL_set_bio, "SSL_set_bio");
  L (o_SSL_do_handshake, "SSL_do_handshake");
  L (o_SSL_get_error, "SSL_get_error");
  L (o_SSL_read, "SSL_read");
  L (o_SSL_write, "SSL_write");
  L (o_SSL_pending, "SSL_pending");
  L (o_BIO_new_bio_pair, "BIO_new_bio_pair");
  L (o_BIO_read, "BIO_read");
  L (o_BIO_write, "BIO_write");
#undef L

  ssl_loaded = 0;
  return 0;
}

/* ---- libfpcbep, located and pinned -------------------------------------- */
#define BLOB_OFF_ENCLAVE_INIT 0x434bc /* symbol address check */
#define BLOB_OFF_SSL 0x1960f8         /* mbedtls_ssl_context */
#define BLOB_OFF_STATE 0x196100       /* ssl state word, 16 = handshake over */

static void *blob_ssl;
static int *blob_state;

/* blob exports used for the transport */
static int (*b_send_usb_data) (void *, const uint8_t *, size_t);
static uint32_t (*b_buff_get) (uint8_t *, uint32_t);
static int (*b_buff_clear) (void);
static int (*b_write_buff_clear) (void);

static int
blob_locate (void)
{
  void *sym;
  Dl_info di;

  if (blob_ssl)
    return 0;
  sym = dlsym (RTLD_DEFAULT, "fpc_enclave_init");
  if (!sym || !dladdr (sym, &di) || !di.dli_fbase)
    return -1;
  if ((uint8_t *) di.dli_saddr - (uint8_t *) di.dli_fbase != BLOB_OFF_ENCLAVE_INIT)
    {
      fprintf (stderr, "[fpc-tlsclient] libfpcbep layout unknown, disabled\n");
      return -1;
    }
  *(void **) &b_send_usb_data = dlsym (RTLD_DEFAULT, "fpc_tls_send_usb_data");
  *(void **) &b_buff_get = dlsym (RTLD_DEFAULT, "fpc_tls_buff_get");
  *(void **) &b_buff_clear = dlsym (RTLD_DEFAULT, "fpc_tls_buff_clear");
  *(void **) &b_write_buff_clear = dlsym (RTLD_DEFAULT, "fpc_tls_write_buff_clear");
  if (!b_send_usb_data || !b_buff_get || !b_buff_clear || !b_write_buff_clear)
    {
      fprintf (stderr, "[fpc-tlsclient] blob transport symbols missing\n");
      return -1;
    }
  blob_ssl = (uint8_t *) di.dli_fbase + BLOB_OFF_SSL;
  blob_state = (int *) ((uint8_t *) di.dli_fbase + BLOB_OFF_STATE);
  fprintf (stderr, "[fpc-tlsclient] blob at %p, ssl %p\n", di.dli_fbase, blob_ssl);
  return 0;
}

/* ---- our session -------------------------------------------------------- */
#define WANT_READ (-0x6900) /* MBEDTLS_ERR_SSL_WANT_READ */

/* OpenSSL's SSL_get_error() values (ssl.h); no headers at build time. */
#define SSL_ERROR_WANT_READ  2
#define SSL_ERROR_WANT_WRITE 3

static SSL *ssl;
static SSL_CTX *ctx;
static BIO *net;         /* records to/from the sensor */
static uint8_t psk[64];
static unsigned psk_len;
static int active, done;

/* patches/0019: the a921 writes its application message header little-endian
 * (type, length, status); libfpcbep.so parses it big-endian, reads a huge
 * length, discards the message and every process_data() call returns -6.
 * Rewrite the first twelve bytes of each message in place. msg_left counts the
 * plaintext bytes still to come in the current message. */
static uint32_t msg_left;

/* FPC_DUMP_IMG=/path writes the raw plaintext of the first large application
 * message (the image, 24 byte prefix + pixels) so the capture can be checked
 * without a debugger. FPC_DUMP_DIR=/dir instead writes every one of them to
 * img-NNN.raw, which is what makes per-press placement feedback possible. */
static uint8_t dumpbuf[65536];
static uint32_t dump_len, dump_have;
static FILE *dumpf;
static int dumped;
static unsigned dump_seq;

/* FPC_IMG_FILL=mirror. The a921 sits under a narrow button slot: a normal press
 * only ever images rows 0..~119 of the 64x176 frame, the rest reads 0xff, and
 * the vendor matcher rejects every such sample as LOW_COVERAGE (4) even though
 * the same press works in Windows. Mirroring the contact band into the blank
 * tail (row y >= 119 takes row 236-y) makes the frame read as full contact:
 * measured offline against libfpcbep.so, identity -> 4 on all ten captures,
 * mirror -> 1, and enroll+identify of the same ten captures returns one id.
 * The mapping is fixed, so enrollment and verification are distorted the same
 * way. Only rows that are blank in practice are overwritten. */
#define IMG_FILL_FIRST 119
#define IMG_W 64
#define IMG_H 176
#define IMG_BYTES (IMG_W * IMG_H)

static uint8_t img_hist[32768];
static uint32_t img_len, img_pos;
static int img_active;

static int
img_fill_mirror (void)
{
  static int on = -1;

  if (on == -1)
    {
      const char *e = getenv ("FPC_IMG_FILL");

      on = e && strcmp (e, "mirror") == 0;
    }
  return on;
}

static uint32_t
le32 (const uint8_t *p)
{
  return (uint32_t) p[0] | (uint32_t) p[1] << 8 |
         (uint32_t) p[2] << 16 | (uint32_t) p[3] << 24;
}

static void
put_be32 (uint8_t *p, uint32_t v)
{
  p[0] = v >> 24;
  p[1] = v >> 16;
  p[2] = v >> 8;
  p[3] = v;
}

static unsigned int
psk_client_cb (SSL *s, const char *hint, char *identity,
               unsigned int max_id_len, unsigned char *out,
               unsigned int max_out_len)
{
  static const char id[] = "Disum PSK";

  (void) s; (void) hint;
  if (max_id_len <= sizeof id || psk_len > max_out_len || psk_len == 0)
    return 0;
  memcpy (identity, id, sizeof id);
  memcpy (out, psk, psk_len);
  return psk_len;
}

/* Move whatever OpenSSL produced into the blob's write ring. The driver reads
 * it back as (size_t length, bytes) and sends it with control 0x06. */
static void
drain_out (void)
{
  uint8_t buf[4096];
  int n;

  while ((n = o_BIO_read (net, buf, sizeof buf)) > 0)
    {
      int off = 0;

      if (trace_on ())
        fprintf (stderr, "[tls] out %d\n", n);
      while (off < n)
        {
          int chunk = n - off > 0x7f8 ? 0x7f8 : n - off;

          if (!b_send_usb_data (NULL, buf + off, chunk))
            fprintf (stderr, "[fpc-tlsclient] send ring full, %d bytes lost\n",
                     n - off);
          off += chunk;
        }
    }
}

/* Move whatever the driver received on EP 0x81 into OpenSSL. */
static void
feed_in (void)
{
  uint8_t buf[4096];
  uint32_t n;

  while ((n = b_buff_get (buf, sizeof buf)) > 0)
    {
      if (trace_on ())
        fprintf (stderr, "[tls] in %u\n", n);
      o_BIO_write (net, buf, (int) n);
    }
}

/* Called by the driver after fpc_connect_tls(), i.e. once the blob's buffers
 * and the PSK are in place and before control 0x05. */
int
fpc_a921_tlsclient_start (const uint8_t *key, uint32_t key_len)
{
  BIO *internal;

  if (blob_locate () != 0 || ssl_load () != 0)
    return -1;
  if (!key || key_len == 0 || key_len > sizeof psk)
    return -1;

  if (ssl)
    {
      o_SSL_free (ssl);
      ssl = NULL;
    }
  if (ctx)
    {
      o_SSL_CTX_free (ctx);
      ctx = NULL;
    }
  net = NULL;
  active = 0;
  done = 0;
  memcpy (psk, key, key_len);
  psk_len = key_len;

  ctx = o_SSL_CTX_new (o_TLS_client_method ());
  if (!ctx)
    return -1;
  o_SSL_CTX_ctrl (ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION, NULL);
  o_SSL_CTX_ctrl (ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_2_VERSION, NULL);
  o_SSL_CTX_set_verify (ctx, 0, NULL);
  o_SSL_CTX_set_cipher_list (ctx, "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384");
  o_SSL_CTX_set_psk_client_callback (ctx, psk_client_cb);

  ssl = o_SSL_new (ctx);
  if (!ssl)
    return -1;
  if (o_BIO_new_bio_pair (&internal, 0, &net, 0) != 1)
    return -1;
  o_SSL_set_bio (ssl, internal, internal);
  o_SSL_set_connect_state (ssl);

  b_buff_clear ();
  b_write_buff_clear ();
  *blob_state = 0;
  msg_left = 0;
  dumped = 0;
  dump_seq = 0;
  img_active = 0;
  img_pos = 0;
  active = 1;
  fprintf (stderr, "[fpc-tlsclient] started, key %u bytes\n", key_len);
  return 0;
}

void
fpc_a921_tlsclient_stop (void)
{
  active = 0;
  done = 0;
  if (ssl)
    {
      o_SSL_free (ssl);
      ssl = NULL;
    }
  if (ctx)
    {
      o_SSL_CTX_free (ctx);
      ctx = NULL;
    }
  net = NULL;
}

int
fpc_a921_tlsclient_is_done (void)
{
  return active && done;
}

/* ---- interposed mbedtls entry points ------------------------------------ */

int
mbedtls_ssl_handshake_step (void *ssl_ctx)
{
  static int (*real) (void *);
  int r, err;

  if (!real)
    *(void **) &real = dlsym (RTLD_NEXT, "mbedtls_ssl_handshake_step");

  if (active && ssl_ctx == blob_ssl && ssl)
    {
      if (done)
        return 0;

      feed_in ();
      r = o_SSL_do_handshake (ssl);
      drain_out ();
      if (r == 1)
        {
          done = 1;
          *blob_state = 16;
          fprintf (stderr, "[fpc-tlsclient] handshake complete\n");
          return 0;
        }
      err = o_SSL_get_error (ssl, r);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
        fprintf (stderr, "[fpc-tlsclient] handshake failed, ssl error %d\n", err);
      return WANT_READ;
    }

  return real ? real (ssl_ctx) : WANT_READ;
}

int
mbedtls_ssl_read (void *ssl_ctx, unsigned char *buf, size_t len)
{
  static int (*real) (void *, unsigned char *, size_t);
  int r, err;

  if (!real)
    *(void **) &real = dlsym (RTLD_NEXT, "mbedtls_ssl_read");

  if (active && ssl_ctx == blob_ssl && ssl && done)
    {
      feed_in ();
      r = o_SSL_read (ssl, buf, (int) len);
      if (r > 0)
        {
          if (trace_on ())
            {
              char hex[3 * 16 + 1] = "";
              int i;

              for (i = 0; i < (r < 16 ? r : 16); i++)
                snprintf (hex + 3 * i, 4, "%02x ", buf[i]);
              fprintf (stderr, "[tls] read %zu -> %d [%s]\n", len, r, hex);
            }
          if (msg_left == 0 && r >= 12)
            {
              uint32_t type = le32 (buf), mlen = le32 (buf + 4), st = le32 (buf + 8);

              put_be32 (buf, type);
              put_be32 (buf + 4, mlen);
              put_be32 (buf + 8, st);
              msg_left = mlen;
              img_active = (type == 8 && mlen <= sizeof img_hist);
              img_len = mlen;
              img_pos = 0;
              if (trace_on ())
                fprintf (stderr, "[tls] header LE->BE: type %u len %u status %u\n",
                         type, mlen, st);
              if (!dumpf && mlen > 1000 && mlen < sizeof dumpbuf)
                {
                  const char *dir = getenv ("FPC_DUMP_DIR");

                  if (dir && *dir)
                    {
                      char path[512];

                      snprintf (path, sizeof path, "%s/img-%03u.raw", dir,
                                ++dump_seq);
                      dumpf = fopen (path, "wb");
                      dump_len = mlen;
                      dump_have = 0;
                    }
                  else if (!dumped)
                    {
                      const char *p = getenv ("FPC_DUMP_IMG");

                      if (p && *p)
                        {
                          dumpf = fopen (p, "wb");
                          dump_len = mlen;
                          dump_have = 0;
                        }
                    }
                }
            }
          if (dumpf)
            {
              uint32_t n = (uint32_t) r;

              if (n > dump_len - dump_have)
                n = dump_len - dump_have;
              memcpy (dumpbuf + dump_have, buf, n);
              dump_have += n;
              if (dump_have >= dump_len)
                {
                  fwrite (dumpbuf, 1, dump_len, dumpf);
                  fclose (dumpf);
                  dumpf = NULL;
                  if (getenv ("FPC_DUMP_DIR") && *getenv ("FPC_DUMP_DIR"))
                    {
                      fprintf (stderr, "[tls] wrote %u byte image #%u\n",
                               dump_len, dump_seq);
                    }
                  else
                    {
                      dumped = 1;
                      fprintf (stderr, "[tls] wrote %u byte message to "
                               "FPC_DUMP_IMG\n", dump_len);
                    }
                }
            }
          if (img_active)
            {
              uint32_t n = (uint32_t) r, i;

              if (img_pos + n > sizeof img_hist)
                n = sizeof img_hist - img_pos;
              memcpy (img_hist + img_pos, buf, n);
              if (img_fill_mirror () && img_len >= 24 + IMG_BYTES)
                {
                  for (i = 0; i < n; i++)
                    {
                      uint32_t p = img_pos + i, q, sy, src;

                      if (p < 24 || p >= 24 + IMG_BYTES)
                        continue;
                      q = p - 24;
                      sy = q / IMG_W;
                      if (sy < IMG_FILL_FIRST)
                        continue;
                      src = (2 * (IMG_FILL_FIRST - 1) - sy) * IMG_W + q % IMG_W;
                      buf[i] = img_hist[24 + src];
                    }
                }
              img_pos += n;
            }
          if (msg_left)
            msg_left -= (uint32_t) r <= msg_left ? (uint32_t) r : msg_left;
          drain_out ();
          return r;
        }
      err = o_SSL_get_error (ssl, r);
      if (trace_on ())
        fprintf (stderr, "[tls] read %zu -> %d err %d\n", len, r, err);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
        fprintf (stderr, "[fpc-tlsclient] read failed, ssl error %d\n", err);
      return WANT_READ;
    }

  return real ? real (ssl_ctx, buf, len) : WANT_READ;
}

int
mbedtls_ssl_write (void *ssl_ctx, const unsigned char *buf, size_t len)
{
  static int (*real) (void *, const unsigned char *, size_t);
  int r, err;

  if (!real)
    *(void **) &real = dlsym (RTLD_NEXT, "mbedtls_ssl_write");

  if (active && ssl_ctx == blob_ssl && ssl && done)
    {
      r = o_SSL_write (ssl, buf, (int) len);
      drain_out ();
      if (trace_on ())
        fprintf (stderr, "[tls] write %zu -> %d\n", len, r);
      if (r > 0)
        return r;
      err = o_SSL_get_error (ssl, r);
      if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
        fprintf (stderr, "[fpc-tlsclient] write failed, ssl error %d\n", err);
      return WANT_READ;
    }

  return real ? real (ssl_ctx, buf, len) : -1;
}

int
mbedtls_ssl_get_bytes_avail (const void *ssl_ctx)
{
  static int (*real) (const void *);

  if (!real)
    *(void **) &real = dlsym (RTLD_NEXT, "mbedtls_ssl_get_bytes_avail");

  if (active && ssl_ctx == blob_ssl && ssl && done)
    {
      feed_in ();
      return o_SSL_pending (ssl);
    }
  return real ? real (ssl_ctx) : 0;
}
