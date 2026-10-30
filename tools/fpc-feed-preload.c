/* LD_PRELOAD helper for the offline matcher harness: replaces the blob's
 * mbedtls_ssl_read with a plaintext feed, so application messages can be handed
 * to fpc_enclave_process_data() without a TLS session. */
#include <stdint.h>
#include <string.h>
#include <stddef.h>

static const uint8_t *feed_ptr;
static size_t feed_len, feed_off;

void
feed_set (const void *p, size_t n)
{
  feed_ptr = p;
  feed_len = n;
  feed_off = 0;
}

size_t
feed_left (void)
{
  return feed_ptr ? feed_len - feed_off : 0;
}

long
mbedtls_ssl_read (void *ssl, unsigned char *buf, size_t len)
{
  size_t n;

  if (!feed_ptr || feed_off >= feed_len)
    return -0x6900; /* MBEDTLS_ERR_SSL_WANT_READ */

  n = feed_len - feed_off;
  if (n > len)
    n = len;
  memcpy (buf, feed_ptr + feed_off, n);
  feed_off += n;
  return (long) n;
}

size_t
mbedtls_ssl_get_bytes_avail (const void *ssl)
{
  return feed_ptr ? feed_len - feed_off : 0;
}

int
mbedtls_ssl_handshake_step (void *ssl)
{
  return 0; /* pretend the handshake is over */
}
