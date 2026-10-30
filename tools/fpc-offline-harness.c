/* Offline matcher harness: feeds captured images straight into libfpcbep.so via
 * the plaintext feed preload, bypassing USB and TLS. Used to compare image
 * transforms (rotation/flip/polarity) against the vendor enrollment verdicts.
 *
 * Build:
 *   cc -O2 -o tools/fpc-offline-harness tools/fpc-offline-harness.c -ldl
 *   cc -shared -fPIC -O2 -o tools/libfpc-feed-preload.so tools/fpc-feed-preload.c
 *
 * Run (frames are FPC_DUMP_DIR/img-NNN.raw, 11288 bytes each):
 *   FPCBEP_BLOB=$PWD/blob/libfpcbep.so \
 *   LD_PRELOAD=$PWD/tools/libfpc-feed-preload.so \
 *     tools/fpc-offline-harness flow frames
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct fpc_enclave fpc_enclave_t;
typedef struct fpc_tee fpc_tee_t;
typedef struct fpc_tee_bio fpc_tee_bio_t;

static fpc_enclave_t *(*p_create_enclave) (void);
static int32_t (*p_start_enclave) (fpc_enclave_t *);
static int32_t (*p_enclave_init) (fpc_enclave_t *, uint16_t);
static int32_t (*p_process_data) (fpc_enclave_t *);
static fpc_tee_t *(*p_tee_init) (void);
static fpc_tee_bio_t *(*p_bio_init) (fpc_tee_t *);
static void (*p_bio_release) (fpc_tee_bio_t *);
static int (*p_begin_enroll) (fpc_tee_bio_t *);
static int (*p_enroll) (fpc_tee_bio_t *, uint32_t *);
static int (*p_end_enroll) (fpc_tee_bio_t *, uint32_t *);
static int (*p_identify) (fpc_tee_bio_t *, uint32_t *);
static int (*p_load_empty_db) (fpc_tee_bio_t *);

static void (*p_feed_set) (const void *, size_t);
static size_t (*p_feed_left) (void);

#define IMG_W 64
#define IMG_H 176
#define PIXELS (IMG_W * IMG_H)
#define PREFIX 34
#define MSG_LEN (PREFIX + PIXELS)

static int
load_blob (void)
{
  const char *path = getenv ("FPCBEP_BLOB");
  Dl_info di;

  if (!path || !*path)
    path = "blob/libfpcbep.so";
  void *h = dlopen (path, RTLD_NOW | RTLD_GLOBAL);

  if (!h)
    {
      fprintf (stderr, "dlopen blob: %s\n", dlerror ());
      return -1;
    }
#define S(v, n) do { *(void **) &v = dlsym (h, n); if (!v) { fprintf (stderr, "missing %s\n", n); return -1; } } while (0)
  S (p_create_enclave, "fpc_create_enclave");
  S (p_start_enclave, "fpc_start_enclave");
  S (p_enclave_init, "fpc_enclave_init");
  S (p_process_data, "fpc_enclave_process_data");
  S (p_tee_init, "fpc_tee_init");
  S (p_bio_init, "fpc_tee_bio_init");
  S (p_bio_release, "fpc_tee_bio_release");
  S (p_begin_enroll, "fpc_tee_begin_enroll");
  S (p_enroll, "fpc_tee_enroll");
  S (p_end_enroll, "fpc_tee_end_enroll");
  S (p_identify, "fpc_tee_identify");
  S (p_load_empty_db, "fpc_tee_load_empty_db");
#undef S
  if (!dladdr (p_enclave_init, &di) || !di.dli_fbase)
    return -1;
  fprintf (stderr, "blob at %p\n", di.dli_fbase);
  return 0;
}

static int
load_feed (void)
{
  p_feed_set = (void (*) (const void *, size_t)) dlsym (RTLD_DEFAULT, "feed_set");
  p_feed_left = (size_t (*) (void)) dlsym (RTLD_DEFAULT, "feed_left");
  if (!p_feed_set || !p_feed_left)
    {
      fprintf (stderr, "feed symbols missing (LD_PRELOAD=tools/libfpc-feed-preload.so)\n");
      return -1;
    }
  return 0;
}

static void
put_be32 (uint8_t *p, uint32_t v)
{
  p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

/* Feed one image message (34 byte prefix + pixels) and run the enroll step. */
static int
try_sample (fpc_enclave_t *enc, fpc_tee_bio_t *bio,
            const uint8_t *pixels, const uint8_t *capture_prefix,
            const char *label)
{
  uint8_t msg[MSG_LEN];
  uint32_t remaining = 0;
  int rc, calls = 0, result;

  memset (msg, 0, sizeof msg);
  msg[0] = 0; msg[1] = 0; msg[2] = 0; msg[3] = 8;
  put_be32 (msg + 4, MSG_LEN);
  /* metadata read by the blob at 0x0c..0x15 comes from the capture */
  memcpy (msg + 12, capture_prefix + 12, 10);
  memcpy (msg + PREFIX, pixels, PIXELS);

  p_feed_set (msg, sizeof msg);
  do
    {
      rc = p_process_data (enc);
      calls++;
    }
  while (rc == 0 && p_feed_left () > 0 && calls < 32);

  remaining = 0;
  result = p_enroll (bio, &remaining);
  printf ("%-26s process_data %d calls, last rc %d -> enroll %d, remaining %u\n",
          label, calls, rc, result, remaining);
  return result;
}

static void
transform (const uint8_t *in, uint8_t *out, int kind)
{
  int x, y;

  for (y = 0; y < IMG_H; y++)
    for (x = 0; x < IMG_W; x++)
      {
        uint8_t v;
        switch (kind)
          {
          case 1: v = in[x * IMG_W + y]; break;                 /* bad index, kept for contrast */
          case 2: v = in[(IMG_H - 1 - y) * IMG_W + (IMG_W - 1 - x)]; break; /* rot180 */
          case 3: v = in[(IMG_H - 1 - y) * IMG_W + x]; break;   /* flip vertical */
          case 4: v = in[y * IMG_W + (IMG_W - 1 - x)]; break;   /* flip horizontal */
          case 5: v = 255 - in[y * IMG_W + x]; break;           /* invert */
          case 6: v = in[x * IMG_H + y]; break;                 /* column-major -> row-major */
          case 7: v = in[y * IMG_W + x]; break;                 /* row-major -> column-major (same source) */
          case 8: v = (uint8_t) (rand () & 0xff); break;        /* noise */
          case 9: v = 128; break;
          case 10: v = 0; break;
          case 11: v = 255; break;
          default: v = in[y * IMG_W + x]; break;
          }
        out[y * IMG_W + x] = v;
      }

  if (kind == 7)
    {
      /* proper inverse permutation: out[x * IMG_H + y] = in[y * IMG_W + x] */
      uint8_t tmp[PIXELS];

      memcpy (tmp, out, PIXELS);
      for (y = 0; y < IMG_H; y++)
        for (x = 0; x < IMG_W; x++)
          out[x * IMG_H + y] = in[y * IMG_W + x];
    }

  if (kind == 12)
    {
      /* coverage test: keep rows 0..118, mirror row 118 into the blank tail */
      for (y = 119; y < IMG_H; y++)
        memcpy (out + y * IMG_W, in + 118 * IMG_W, IMG_W);
    }
  if (kind == 15)
    {
      /* mirror the contact band into the blank tail, no scaling */
      for (y = 119; y < IMG_H; y++)
        {
          int sy = 2 * 118 - y;

          if (sy < 0) sy = 0;
          memcpy (out + y * IMG_W, in + sy * IMG_W, IMG_W);
        }
    }

  if (kind == 16)
    {
      /* tile the contact band into the blank tail, no scaling */
      for (y = 119; y < IMG_H; y++)
        {
          int sy = y % 119;

          memcpy (out + y * IMG_W, in + sy * IMG_W, IMG_W);
        }
    }

  if (kind == 13 || kind == 14)
    {
      /* vertical stretch of the contact band (rows 0..hi) onto the whole frame */
      int hi = (kind == 13) ? 118 : 110;

      for (y = 0; y < IMG_H; y++)
        {
          int sy = y * hi / (IMG_H - 1);

          memcpy (out + y * IMG_W, in + sy * IMG_W, IMG_W);
        }
    }
}

static const char *kind_name[] = {
  "identity", "transpose(bad)", "rot180", "flip-vertical", "flip-horizontal",
  "invert", "colmajor->rowmajor", "rowmajor->colmajor", "noise", "const128",
  "const0", "const255", "identity+tail-filled", "stretch(0..118)", "stretch(0..110)",
  "mirror-band", "tile-band"
};


static int
run_flow (fpc_enclave_t *enc, fpc_tee_t *tee, const char *dir)
{
  fpc_tee_bio_t *bio = p_bio_init (tee);
  uint8_t raw[11288], pix[PIXELS], out[PIXELS];
  uint32_t rem = 0, id = 0;
  int i, accepted = 0, result;
  char path[512];
  int flow_kind = 13;
  const char *ke = getenv ("FPC_FLOW_KIND");

  if (ke && *ke)
    flow_kind = atoi (ke);

  if (!bio || p_load_empty_db (bio) != 0 || p_begin_enroll (bio) != 0)
    {
      fprintf (stderr, "bio setup failed\n");
      return 1;
    }

  for (i = 1; i <= 10; i++)
    {
      FILE *f;

      snprintf (path, sizeof path, "%s/img-%03d.raw", dir, i);
      f = fopen (path, "rb");
      if (!f)
        break;
      if (fread (raw, 1, sizeof raw, f) != sizeof raw)
        {
          fclose (f);
          break;
        }
      fclose (f);
      memcpy (pix, raw + 24, PIXELS);
      transform (pix, out, flow_kind);
      result = try_sample (enc, bio, out, raw, path);
      if (result == 1 || result == 0)
        accepted++;
      if (result == 0)
        break;
    }

  result = p_end_enroll (bio, &id);
  printf ("end_enroll -> %d, id %u, accepted %d\n", result, id, accepted);

  if (result == 0)
    {
      snprintf (path, sizeof path, "%s/img-010.raw", dir);
      FILE *f = fopen (path, "rb");

      if (f && fread (raw, 1, sizeof raw, f) == sizeof raw)
        {
          fclose (f);
          memcpy (pix, raw + 24, PIXELS);
          transform (pix, out, flow_kind);
          p_feed_set (NULL, 0);
          (void) 0;
          {
            uint8_t msg[MSG_LEN];
            int rc, calls = 0;

            memset (msg, 0, sizeof msg);
            msg[3] = 8;
            put_be32 (msg + 4, MSG_LEN);
            memcpy (msg + 12, raw + 12, 10);
            memcpy (msg + PREFIX, out, PIXELS);
            p_feed_set (msg, sizeof msg);
            do { rc = p_process_data (enc); calls++; }
            while (rc == 0 && p_feed_left () > 0 && calls < 32);
          }
          id = 0;
          result = p_identify (bio, &id);
          printf ("identify -> %d, id %u, remaining %u\n", result, id, rem);
        }
    }

  return 0;
}

int
main (int argc, char **argv)
{
  fpc_enclave_t *enc;
  fpc_tee_t *tee;
  uint8_t raw[11288], pix[PIXELS], out[PIXELS];
  FILE *f;
  int k;

  srand (1);

  if (load_blob () || load_feed ())
    return 1;

  enc = p_create_enclave ();
  if (!enc || p_start_enclave (enc) != 0 || p_enclave_init (enc, 0x331) != 0)
    {
      fprintf (stderr, "enclave init failed\n");
      return 1;
    }
  fprintf (stderr, "enclave ready\n");

  if (argc < 2)
    {
      fprintf (stderr, "usage: %s image.raw | flow [frames-dir]\n", argv[0]);
      return 1;
    }

  if (strcmp (argv[1], "flow") == 0)
    {
      fpc_tee_t *t;

      {
        Dl_info di;
        dladdr (p_enclave_init, &di);
        *(uint32_t *) ((uint8_t *) di.dli_fbase + 0x196100) = 16;
      }
      t = p_tee_init ();
      return t ? run_flow (enc, t, argc > 2 ? argv[2] : "frames") : 1;
    }
  f = fopen (argv[1], "rb");
  if (!f)
    {
      perror (argv[1]);
      return 1;
    }
  if (fread (raw, 1, sizeof raw, f) != sizeof raw)
    {
      fprintf (stderr, "short read\n");
      return 1;
    }
  fclose (f);
  memcpy (pix, raw + 24, PIXELS);

  /* tls_state must read 16 or process_data refuses to decrypt; there is no
   * TLS here, the feed replaces mbedtls_ssl_read. */
  {
    Dl_info di;
    dladdr (p_enclave_init, &di);
    *(uint32_t *) ((uint8_t *) di.dli_fbase + 0x196100) = 16;
  }

  tee = p_tee_init ();
  if (!tee)
    {
      fprintf (stderr, "tee init failed\n");
      return 1;
    }

  for (k = 0; k < 17; k++)
    {
      fpc_tee_bio_t *bio = p_bio_init (tee);

      if (!bio)
        {
          fprintf (stderr, "bio init failed\n");
          return 1;
        }
      if (p_begin_enroll (bio) != 0)
        {
          fprintf (stderr, "begin_enroll failed\n");
          return 1;
        }
      transform (pix, out, k);
      try_sample (enc, bio, out, raw, kind_name[k]);
      p_bio_release (bio);
    }

  return 0;
}
