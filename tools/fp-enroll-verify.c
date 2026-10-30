/* Enroll then verify through libfprint's own API, without fprintd. Useful when
 * the daemon is in the way (stale claim) or when the enroll/verify verdicts are
 * wanted on stdout.
 *
 * Build (after ./build.sh):
 *   cc -O2 -o tools/fp-enroll-verify tools/fp-enroll-verify.c \
 *      -Ibuild/libfprint-src/libfprint -Ibuild/libfprint-src/builddir/libfprint \
 *      $(pkg-config --cflags --libs glib-2.0 gio-2.0 gusb) \
 *      dist/libfprint-2.so.2.0.0 -Wl,-rpath-link,blob
 *
 * Run (the shim matters: without it the blob cannot start the TLS handshake):
 *   LD_LIBRARY_PATH=$PWD/dist:$PWD/blob \
 *   LD_PRELOAD=$PWD/dist/libfpc_tlsclient.so FPC_IMG_FILL=mirror \
 *     tools/fp-enroll-verify
 */
#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>
#include "fp-context.h"
#include "fp-device.h"
#include "fp-print.h"

static GMainLoop *loop;
static FpDevice *dev;
static FpPrint *print;

static void
on_progress (FpDevice *d, gint stages, FpPrint *p, gpointer data, GError *error)
{
  g_print ("[enroll] stage %d/12%s%s\n", stages,
           error ? " retry: " : "", error ? error->message : "");
  fflush (stdout);
}

static gboolean start_verify (gpointer data);

static void
on_verify_match (FpDevice *d, FpPrint *match, FpPrint *p, gpointer data, GError *error)
{
  g_print ("[verify] match %s%s%s\n", match ? "YES" : "NO",
           error ? " : " : "", error ? error->message : "");
  fflush (stdout);
}

static void
on_verify_done (GObject *src, GAsyncResult *res, gpointer data)
{
  GError *error = NULL;
  gboolean match = FALSE;
  FpPrint *matched = NULL;

  if (!fp_device_verify_finish (FP_DEVICE (src), res, &match, &matched, &error))
    g_print ("VERIFY RESULT: FAILED%s%s\n", error ? " : " : "",
             error ? error->message : "");
  else
    g_print ("VERIFY RESULT: %s\n", match ? "MATCH" : "NO MATCH");
  fflush (stdout);
  g_main_loop_quit (loop);
}

static void
on_enroll_done (GObject *src, GAsyncResult *res, gpointer data)
{
  GError *error = NULL;
  FpPrint *enrolled = fp_device_enroll_finish (FP_DEVICE (src), res, &error);

  g_print ("ENROLL RESULT: %s%s%s\n",
           enrolled ? "SUCCESS" : "FAILED",
           error ? " : " : "", error ? error->message : "");
  fflush (stdout);
  if (!enrolled)
    {
      g_main_loop_quit (loop);
      return;
    }
  print = g_object_ref (enrolled);
  g_timeout_add (800, start_verify, NULL);
}

static gboolean
start_verify (gpointer data)
{
  g_print ("=== VERIFY: PRESS YOUR FINGER ===\n");
  fflush (stdout);
  fp_device_verify (dev, print, NULL, on_verify_match, NULL, NULL,
                    on_verify_done, NULL);
  return G_SOURCE_REMOVE;
}

static gboolean
on_timeout (gpointer data)
{
  g_print ("TIMEOUT\n");
  g_main_loop_quit (loop);
  return G_SOURCE_REMOVE;
}

int
main (void)
{
  FpContext *ctx = fp_context_new ();
  GPtrArray *devs;
  GError *error = NULL;

  loop = g_main_loop_new (NULL, FALSE);
  fp_context_enumerate (ctx);
  g_timeout_add (1500, (GSourceFunc) (void (*) (void)) g_main_loop_quit, loop);
  g_main_loop_run (loop);

  devs = fp_context_get_devices (ctx);
  if (!devs || devs->len == 0)
    return 2;
  dev = g_ptr_array_index (devs, 0);

  if (!fp_device_open_sync (dev, NULL, &error))
    {
      g_print ("OPEN FAILED: %s\n", error->message);
      return 3;
    }
  g_print ("device open\n");

  print = fp_print_new (dev);
  g_print ("=== PRESS AND LIFT YOUR FINGER, REPEATEDLY ===\n");
  fflush (stdout);

  fp_device_enroll (dev, print, NULL, on_progress, NULL, NULL, on_enroll_done, NULL);
  g_timeout_add (240000, on_timeout, NULL);
  g_main_loop_run (loop);
  return 0;
}
