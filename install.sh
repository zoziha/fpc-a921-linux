#!/bin/bash
# Install the FPC 10a5:a921 fingerprint driver system-wide.
#
# Installs a libfprint built FROM SOURCE (v1.94.6 + merge request 396, which
# adds the fpcmoh match-on-host driver, + the patches in patches/) into a
# PRIVATE directory, and points ONLY the fprintd daemon at it via
# LD_LIBRARY_PATH. Nothing under /usr/lib is modified, moved or overwritten.
#
# Build the artifact first with ./build.sh, then: sudo ./install.sh

set -euo pipefail

PREFIX=/opt/fpc-a921/lib
SRC="$(cd "$(dirname "$0")" && pwd)"
LIB="$SRC/dist/libfprint-2.so.2.0.0"
SHIM="$SRC/dist/libfpc_tlsclient.so"
BLOB="${FPCBEP:-$SRC/blob/libfpcbep.so}"
UDEV=/etc/udev/rules.d/60-libfprint-2-device-fpc-a921.rules
DROPIN_DIR=/etc/systemd/system/fprintd.service.d
DROPIN="$DROPIN_DIR/10-fpc-a921.conf"

[ "$(id -u)" -eq 0 ] || { echo "must run as root (sudo ./install.sh)" >&2; exit 1; }

for f in "$LIB" "$SHIM" "$BLOB"; do
  [ -f "$f" ] || { echo "missing: $f" >&2
                   echo "  (run ./get-blob.sh then ./build.sh first)" >&2
                   exit 1; }
done

# ---------------------------------------------------------------------------
# Pre-install guard.
#
# The old guard checked fixed byte offsets. Those are meaningless for a
# compiled artifact -- offsets move on every build. Check instead the two
# properties that actually have to hold, straight out of the ELF:
#
#   1. the fpcmoh driver is present at all;
#   2. its id_table contains an entry for 10a5:a921.
#
# FpIdEntry is { guint32 pid; guint32 vid; ... } -- pid FIRST -- so an a921
# entry is the 8 little-endian bytes 00 a9 00 00 a5 10 00 00. (Field order
# verified against DWARF for 1.94.x; see FINDINGS.md section 4.)
# ---------------------------------------------------------------------------
echo "==> verifying $LIB"

# NB: use awk, not grep. grep on this system is ugrep, which classifies
# `strings` output of a binary as binary and silently matches nothing. That
# gotcha has already produced one false finding in this project.
if [ "$(strings -a "$LIB" | awk '$0 == "FPC MOH Fingerprint Sensor" {c++} END {print c+0}')" -eq 0 ]; then
  echo "ERROR: $LIB does not contain the fpcmoh driver." >&2
  echo "       Was it built with -Ddrivers=fpcmoh ?" >&2
  exit 1
fi

python3 - "$LIB" <<'PYEOF' || exit 1
import sys
data = open(sys.argv[1], 'rb').read()
entry = bytes.fromhex('21a90000a5100000')   # pid=0xa921, vid=0x10a5, LE
if data.count(entry) < 1:
    sys.stderr.write("ERROR: no 10a5:a921 entry found in any id_table.\n"
                     "       The a921 support patch is not applied to this build.\n")
    sys.exit(1)
print("    fpcmoh driver present, 10a5:a921 in id_table -- OK")
PYEOF

# MR396's driver links the proprietary blob directly (DT_NEEDED), unlike
# furcom's prebuilt library which dlopen()s it by bare name. LD_LIBRARY_PATH
# covers both, but say which one this is so a load failure is diagnosable.
if [ "$(objdump -p "$LIB" | awk '/NEEDED/ && /libfpcbep\.so/ {c++} END {print c+0}')" -gt 0 ]; then
  echo "    libfpcbep.so is a DT_NEEDED entry -- OK"
else
  echo "    note: libfpcbep.so not in DT_NEEDED (dlopen-style build) -- continuing"
fi

echo "==> installing libfprint + FPC blob to $PREFIX"
install -d -m 0755 "$PREFIX"
install -m 0644 "$LIB"  "$PREFIX/libfprint-2.so.2.0.0"
install -m 0644 "$BLOB" "$PREFIX/libfpcbep.so"
install -m 0644 "$SHIM" "$PREFIX/libfpc_tlsclient.so"
ln -sf libfprint-2.so.2.0.0 "$PREFIX/libfprint-2.so.2"

# The fpcmoh driver / FPC blob expect this to exist and be writable.
echo "==> creating /var/log/fpc"
install -d -m 0755 /var/log/fpc

echo "==> installing udev rule -> $UDEV"
cat > "$UDEV" <<'EOF'
# FPC 10a5:a921 (Honor MagicBook) - handled by the fpcmoh driver in the
# libfprint built from source into /opt/fpc-a921/lib.
SUBSYSTEM=="usb", ATTRS{idVendor}=="10a5", ATTRS{idProduct}=="a921", ATTRS{dev}=="*", TEST=="power/control", ATTR{power/control}="auto"
SUBSYSTEM=="usb", ATTRS{idVendor}=="10a5", ATTRS{idProduct}=="a921", ENV{LIBFPRINT_DRIVER}="FPC MOH Fingerprint Sensor"
EOF

echo "==> installing systemd drop-in -> $DROPIN"
install -d -m 0755 "$DROPIN_DIR"
cat > "$DROPIN" <<EOF
[Service]
# Load our libfprint (and its libfpcbep.so) from $PREFIX.
# Only fprintd is affected; the rest of the system keeps the distro libfprint.
Environment=LD_LIBRARY_PATH=$PREFIX
# patches/0016: the FPC blob's mbedtls is server-only and the a921 is a TLS
# server as well, so the client half of the handshake comes from this shim.
Environment=LD_PRELOAD=$PREFIX/libfpc_tlsclient.so
# An a921 button press images only rows 0..~119 of the 64x176 frame and leaves
# the rest 0xff, which the vendor matcher scores LOW_COVERAGE (4) on every
# sample -- the same press enrolls fine in Windows. The shim mirrors the
# contact band into the blank tail; without this, enrollment never completes.
Environment=FPC_IMG_FILL=mirror
# fprintd.service sets ProtectSystem=strict, so /var/log/fpc is read-only
# without this. The FPC blob expects to be able to write there.
ReadWritePaths=/var/log/fpc
EOF

# Bring-up leftovers: a world-writable udev rule and a debug drop-in were
# needed while the sensor was being probed without fprintd. fprintd runs as
# root and needs neither, so drop them if they are still present.
for f in /etc/udev/rules.d/99-fpc-a921-probe.rules "$DROPIN_DIR/20-debug.conf"; do
  if [ -e "$f" ]; then
    echo "==> removing bring-up leftover $f"
    rm -f "$f"
  fi
done

echo "==> reloading udev + systemd"
udevadm control --reload-rules
udevadm trigger --subsystem-match=usb
systemctl daemon-reload
systemctl restart fprintd 2>/dev/null || true

echo
echo "FINISHED. Verify the right library is actually loaded:"
echo "  fprintd-enroll \$USER & sleep 2; sudo grep -E 'fpc-a921|libfpcbep' /proc/\$(pidof fprintd)/maps"
echo "  systemctl show fprintd -p Environment | tr ' ' '\\n' | grep IMG_FILL"
echo
echo "Then enroll (in a DESKTOP terminal -- needs a polkit agent):"
echo "  fprintd-enroll \$USER"
echo "To remove:    sudo ./uninstall.sh"
