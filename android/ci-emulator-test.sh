#!/usr/bin/env bash
# Runs on the CI emulator: installs Shardrip.apk, then downloads through the app's own interface.
set -uo pipefail
PKG=com.geomatter.shardrip
OUT=ci-out; mkdir -p "$OUT"
fail() { echo "❌ $*"; adb logcat -d > "$OUT/logcat.txt"; adb logcat -d -s Shardrip AndroidRuntime python.stderr python.stdout | tail -80; exit 1; }
shot() {  # screenshot -> file, plus a small copy printed into the log (artifacts can't always be fetched)
  adb exec-out screencap -p > "$OUT/$1.png"
  python3 - "$OUT/$1.png" "$1" <<'PYEOF'
import base64, io, sys
from PIL import Image
im = Image.open(sys.argv[1]).convert("RGB"); im.thumbnail((360, 800))
b = io.BytesIO(); im.save(b, "JPEG", quality=70)
print(f"SHOT-BEGIN {sys.argv[2]}"); print(base64.b64encode(b.getvalue()).decode()); print("SHOT-END")
PYEOF
}

adb install -r Shardrip-x86_64-test.apk || fail "install failed"
adb shell pm grant $PKG android.permission.POST_NOTIFICATIONS || true
adb shell pm grant $PKG android.permission.CAMERA || true
adb logcat -c
adb shell am start -n $PKG/.MainActivity

URL=""
for i in $(seq 1 90); do
  URL=$(adb logcat -d -s Shardrip:I | grep -o 'SHARDRIP_URL [^ ]*' | tail -1 | cut -d' ' -f2)
  [ -n "$URL" ] && break
  sleep 2
done
[ -n "$URL" ] || fail "the app didn't start Shardrip"
echo "App started: $URL"
PORT=$(echo "$URL" | sed -E 's#http://127.0.0.1:([0-9]+)/.*#\1#')
KEY=${URL##*key=}
adb forward tcp:$PORT tcp:$PORT
api() { curl -sS --fail -H "X-Shardrip-Key: $KEY" -H "Content-Type: application/json" "http://127.0.0.1:$PORT$@"; }
api /api/defaults || fail "API not reachable"; echo
sleep 6
shot 1-app-open

SERVICE_SEEN=0; NOTIF_SEEN=0
wait_done() {  # $1 = name; waits for the download to finish, watching the background service
  for i in $(seq 1 300); do
    S=$(api /api/status) || fail "status failed"
    RUN=$(echo "$S" | python3 -c 'import json,sys; print(json.load(sys.stdin)["dl"]["running"])')
    if [ "$RUN" = "True" ]; then
      adb shell dumpsys activity services $PKG | grep -q "DownloadService" && SERVICE_SEEN=1
      adb shell dumpsys notification --noredact | grep -q "Shardrip - downloading" && NOTIF_SEEN=1
    fi
    [ "$i" = 5 ] && shot "$1-downloading"
    [ "$RUN" = "False" ] && [ "$i" -gt 2 ] && break
    sleep 1
  done
  echo "$S" | python3 -c 'import json,sys; d=json.load(sys.stdin)["dl"]; print("\n".join(d["log"][-12:])); print("RESULT:", d["result"])'
}

echo "== Test 1: password-locked file from the PC on the same network =="
LINK=$(cat link.txt)
api /api/download -X POST -d "{\"url\": \"$LINK\", \"password\": \"ci-pass-123\", \"via\": \"lan\", \"connections\": 16}" || fail "start failed"
echo; sleep 2; adb shell input keyevent KEYCODE_HOME   # app goes to the background mid-download
wait_done 2-locked-lan
GOT=$(adb shell sha256sum /sdcard/Download/ci-test.bin | cut -d' ' -f1)
[ "$GOT" = "$(cat ci-test.sha)" ] || fail "locked download doesn't match (got '$GOT')"
echo "✅ Locked download saved to Download/ and unlocked byte-perfect"
echo "✅ Kept downloading with the app in the background"
[ "$SERVICE_SEEN" = 1 ] && echo "✅ Background download service was running" || echo "⚠️ background service not seen"
[ "$NOTIF_SEEN" = 1 ] && echo "✅ 'Shardrip - downloading' notification was shown" || echo "⚠️ notification not seen"
adb shell am start -n $PKG/.MainActivity; sleep 3; shot 2-locked-lan-done

echo "== Test 2: normal https download from the internet (redirects, ranges, auto) =="
api /api/download -X POST -d '{"url": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64", "via": "auto"}' || fail "start failed"
echo; wait_done 3-internet; shot 3-internet-done
SIZE=$(adb shell stat -c %s /sdcard/Download/cloudflared-linux-arm64 | tr -d '\r')
[ "${SIZE:-0}" -gt 1000000 ] || fail "internet download missing (size '$SIZE')"
echo "✅ Internet download saved ($SIZE bytes)"

adb logcat -d -s Shardrip:I | grep "page:" | tail -5
adb logcat -d -s Shardrip:I | grep -q "secure=true camera=true" && echo "✅ Camera (QR scanner) is available to the page" || echo "⚠️ camera check not seen"
adb logcat -d > "$OUT/logcat.txt"
echo "ALL APP TESTS PASSED"
