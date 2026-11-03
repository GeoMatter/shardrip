#!/usr/bin/env bash
# Runs on the CI emulator: installs Shardrip.apk, then downloads through the app's own interface.
set -uo pipefail
PKG=com.geomatter.shardrip
OUT=ci-out; mkdir -p "$OUT"
fail() { echo "❌ $*"; adb logcat -d > "$OUT/logcat.txt"; exit 1; }

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
adb exec-out screencap -p > "$OUT/1-app-open.png"

wait_done() {  # $1 = name; waits for the download to finish, takes screenshots on the way
  for i in $(seq 1 240); do
    S=$(api /api/status) || fail "status failed"
    RUN=$(echo "$S" | python3 -c 'import json,sys; print(json.load(sys.stdin)["dl"]["running"])')
    if [ "$i" = 4 ]; then
      adb exec-out screencap -p > "$OUT/$1-downloading.png"
      adb shell dumpsys notification --noredact | grep -i -A3 "shardrip - downloading" > "$OUT/$1-notification.txt" || true
    fi
    [ "$RUN" = "False" ] && [ "$i" -gt 2 ] && break
    sleep 1
  done
  echo "$S" | python3 -c 'import json,sys; d=json.load(sys.stdin)["dl"]; print("\n".join(d["log"][-12:])); print("RESULT:", d["result"])'
  adb exec-out screencap -p > "$OUT/$1-done.png"
}

echo "== Test 1: password-locked file from the PC on the same network =="
LINK=$(cat link.txt)
api /api/download -X POST -d "{\"url\": \"$LINK\", \"password\": \"ci-pass-123\", \"via\": \"lan\", \"connections\": 16}" || fail "start failed"
echo; wait_done 2-locked-lan
GOT=$(adb shell sha256sum /sdcard/Download/ci-test.bin | cut -d' ' -f1)
[ "$GOT" = "$(cat ci-test.sha)" ] || fail "locked download doesn't match (got '$GOT')"
echo "✅ Locked download saved to Download/ and unlocked byte-perfect"
[ -s "$OUT/2-locked-lan-notification.txt" ] && echo "✅ 'Downloading' notification was shown" || echo "⚠️ notification not captured"

echo "== Test 2: normal https download from the internet (redirects, ranges, auto) =="
api /api/download -X POST -d '{"url": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64", "via": "auto"}' || fail "start failed"
echo; wait_done 3-internet
SIZE=$(adb shell stat -c %s /sdcard/Download/cloudflared-linux-arm64 | tr -d '\r')
[ "${SIZE:-0}" -gt 1000000 ] || fail "internet download missing (size '$SIZE')"
echo "✅ Internet download saved ($SIZE bytes)"

adb logcat -d -s Shardrip:I | grep "page:" | tail -5
adb logcat -d -s Shardrip:I | grep -q "secure=true camera=true" && echo "✅ Camera (QR scanner) is available to the page" || echo "⚠️ camera check not seen"
adb logcat -d > "$OUT/logcat.txt"
echo "ALL APP TESTS PASSED"
