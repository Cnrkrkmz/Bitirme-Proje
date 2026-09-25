#!/usr/bin/env bash
# Uc siniflandirmayi da tek calistirmada dogrular: established / refused / dropped.
#
# Kubernetes gerekmez. "dropped" senaryosu icin gecici bir iptables OUTPUT
# kurali ekleniyor (NetworkPolicy'nin yaptiginin aynisi: paketi sessizce dus),
# cikista her durumda kaldiriliyor.
set -uo pipefail

BIN=${BIN:-./bin/flowmon}
DROP_PORT=${DROP_PORT:-9999}
DROP_DST=${DROP_DST:-192.0.2.10}     # TEST-NET-1, yonlendirilmez
REFUSE_PORT=${REFUSE_PORT:-59321}
OUT=$(mktemp)

[[ -x $BIN ]] || { echo "HATA: $BIN yok - once 'make build'"; exit 1; }
[[ $EUID -eq 0 ]] || { echo "HATA: root gerekiyor (BPF program yukleme)"; exit 1; }

RULE_ADDED=0
PID=""
cleanup() {
	[[ -n $PID ]] && kill -INT "$PID" 2>/dev/null
	[[ $RULE_ADDED -eq 1 ]] && iptables -D OUTPUT -p tcp -d "$DROP_DST" --dport "$DROP_PORT" -j DROP 2>/dev/null
	rm -f "$OUT"
}
trap cleanup EXIT

echo "==> flowmon yukleniyor (BPF verifier)"
$BIN -exclude-loopback=false > "$OUT" 2>/tmp/flowmon.err &
PID=$!
sleep 2
if ! kill -0 "$PID" 2>/dev/null; then
	echo "    BASARISIZ - program yuklenmedi:"
	sed 's/^/    /' /tmp/flowmon.err
	exit 1
fi
echo "    OK"

echo "==> 1/3  established  (example.com:80)"
timeout 10 curl -s -o /dev/null http://example.com/ 2>/dev/null
echo "==> 2/3  refused      (127.0.0.1:$REFUSE_PORT - dinleyen yok)"
timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$REFUSE_PORT" 2>/dev/null
echo "==> 3/3  dropped      ($DROP_DST:$DROP_PORT - iptables DROP)"
iptables -A OUTPUT -p tcp -d "$DROP_DST" --dport "$DROP_PORT" -j DROP && RULE_ADDED=1
timeout 20 bash -c "exec 3<>/dev/tcp/$DROP_DST/$DROP_PORT" 2>/dev/null

sleep 1
kill -INT "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""

echo
echo "==> yakalanan olaylar"
cat "$OUT"
echo
echo "==> sonuc"
fail=0
for want in established refused dropped; do
	printf '  %-14s ' "$want"
	if grep -q "\"class\":\"$want\"" "$OUT"; then echo GECTI; else echo BASARISIZ; fail=1; fi
done
exit $fail
