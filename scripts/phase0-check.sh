#!/usr/bin/env bash
# Faz 0 de-risk kontrolu (Proje Ozeti §15).
#
# Tek bir soruyu yanitlar: secilen makinede kancalar takiliyor ve basarisiz bir
# connect() denemesinden (kaynak, hedef, port) ucluosu cikiyor mu?
#
# Yontem: hicbir seyin dinlemedigi bir porta baglanmayi deniyoruz. Beklenen
# sonuc "refused" — RST donuyor, yani yol acik ama port kapali. NetworkPolicy
# ile dusurulen trafik ayni testte "dropped" olarak gorunecek; ayrimi yapan
# sey retransmit sayaci.
set -euo pipefail

BIN=${BIN:-./bin/flowmon}
PORT=${PORT:-59321}
OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT

[[ -x $BIN ]] || { echo "HATA: $BIN yok — once 'make build' calistirin"; exit 1; }
[[ $EUID -eq 0 ]] || { echo "HATA: root gerekiyor (BPF program yukleme)"; exit 1; }

echo "==> BTF"
[[ -r /sys/kernel/btf/vmlinux ]] && echo "    OK" || { echo "    EKSIK — tp_btf kancalari takilmaz"; exit 1; }

echo "==> flowmon baslatiliyor (hedef port $PORT)"
$BIN -dport "$PORT" -exclude-loopback=false > "$OUT" 2>/dev/null &
PID=$!
trap 'kill $PID 2>/dev/null || true; rm -f "$OUT"' EXIT
sleep 2

kill -0 $PID 2>/dev/null || { echo "HATA: flowmon baslamadi"; exit 1; }

echo "==> kapali bir porta baglanti denemesi"
for _ in 1 2 3; do
	timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" 2>/dev/null || true
done
sleep 1

kill -INT $PID 2>/dev/null || true
wait $PID 2>/dev/null || true

echo "==> yakalanan olaylar"
if [[ ! -s $OUT ]]; then
	echo "    BASARISIZ: hic olay yakalanmadi"
	exit 1
fi
cat "$OUT"

n=$(grep -c "\"dport\":$PORT" "$OUT" || true)
echo
if [[ $n -gt 0 ]]; then
	echo "GECTI: $n deneme yakalandi, uclu cikarilabiliyor."
else
	echo "BASARISIZ: $PORT portuna yapilan deneme goruntulenemedi."
	exit 1
fi
