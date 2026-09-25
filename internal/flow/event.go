// Package flow, cekirdekten gelen ham olaylari cozumler ve dogrulama kapisini
// sinirlayan "gozlenen akis" kumesini olusturur.
package flow

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// EventSize, bpf/flowmon.h icindeki FLOW_EVENT_SIZE ile ayni olmali.
const EventSize = 72

// Cekirdekteki enum fm_verdict ile ayni.
const (
	verdictEstablished uint8 = 0
	verdictFailed      uint8 = 1
)

const flagNoMeta uint8 = 1 << 0

// Class, bir connect() denemesinin ne anlama geldigi.
//
// kubectl describe bu ucunu de ayni gosterir; ayrimi yapan sey retransmit
// sayaci: SYN'e hic cevap gelmediyse paket sessizce dusurulmustur
// (NetworkPolicy, partition), aninda RST geldiyse hedef erisilebilir ama o
// portta dinleyen yoktur.
type Class string

const (
	ClassOK      Class = "established"
	ClassDropped Class = "dropped"  /* SYN yeniden iletildi, cevap yok */
	ClassRefused Class = "refused"  /* RST — hedefe ulasildi, port kapali */
)

// İlk SYN yeniden iletimi ~1sn sonra gelir. Uygulama bundan once vazgecerse
// (non-blocking connect + kisa timeout) retransmit gormeyiz; bu durumda sureye
// bakarak yine de "dusuruldu" diyoruz. Anlik RST milisaniyeler icinde doner,
// yani iki durum sure ekseninde net ayrilir.
const dropInferenceThreshold = 900 * time.Millisecond

// Event, tek bir connect() denemesinin sonucu.
type Event struct {
	Timestamp time.Duration // cekirdek monotonik saati (bpf_ktime_get_ns)
	CgroupID  uint64
	Duration  time.Duration
	PID       uint32
	TGID      uint32
	Src       netip.AddrPort
	Dst       netip.AddrPort
	Retrans   uint32
	Comm      string
	HasMeta   bool // false ise cgroup/pid alanlari anlamsiz
	verdict   uint8
}

// Class, olayin sinifini dondurur.
func (e Event) Class() Class {
	if e.verdict == verdictEstablished {
		return ClassOK
	}
	if e.Retrans > 0 || e.Duration >= dropInferenceThreshold {
		return ClassDropped
	}
	return ClassRefused
}

// Failed, denemenin el sikismayi tamamlayamadigini soyler.
func (e Event) Failed() bool { return e.verdict == verdictFailed }

// Parse, ring buffer'dan gelen ham kaydi cozumler.
func Parse(raw []byte) (Event, error) {
	if len(raw) < EventSize {
		return Event{}, fmt.Errorf("kisa kayit: %d bayt, beklenen %d", len(raw), EventSize)
	}
	// Cekirdek struct'i host sirasinda yaziyor.
	e := binary.NativeEndian
	ev := Event{
		Timestamp: time.Duration(e.Uint64(raw[0:8])),
		CgroupID:  e.Uint64(raw[8:16]),
		Duration:  time.Duration(e.Uint64(raw[16:24])),
		PID:       e.Uint32(raw[24:28]),
		TGID:      e.Uint32(raw[28:32]),
		Retrans:   e.Uint32(raw[40:44]),
		verdict:   raw[48],
	}
	// saddr/daddr network byte order; netip.AddrFrom4 zaten big-endian bekliyor.
	ev.Src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(raw[32:36])), e.Uint16(raw[44:46]))
	ev.Dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(raw[36:40])), e.Uint16(raw[46:48]))
	ev.HasMeta = raw[50]&flagNoMeta == 0
	ev.Comm = cstr(raw[52:68])
	return ev, nil
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
