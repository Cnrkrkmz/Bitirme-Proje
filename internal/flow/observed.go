package flow

import (
	"encoding/json"
	"io"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Key, bir akisin kimligi. Kaynak PORT'u kasitli olarak disarida: efemeral
// kaynak portu her denemede degisir ve NetworkPolicy semantiginde anlami yok.
// Politika (kaynak IP, hedef IP, hedef port) uzerinden yazilir.
type Key struct {
	Src   netip.Addr `json:"src"`
	Dst   netip.Addr `json:"dst"`
	Dport uint16     `json:"dport"`
}

// Flow, tek bir uclunun gozlem ozeti.
type Flow struct {
	Key
	Established uint64 `json:"established"`
	Dropped     uint64 `json:"dropped"`
	Refused     uint64 `json:"refused"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	// Meta bilgisi olan en son olaydan; pod eslestirmesi icin ipucu.
	CgroupID uint64 `json:"cgroup_id,omitempty"`
	Comm     string `json:"comm,omitempty"`
}

// Attempts, uclu icin gorulen toplam deneme sayisi.
func (f Flow) Attempts() uint64 { return f.Established + f.Dropped + f.Refused }

// ObservedSet, dogrulama kapisini sinirlayan gozlenen akis kumesi (§3.3).
//
// Kapinin sordugu soru "bu oneri gozlenen akistan fazlasini aciyor mu"
// oldugu icin bu kumenin iki yarisi da gerekli: basarisiz akislar onarilmasi
// gerekeni, basarili akislar ise korunmasi gerekeni tanimlar. Yalnizca
// basarisizlari toplamak, kapinin mesru trafigi kapatmasina (UPR > 0) yol acar.
type ObservedSet struct {
	mu    sync.Mutex
	flows map[Key]*Flow
}

func NewObservedSet() *ObservedSet {
	return &ObservedSet{flows: make(map[Key]*Flow)}
}

// Add, bir olayi kumeye isler. wall, cekirdek monotonik saatinden duvar saatine
// cevrilmis zaman damgasi.
func (s *ObservedSet) Add(ev Event, wall time.Time) {
	k := Key{Src: ev.Src.Addr(), Dst: ev.Dst.Addr(), Dport: ev.Dst.Port()}

	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.flows[k]
	if !ok {
		f = &Flow{Key: k, FirstSeen: wall}
		s.flows[k] = f
	}
	f.LastSeen = wall

	switch ev.Class() {
	case ClassOK:
		f.Established++
	case ClassDropped:
		f.Dropped++
	case ClassRefused:
		f.Refused++
	}

	if ev.HasMeta {
		f.CgroupID = ev.CgroupID
		f.Comm = ev.Comm
	}
}

// Snapshot, kumeyi deterministik sirada dondurur. Sira sabit olmali: bu ciktinin
// hash'i senaryolarin (scenario, seed, proposal hash) eslesmesinde kullaniliyor.
func (s *ObservedSet) Snapshot() []Flow {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Flow, 0, len(s.flows))
	for _, f := range s.flows {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Src != out[j].Src {
			return out[i].Src.Less(out[j].Src)
		}
		if out[i].Dst != out[j].Dst {
			return out[i].Dst.Less(out[j].Dst)
		}
		return out[i].Dport < out[j].Dport
	})
	return out
}

// WriteJSON, kumeyi kapinin girdisi olarak kullanilabilecek bicimde yazar.
func (s *ObservedSet) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		CapturedAt time.Time `json:"captured_at"`
		Flows      []Flow    `json:"flows"`
	}{time.Now().UTC(), s.Snapshot()})
}
