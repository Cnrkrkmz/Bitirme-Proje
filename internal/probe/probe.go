// Package probe, derlenmis eBPF nesnesini yukler ve kancalari takar.
//
// .o dosyasi ikiliye gomulu (go:embed): calisma aninda dosya yolu bagimliligi
// olmuyor, boylece Operator tarafindan bir DaemonSet icinde tek binary olarak
// dagitilabiliyor.
package probe

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/flowmon.bpf.o
var flowmonELF []byte

// Probe, yuklenmis programlari ve acik ring buffer'i tutar.
type Probe struct {
	coll   *ebpf.Collection
	links  []link.Link
	Events *ringbuf.Reader
}

// Load, eBPF nesnesini yukler ve uc kancayi takar. Hata durumunda kismi
// kaynaklar temizlenir.
func Load() (*Probe, error) {
	// Eski cekirdeklerde BPF map'leri memlock kotasindan dusuyor; kaldiriyoruz.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock limiti kaldirilamadi: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(flowmonELF))
	if err != nil {
		return nil, fmt.Errorf("gomulu BPF nesnesi cozumlenemedi: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		// Verifier hatalari cok satirli gelir ve tam metni olmadan tesbit
		// edilemez; kirpilmis halini yaymiyoruz.
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("BPF verifier reddetti:\n%+v", ve)
		}
		return nil, fmt.Errorf("BPF koleksiyonu yuklenemedi: %w", err)
	}

	p := &Probe{coll: coll}

	// Programi isimle ariyoruz; eksikse .o ile bu dosya birbirinden kaymis
	// demektir ve nil'i link'e vermek anlamsiz bir hata uretir.
	prog := func(name string) (*ebpf.Program, error) {
		if pr := coll.Programs[name]; pr != nil {
			return pr, nil
		}
		return nil, fmt.Errorf("BPF programi bulunamadi: %s (flowmon.bpf.o guncel mi?)", name)
	}

	kprog, err := prog("fm_tcp_v4_connect")
	if err != nil {
		p.Close()
		return nil, err
	}
	kp, err := link.Kprobe("tcp_v4_connect", kprog, nil)
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("kprobe tcp_v4_connect takilamadi: %w", err)
	}
	p.links = append(p.links, kp)

	for _, name := range []string{"fm_tcp_retransmit_skb", "fm_inet_sock_set_state"} {
		tp, err := prog(name)
		if err != nil {
			p.Close()
			return nil, err
		}
		l, err := link.AttachTracing(link.TracingOptions{Program: tp})
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("tp_btf %s takilamadi (cekirdekte BTF var mi?): %w", name, err)
		}
		p.links = append(p.links, l)
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("ring buffer acilamadi: %w", err)
	}
	p.Events = rd

	return p, nil
}

// Dropped, ring buffer dolu oldugu icin atilan olay sayisini dondurur.
// Sifirdan buyuk bir deger olcumun eksik oldugu anlamina gelir; sessizce
// gecilmemeli.
func (p *Probe) Dropped() (uint64, error) {
	m := p.coll.Maps["dropped"]
	if m == nil {
		return 0, errors.New("dropped map bulunamadi")
	}
	var v uint64
	if err := m.Lookup(uint32(0), &v); err != nil {
		return 0, err
	}
	return v, nil
}

// Close, ring buffer'i, kancalari ve yuklenmis programlari birakir.
func (p *Probe) Close() {
	if p.Events != nil {
		p.Events.Close()
	}
	for _, l := range p.links {
		l.Close()
	}
	if p.coll != nil {
		p.coll.Close()
	}
}
