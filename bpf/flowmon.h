/* SPDX-License-Identifier: GPL-2.0 */
/*
 * flowmon.h — kernel/userspace arasinda paylasilan olay sozlesmesi.
 *
 * Bu struct'in yerlesimi (layout) Go tarafinda internal/flow/event.go icinde
 * elle cozumleniyor. Alan ekler/cikarirsaniz iki tarafi da guncelleyin;
 * boyut sabiti FLOW_EVENT_SIZE ile Go tarafinda dogrulaniyor.
 */
#ifndef __FLOWMON_H
#define __FLOWMON_H

#define FM_COMM_LEN 16

/* connect() denemesinin nasil sonuclandigi. Sinifi (drop mu, RST mi) userspace
 * belirler; cekirdek yalnizca ham olguyu bildirir. */
enum fm_verdict {
	FM_VERDICT_ESTABLISHED = 0, /* SYN_SENT -> ESTABLISHED */
	FM_VERDICT_FAILED      = 1, /* SYN_SENT -> CLOSE (el sikisma tamamlanmadi) */
};

/* flags */
#define FM_FLAG_NO_META (1 << 0) /* soket biz baglanmadan once yaratilmis */

struct flow_event {
	__u64 ts_ns;       /* olayin cekirdek zamani (bpf_ktime_get_ns) */
	__u64 cgroup_id;   /* connect() cagiran gorevin cgroup v2 id'si */
	__u64 duration_ns; /* connect() basi ile sonucu arasindaki sure */
	__u32 pid;         /* thread id */
	__u32 tgid;        /* process id */
	__u32 saddr;       /* IPv4, network byte order */
	__u32 daddr;       /* IPv4, network byte order */
	__u32 retrans;     /* SYN_SENT sirasinda gorulen yeniden iletim sayisi */
	__u16 sport;       /* host byte order */
	__u16 dport;       /* host byte order */
	__u8  verdict;     /* enum fm_verdict */
	__u8  family;      /* 2 = AF_INET */
	__u8  flags;
	__u8  _pad;
	char  comm[FM_COMM_LEN];
	__u8  _pad2[4];    /* 8-bayt hizalamayi acikca tamamlar */
};

#define FLOW_EVENT_SIZE 72

#endif /* __FLOWMON_H */
