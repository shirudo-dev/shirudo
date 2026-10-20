// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * obs_net.bpf.c -- sockets, peers, listeners and watched destinations.
 *
 * Socket creation and accept stamp the socket with its owner's identity.
 * Connects, datagram sends, listens and binds record the endpoint; the
 * cgroup packet hooks add packet and byte counts per peer in both
 * directions, so volume is visible, not only reachability.  Peers on
 * the signed watch list are recorded a second time in the watch table.
 */

#define OBS_WATCH_CHECKED	0
#define OBS_WATCH_MATCHED	1

enum obs_listen_kind {
	OBS_LISTEN_LISTEN = 1,
	OBS_LISTEN_BIND = 2,
};

enum obs_socket_operation {
	OBS_SOCKET_CREATE = 1,
	OBS_SOCKET_BIND,
	OBS_SOCKET_CONNECT,
	OBS_SOCKET_LISTEN,
	OBS_SOCKET_ACCEPT,
	OBS_SOCKET_SENDMSG,
	OBS_SOCKET_RECVMSG,
	OBS_SOCKET_SETSOCKOPT,
	OBS_SOCKET_SHUTDOWN,
	OBS_SOCKET_SOCKETPAIR,
};

#define OBS_SOCKET_F_OWNER_KNOWN	(1u << 0)
#define OBS_SOCKET_F_OWNER_INFERRED	(1u << 1)
#define OBS_SOCKET_F_ACTOR_KNOWN	(1u << 2)

struct net_key {
	struct obs_ident ident;
	__u8 family;
	__u8 proto;
	__u8 role;
	__u8 _pad0;
	__u16 port;		/* host order */
	__u16 _pad1;
	__u32 addr[4];		/* network order, IPv4 in addr[0] */
};

struct net_val {
	__u64 count;
	__u64 first_ns;
	__u64 last_ns;
	__u64 tx_pkts;
	__u64 tx_bytes;
	__u64 rx_pkts;
	__u64 rx_bytes;
	__u32 pid;
	__u32 _pad;
};

struct listen_val {
	__u64 count;
	__u64 first_ns;
	__u64 last_ns;
	__u32 pid;
	__u32 backlog;
};

struct watch_val {
	__u64 count;
	__u64 first_ns;
	__u64 last_ns;
	__u64 pkts;
	__u64 bytes;
	__u32 pid;
	__u32 _pad;
};

struct socket_key {
	struct obs_ident owner;
	struct obs_ident actor;
	__u32 owner_pid;
	__u32 actor_pid;
	__u16 family;
	__u16 type;
	__u16 operation;
	__u16 _pad0;
	__u32 protocol;
	__u32 level;
	__u32 option;
	__u32 flags;
	__u32 _pad1;
	__u32 _pad2;
};

struct socket_val {
	__u64 count;
	__u64 first_ns;
	__u64 last_ns;
	__u64 bytes_requested;
};

struct obs_watch_node {
	__u16 child[256];
	__u16 terminal;
	__u16 reserved[3];
};

#include "watch_generated.h"

static const struct obs_watch_node obs_watch_v4[OBS_WATCH_V4_NODES] =
	OBS_WATCH_V4_INIT;
static const struct obs_watch_node obs_watch_v6[OBS_WATCH_V6_NODES] =
	OBS_WATCH_V6_INIT;

struct obs_watch_counter {
	__u64 checked;
	__u64 matched;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct obs_watch_counter);
} watch_stat SEC(".maps");

static __always_inline void net_emit_key(struct shirudo_serial_chunk *chunk,
					 __u32 off,
					 const struct net_key __arena *key)
{
	*(__u32 *)&chunk->data[off + 8] = key->ident.exe.dev;
	*(__u32 *)&chunk->data[off + 12] = 0;
	*(__u64 *)&chunk->data[off + 16] = key->ident.exe.ino;
	*(__u64 *)&chunk->data[off + 24] = key->ident.cgroup;
	chunk->data[off + 32] = key->family;
	chunk->data[off + 33] = key->proto;
	chunk->data[off + 34] = key->role;
	chunk->data[off + 35] = 0;
	*(__u16 *)&chunk->data[off + 36] = key->port;
	*(__u16 *)&chunk->data[off + 38] = 0;
	*(__u32 *)&chunk->data[off + 40] = key->addr[0];
	*(__u32 *)&chunk->data[off + 44] = key->addr[1];
	*(__u32 *)&chunk->data[off + 48] = key->addr[2];
	*(__u32 *)&chunk->data[off + 52] = key->addr[3];
}

#define OBS_T		net
#define OBS_T_MAP	net
#define OBS_T_KEY	struct net_key
#define OBS_T_VAL	struct net_val
#define OBS_T_CAPACITY	8192
#define OBS_T_BUCKETS	4096
#define OBS_T_STEPS	8
#define OBS_T_MAGIC	0x5445454eu	/* "NEET" little-endian */
#define OBS_T_RECORD	120
#define OBS_T_EMIT	net_emit_record
#include "obs_table.h"

static int net_emit_record(struct shirudo_serial_chunk *chunk, __u32 off,
			   const struct net_entry __arena *e)
{
	net_emit_key(chunk, off, &e->key);
	*(__u64 *)&chunk->data[off + 56] = e->val.count;
	*(__u64 *)&chunk->data[off + 64] = e->val.first_ns;
	*(__u64 *)&chunk->data[off + 72] = e->val.last_ns;
	*(__u64 *)&chunk->data[off + 80] = e->val.tx_pkts;
	*(__u64 *)&chunk->data[off + 88] = e->val.tx_bytes;
	*(__u64 *)&chunk->data[off + 96] = e->val.rx_pkts;
	*(__u64 *)&chunk->data[off + 104] = e->val.rx_bytes;
	*(__u32 *)&chunk->data[off + 112] = e->val.pid;
	*(__u32 *)&chunk->data[off + 116] = 0;
	return 0;
}

#define OBS_T		listen
#define OBS_T_MAP	listen
#define OBS_T_KEY	struct net_key
#define OBS_T_VAL	struct listen_val
#define OBS_T_CAPACITY	1024
#define OBS_T_BUCKETS	512
#define OBS_T_STEPS	8
#define OBS_T_MAGIC	0x5453494cu	/* "LIST" little-endian */
#define OBS_T_RECORD	88
#define OBS_T_EMIT	listen_emit_record
#include "obs_table.h"

static int listen_emit_record(struct shirudo_serial_chunk *chunk, __u32 off,
			      const struct listen_entry __arena *e)
{
	net_emit_key(chunk, off, &e->key);
	*(__u64 *)&chunk->data[off + 56] = e->val.count;
	*(__u64 *)&chunk->data[off + 64] = e->val.first_ns;
	*(__u64 *)&chunk->data[off + 72] = e->val.last_ns;
	*(__u32 *)&chunk->data[off + 80] = e->val.pid;
	*(__u32 *)&chunk->data[off + 84] = e->val.backlog;
	return 0;
}

#define OBS_T		watch
#define OBS_T_MAP	watch
#define OBS_T_KEY	struct net_key
#define OBS_T_VAL	struct watch_val
#define OBS_T_CAPACITY	1024
#define OBS_T_BUCKETS	512
#define OBS_T_STEPS	8
#define OBS_T_MAGIC	0x48435457u	/* "WTCH" little-endian */
#define OBS_T_RECORD	104
#define OBS_T_EMIT	watch_emit_record
#include "obs_table.h"

static int watch_emit_record(struct shirudo_serial_chunk *chunk, __u32 off,
			     const struct watch_entry __arena *e)
{
	net_emit_key(chunk, off, &e->key);
	*(__u64 *)&chunk->data[off + 56] = e->val.count;
	*(__u64 *)&chunk->data[off + 64] = e->val.first_ns;
	*(__u64 *)&chunk->data[off + 72] = e->val.last_ns;
	*(__u64 *)&chunk->data[off + 80] = e->val.pkts;
	*(__u64 *)&chunk->data[off + 88] = e->val.bytes;
	*(__u32 *)&chunk->data[off + 96] = e->val.pid;
	*(__u32 *)&chunk->data[off + 100] = 0;
	return 0;
}

#define OBS_T		socket
#define OBS_T_MAP	socket
#define OBS_T_KEY	struct socket_key
#define OBS_T_VAL	struct socket_val
#define OBS_T_CAPACITY	1024
#define OBS_T_BUCKETS	512
#define OBS_T_STEPS	8
#define OBS_T_MAGIC	0x4b434f53u	/* "SOCK" little-endian */
#define OBS_T_RECORD	128
#define OBS_T_EMIT	socket_emit_record
#include "obs_table.h"

static int socket_emit_record(struct shirudo_serial_chunk *chunk, __u32 off,
			      const struct socket_entry __arena *e)
{
	const struct socket_key __arena *key = &e->key;

	*(__u32 *)&chunk->data[off + 8] = key->owner.exe.dev;
	*(__u32 *)&chunk->data[off + 12] = 0;
	*(__u64 *)&chunk->data[off + 16] = key->owner.exe.ino;
	*(__u64 *)&chunk->data[off + 24] = key->owner.cgroup;
	*(__u32 *)&chunk->data[off + 32] = key->actor.exe.dev;
	*(__u32 *)&chunk->data[off + 36] = 0;
	*(__u64 *)&chunk->data[off + 40] = key->actor.exe.ino;
	*(__u64 *)&chunk->data[off + 48] = key->actor.cgroup;
	*(__u32 *)&chunk->data[off + 56] = key->owner_pid;
	*(__u32 *)&chunk->data[off + 60] = key->actor_pid;
	*(__u16 *)&chunk->data[off + 64] = key->family;
	*(__u16 *)&chunk->data[off + 66] = key->type;
	*(__u16 *)&chunk->data[off + 68] = key->operation;
	*(__u16 *)&chunk->data[off + 70] = 0;
	*(__u32 *)&chunk->data[off + 72] = key->protocol;
	*(__u32 *)&chunk->data[off + 76] = key->level;
	*(__u32 *)&chunk->data[off + 80] = key->option;
	*(__u32 *)&chunk->data[off + 84] = key->flags;
	*(__u32 *)&chunk->data[off + 88] = 0;
	*(__u32 *)&chunk->data[off + 92] = 0;
	*(__u64 *)&chunk->data[off + 96] = e->val.count;
	*(__u64 *)&chunk->data[off + 104] = e->val.first_ns;
	*(__u64 *)&chunk->data[off + 112] = e->val.last_ns;
	*(__u64 *)&chunk->data[off + 120] = e->val.bytes_requested;
	return 0;
}

static __always_inline bool obs_watch_lookup_v4(__u32 addr4)
{
	__u32 address = bpf_ntohl(addr4), idx = 0, octet;
	__u16 child;
	int depth;

	if (obs_watch_v4[0].terminal)
		return true;
#pragma clang loop unroll(full)
	for (depth = 0; depth < 4; depth++) {
		octet = (address >> (24 - depth * 8)) & 0xff;
		child = obs_watch_v4[idx].child[octet];
		if (!child)
			return false;
		idx = (__u32)child - 1;
		if (idx >= OBS_WATCH_V4_NODES)
			return false;
		if (obs_watch_v4[idx].terminal)
			return true;
	}
	return false;
}

static __always_inline bool obs_watch_lookup_v6(const __u32 *addr6)
{
	const __u8 *bytes = (const __u8 *)addr6;
	__u32 idx = 0, octet;
	__u16 child;
	int depth;

	if (obs_watch_v6[0].terminal)
		return true;
#pragma clang loop unroll(full)
	for (depth = 0; depth < 16; depth++) {
		octet = bytes[depth];
		child = obs_watch_v6[idx].child[octet];
		if (!child)
			return false;
		idx = (__u32)child - 1;
		if (idx >= OBS_WATCH_V6_NODES)
			return false;
		if (obs_watch_v6[idx].terminal)
			return true;
	}
	return false;
}

static __always_inline bool obs_watch_match(__u8 family, const __u32 *addr)
{
	if (family == AF_INET)
		return obs_watch_lookup_v4(addr[0]);
	if (family == AF_INET6)
		return obs_watch_lookup_v6(addr);
	return false;
}

static __always_inline void obs_watch_count(bool matched)
{
	struct obs_watch_counter *counter;
	__u32 key = 0;

	counter = bpf_map_lookup_elem(&watch_stat, &key);
	if (!counter)
		return;
	__sync_fetch_and_add(&counter->checked, 1);
	if (matched)
		__sync_fetch_and_add(&counter->matched, 1);
}

/* Socket-level attempt against a watched destination. */
static __always_inline void obs_watch_attempt(const struct net_key *peer,
					      __u64 now)
{
	struct watch_entry __arena *e;
	struct net_key key = *peer;
	bool matched;
	int status;

	matched = obs_watch_match(key.family, key.addr);
	obs_watch_count(matched);
	if (!matched)
		return;
	key.role = 0;
	e = watch_touch(&key, &status);
	if (!e)
		return;
	if (status == OBS_TOUCH_CREATED)
		e->val.first_ns = now;
	__sync_fetch_and_add(&e->val.count, 1);
	e->val.last_ns = now;
	e->val.pid = obs_tgid();
}

static __always_inline void obs_watch_packet(const struct net_key *peer,
					     __u32 len, __u64 now)
{
	struct watch_entry __arena *e;
	struct net_key key = *peer;
	int status;

	if (!obs_watch_match(key.family, key.addr))
		return;
	key.role = 0;
	e = watch_touch(&key, &status);
	if (!e)
		return;
	if (status == OBS_TOUCH_CREATED)
		e->val.first_ns = now;
	__sync_fetch_and_add(&e->val.pkts, 1);
	__sync_fetch_and_add(&e->val.bytes, len);
	e->val.last_ns = now;
}

static __always_inline void obs_net_count(const struct net_key *key,
					  __u64 now)
{
	struct net_entry __arena *e;
	int status;

	e = net_touch(key, &status);
	if (!e)
		return;
	if (status == OBS_TOUCH_CREATED)
		e->val.first_ns = now;
	__sync_fetch_and_add(&e->val.count, 1);
	e->val.last_ns = now;
	e->val.pid = obs_tgid();
}

static __always_inline void obs_listen_count(const struct net_key *key,
					     __u32 backlog, __u64 now)
{
	struct listen_entry __arena *e;
	int status;

	e = listen_touch(key, &status);
	if (!e)
		return;
	if (status == OBS_TOUCH_CREATED)
		e->val.first_ns = now;
	__sync_fetch_and_add(&e->val.count, 1);
	e->val.last_ns = now;
	e->val.pid = obs_tgid();
	e->val.backlog = backlog;
}

static __always_inline struct obs_sock_meta *
obs_sock_meta_set(struct sock *sk, __u32 role, __u64 now)
{
	struct obs_sock_meta *meta;
	struct obs_ident ident;
	bool known;

	meta = bpf_sk_storage_get(&obs_i_sock, sk, 0,
				  BPF_SK_STORAGE_GET_F_CREATE);
	if (!meta)
		return 0;
	known = obs_ident_checked(&ident, now);
	meta->exe = ident.exe;
	meta->cgroup = ident.cgroup;
	meta->owner_pid = obs_tgid();
	meta->role = role;
	meta->flags = known ? 0 : OBS_SOCK_META_OWNER_UNKNOWN;
	meta->_pad = 0;
	return meta;
}

/* A socket first seen after load has no observed creator. */
static __always_inline struct obs_sock_meta *
obs_sock_meta_get(struct sock *sk, __u64 now)
{
	struct obs_sock_meta *meta;

	meta = bpf_sk_storage_get(&obs_i_sock, sk, 0, 0);
	if (meta)
		return meta;
	meta = obs_sock_meta_set(sk, OBS_ROLE_NONE, now);
	if (meta)
		meta->flags |= OBS_SOCK_META_OWNER_INFERRED;
	return meta;
}

static __always_inline bool obs_socket_detail_family(__u16 family)
{
	return family == AF_UNIX || family == AF_INET ||
	       family == AF_INET6 || family == AF_NETLINK ||
	       family == AF_PACKET || family == AF_VSOCK ||
	       family == AF_XDP;
}

static __always_inline void
obs_socket_record(struct socket *sock, __u16 family, __u16 type,
		  __u32 protocol, __u16 operation, __s32 size,
		  __s32 level, __s32 option, __u64 now)
{
	struct socket_entry __arena *entry;
	struct obs_sock_meta *meta;
	struct socket_key key = {};
	struct obs_ident actor = {};
	struct sock *sk;
	__u32 flags = 0;
	int status;

	if (!sock)
		return;
	sk = sock->sk;
	if (!sk)
		return;
	if (operation != OBS_SOCKET_CREATE &&
	    !obs_socket_detail_family(family))
		return;
	meta = obs_sock_meta_get(sk, now);
	if (meta) {
		if (!(meta->flags & (OBS_SOCK_META_OWNER_INFERRED |
				     OBS_SOCK_META_OWNER_UNKNOWN))) {
			key.owner.exe = meta->exe;
			key.owner.cgroup = meta->cgroup;
			key.owner_pid = meta->owner_pid;
			flags |= OBS_SOCKET_F_OWNER_KNOWN;
		} else if (meta->flags & OBS_SOCK_META_OWNER_INFERRED) {
			flags |= OBS_SOCKET_F_OWNER_INFERRED;
		}
	}
	if (obs_ident_checked(&actor, now))
		flags |= OBS_SOCKET_F_ACTOR_KNOWN;
	key.actor = actor;
	key.actor_pid = obs_tgid();
	key.family = family;
	key.type = type & SOCK_TYPE_MASK;
	key.operation = operation;
	key.protocol = protocol;
	key.level = level < 0 ? 0 : (__u32)level;
	key.option = option < 0 ? 0 : (__u32)option;
	key.flags = flags;
	entry = socket_touch(&key, &status);
	if (!entry)
		return;
	if (status == OBS_TOUCH_CREATED)
		entry->val.first_ns = now;
	__sync_fetch_and_add(&entry->val.count, 1);
	if (size > 0)
		__sync_fetch_and_add(&entry->val.bytes_requested, (__u32)size);
	entry->val.last_ns = now;
}

static __always_inline bool obs_peer_from_sockaddr(struct sockaddr *addr,
						   int addrlen,
						   struct net_key *key)
{
	struct sockaddr_in sin = {};
	struct obs_sockaddr_in6 sin6 = {};
	__u16 family = 0;

	if (!addr || addrlen < (int)sizeof(struct sockaddr))
		return false;
	if (bpf_probe_read_kernel(&family, sizeof(family), &addr->sa_family))
		return false;
	if (family == AF_INET) {
		if (addrlen < (int)sizeof(sin) ||
		    bpf_probe_read_kernel(&sin, sizeof(sin), addr))
			return false;
		key->family = AF_INET;
		key->port = bpf_ntohs(sin.sin_port);
		key->addr[0] = sin.sin_addr.s_addr;
		return true;
	}
	if (family == AF_INET6 && obs_ipv6_enabled()) {
		if (addrlen < (int)sizeof(sin6) ||
		    bpf_probe_read_kernel(&sin6, sizeof(sin6), addr))
			return false;
		key->family = AF_INET6;
		key->port = bpf_ntohs(sin6.sin6_port);
		key->addr[0] = sin6.sin6_addr[0];
		key->addr[1] = sin6.sin6_addr[1];
		key->addr[2] = sin6.sin6_addr[2];
		key->addr[3] = sin6.sin6_addr[3];
		return true;
	}
	return false;
}

static __always_inline bool obs_peer_from_sock(struct sock *sk,
					       struct net_key *key)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	__be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

	if (family == AF_INET) {
		key->family = AF_INET;
		key->port = bpf_ntohs(dport);
		key->addr[0] = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		return key->addr[0] != 0 || dport != 0;
	}
	if (family == AF_INET6 && obs_ipv6_enabled()) {
		struct sock_common___ipv6 *common = (void *)&sk->__sk_common;

		key->family = AF_INET6;
		key->port = bpf_ntohs(dport);
		if (bpf_core_read(key->addr, sizeof(key->addr),
				  &common->skc_v6_daddr))
			return false;
		return dport != 0;
	}
	return false;
}

static __always_inline bool obs_local_from_sock(struct sock *sk,
						struct net_key *key)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

	key->port = BPF_CORE_READ(sk, __sk_common.skc_num);
	if (family == AF_INET) {
		key->family = AF_INET;
		key->addr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		return true;
	}
	if (family == AF_INET6 && obs_ipv6_enabled()) {
		struct sock_common___ipv6 *common = (void *)&sk->__sk_common;

		key->family = AF_INET6;
		if (bpf_core_read(key->addr, sizeof(key->addr),
				  &common->skc_v6_rcv_saddr))
			return false;
		return true;
	}
	return false;
}

static __always_inline bool obs_inet_family(__u16 family)
{
	return family == AF_INET || family == AF_INET6;
}

SEC("lsm/socket_post_create")
int BPF_PROG(obs_socket_create, struct socket *sock, int family, int type,
	     int protocol, int kern)
{
	__u64 now = obs_now();
	struct sock *sk;

	if (kern || !sock)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;
	obs_sock_meta_set(sk, OBS_ROLE_NONE, now);
	obs_socket_record(sock, (__u16)family, (__u16)type, (__u32)protocol,
			  OBS_SOCKET_CREATE, 0, 0, 0, now);
	return 0;
}

SEC("lsm/sock_graft")
int BPF_PROG(obs_sock_graft, struct sock *sk, struct socket *parent)
{
	struct obs_sock_meta *meta;
	struct net_key key = {};
	__u64 now = obs_now();

	(void)parent;
	if (!sk)
		return 0;
	meta = obs_sock_meta_set(sk, OBS_ROLE_ACCEPTOR, now);
	if (!meta || !obs_inet_family(BPF_CORE_READ(sk, __sk_common.skc_family)) ||
	    !obs_peer_from_sock(sk, &key))
		return 0;
	key.ident.exe = meta->exe;
	key.ident.cgroup = meta->cgroup;
	key.proto = BPF_CORE_READ(sk, sk_protocol);
	key.role = OBS_ROLE_ACCEPTOR;
	key.port = 0;	/* a client's ephemeral port is not worth a record */
	obs_net_count(&key, now);
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(obs_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	struct obs_sock_meta *meta;
	struct net_key key = {};
	struct sock *sk;
	__u64 now = obs_now();
	__u16 type;

	if (!sock)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;
	obs_socket_record(sock, BPF_CORE_READ(sk, __sk_common.skc_family),
			  sock->type, BPF_CORE_READ(sk, sk_protocol),
			  OBS_SOCKET_CONNECT, 0, 0, 0, now);
	if (!obs_inet_family(BPF_CORE_READ(sk, __sk_common.skc_family)))
		return 0;
	type = sock->type & SOCK_TYPE_MASK;
	if (type != SOCK_STREAM && type != SOCK_SEQPACKET)
		return 0;
	if (!obs_peer_from_sockaddr(address, addrlen, &key))
		return 0;
	meta = obs_sock_meta_get(sk, now);
	if (meta) {
		meta->role = OBS_ROLE_INITIATOR;
		key.ident.exe = meta->exe;
		key.ident.cgroup = meta->cgroup;
	}
	key.proto = BPF_CORE_READ(sk, sk_protocol);
	key.role = OBS_ROLE_INITIATOR;
	obs_net_count(&key, now);
	obs_watch_attempt(&key, now);
	return 0;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(obs_socket_sendmsg, struct socket *sock, struct msghdr *msg,
	     int size)
{
	struct obs_sock_meta *meta;
	struct net_key key = {};
	struct sockaddr *addr;
	struct sock *sk;
	__u64 now = obs_now();
	__u16 type;
	int addrlen;

	if (!sock || !msg)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;
	obs_socket_record(sock, BPF_CORE_READ(sk, __sk_common.skc_family),
			  sock->type, BPF_CORE_READ(sk, sk_protocol),
			  OBS_SOCKET_SENDMSG, size, 0, 0, now);
	if (size <= 0 ||
	    !obs_inet_family(BPF_CORE_READ(sk, __sk_common.skc_family)))
		return 0;
	type = sock->type & SOCK_TYPE_MASK;
	if (type != SOCK_DGRAM && type != SOCK_RAW)
		return 0;
	addr = msg->msg_name;
	addrlen = msg->msg_namelen;
	if (addr && addrlen > 0) {
		if (!obs_peer_from_sockaddr(addr, addrlen, &key))
			return 0;
	} else if (!obs_peer_from_sock(sk, &key)) {
		return 0;
	}
	meta = obs_sock_meta_get(sk, now);
	if (meta) {
		key.ident.exe = meta->exe;
		key.ident.cgroup = meta->cgroup;
	}
	key.proto = BPF_CORE_READ(sk, sk_protocol);
	key.role = OBS_ROLE_NONE;
	obs_net_count(&key, now);
	obs_watch_attempt(&key, now);
	return 0;
}

SEC("lsm/socket_listen")
int BPF_PROG(obs_socket_listen, struct socket *sock, int backlog)
{
	struct obs_sock_meta *meta;
	struct net_key key = {};
	struct sock *sk;
	__u64 now = obs_now();

	if (!sock)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;
	obs_socket_record(sock, BPF_CORE_READ(sk, __sk_common.skc_family),
			  sock->type, BPF_CORE_READ(sk, sk_protocol),
			  OBS_SOCKET_LISTEN, 0, 0, 0, now);
	if (!obs_inet_family(BPF_CORE_READ(sk, __sk_common.skc_family)))
		return 0;
	if (!obs_local_from_sock(sk, &key))
		return 0;
	meta = obs_sock_meta_get(sk, now);
	if (meta) {
		meta->role = OBS_ROLE_LISTENER;
		key.ident.exe = meta->exe;
		key.ident.cgroup = meta->cgroup;
	}
	key.proto = BPF_CORE_READ(sk, sk_protocol);
	key.role = OBS_LISTEN_LISTEN;
	obs_listen_count(&key, backlog < 0 ? 0 : (__u32)backlog, now);
	return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(obs_socket_bind, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	struct obs_sock_meta *meta;
	struct net_key key = {};
	struct sock *sk;
	__u64 now = obs_now();
	__u16 type;

	if (!sock)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;
	obs_socket_record(sock, BPF_CORE_READ(sk, __sk_common.skc_family),
			  sock->type, BPF_CORE_READ(sk, sk_protocol),
			  OBS_SOCKET_BIND, 0, 0, 0, now);
	if (!obs_inet_family(BPF_CORE_READ(sk, __sk_common.skc_family)))
		return 0;
	type = sock->type & SOCK_TYPE_MASK;
	if (type != SOCK_DGRAM)
		return 0;
	if (!obs_peer_from_sockaddr(address, addrlen, &key) || key.port == 0)
		return 0;
	meta = obs_sock_meta_get(sk, now);
	if (meta) {
		key.ident.exe = meta->exe;
		key.ident.cgroup = meta->cgroup;
	}
	key.proto = BPF_CORE_READ(sk, sk_protocol);
	key.role = OBS_LISTEN_BIND;
	obs_listen_count(&key, 0, now);
	return 0;
}

SEC("lsm/socket_accept")
int BPF_PROG(obs_socket_accept, struct socket *sock, struct socket *newsock)
{
	__u64 now = obs_now();
	struct sock *sk;

	(void)newsock;
	if (!sock)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;
	obs_socket_record(sock, BPF_CORE_READ(sk, __sk_common.skc_family),
			  sock->type, BPF_CORE_READ(sk, sk_protocol),
			  OBS_SOCKET_ACCEPT, 0, 0, 0, now);
	return 0;
}

SEC("lsm/socket_recvmsg")
int BPF_PROG(obs_socket_recvmsg, struct socket *sock, struct msghdr *msg,
	     int size, int flags)
{
	__u64 now = obs_now();
	struct sock *sk;

	(void)msg;
	(void)flags;
	if (!sock)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;
	obs_socket_record(sock, BPF_CORE_READ(sk, __sk_common.skc_family),
			  sock->type, BPF_CORE_READ(sk, sk_protocol),
			  OBS_SOCKET_RECVMSG, size, 0, 0, now);
	return 0;
}

SEC("lsm/socket_setsockopt")
int BPF_PROG(obs_socket_setsockopt, struct socket *sock, int level,
	     int optname)
{
	__u64 now = obs_now();
	struct sock *sk;

	if (!sock)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;
	obs_socket_record(sock, BPF_CORE_READ(sk, __sk_common.skc_family),
			  sock->type, BPF_CORE_READ(sk, sk_protocol),
			  OBS_SOCKET_SETSOCKOPT, 0, level, optname, now);
	return 0;
}

SEC("lsm/socket_shutdown")
int BPF_PROG(obs_socket_shutdown, struct socket *sock, int how)
{
	__u64 now = obs_now();
	struct sock *sk;

	(void)how;
	if (!sock)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;
	obs_socket_record(sock, BPF_CORE_READ(sk, __sk_common.skc_family),
			  sock->type, BPF_CORE_READ(sk, sk_protocol),
			  OBS_SOCKET_SHUTDOWN, 0, 0, 0, now);
	return 0;
}

SEC("lsm/socket_socketpair")
int BPF_PROG(obs_socket_socketpair, struct socket *socka,
	     struct socket *sockb)
{
	__u64 now = obs_now();
	struct sock *sk;

	(void)sockb;
	if (!socka)
		return 0;
	sk = socka->sk;
	if (!sk)
		return 0;
	obs_socket_record(socka, BPF_CORE_READ(sk, __sk_common.skc_family),
			  socka->type, BPF_CORE_READ(sk, sk_protocol),
			  OBS_SOCKET_SOCKETPAIR, 0, 0, 0, now);
	return 0;
}

/* Parsed network and transport headers of one cgroup packet. */
struct obs_pkt {
	__u8 family;
	__u8 proto;
	__u16 sport;		/* network order */
	__u16 dport;		/* network order */
	__u16 l4_off;
	__u16 ethertype;	/* host order, set before any parsing */
	__u32 saddr[4];
	__u32 daddr[4];
};

static __always_inline bool obs_pkt_parse(struct __sk_buff *skb,
					  struct obs_pkt *pkt)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct obs_ipv6hdr *ip6;
	struct iphdr *ip4;
	__u32 l4_off;
	__u16 *ports;

	__builtin_memset(pkt, 0, sizeof(*pkt));
	/*
	 * Read the context field once; a second read elsewhere lets the
	 * compiler form context pointer arithmetic the verifier rejects.
	 */
	pkt->ethertype = bpf_ntohs(skb->protocol);
	switch (pkt->ethertype) {
	case ETH_P_IP:
		ip4 = data;
		if ((void *)(ip4 + 1) > data_end)
			return false;
		l4_off = ip4->ihl * 4;
		if (l4_off < sizeof(*ip4) || l4_off > 60)
			return false;
		pkt->family = AF_INET;
		pkt->proto = ip4->protocol;
		pkt->saddr[0] = ip4->saddr;
		pkt->daddr[0] = ip4->daddr;
		break;
	case ETH_P_IPV6:
		if (!obs_ipv6_enabled())
			return false;
		ip6 = data;
		if ((void *)(ip6 + 1) > data_end)
			return false;
		l4_off = sizeof(*ip6);
		pkt->family = AF_INET6;
		pkt->proto = ip6->nexthdr;
		pkt->saddr[0] = ip6->saddr[0];
		pkt->saddr[1] = ip6->saddr[1];
		pkt->saddr[2] = ip6->saddr[2];
		pkt->saddr[3] = ip6->saddr[3];
		pkt->daddr[0] = ip6->daddr[0];
		pkt->daddr[1] = ip6->daddr[1];
		pkt->daddr[2] = ip6->daddr[2];
		pkt->daddr[3] = ip6->daddr[3];
		break;
	default:
		return false;
	}
	pkt->l4_off = (__u16)l4_off;
	if (pkt->proto == IPPROTO_TCP || pkt->proto == IPPROTO_UDP ||
	    pkt->proto == IPPROTO_SCTP || pkt->proto == IPPROTO_UDPLITE) {
		ports = data + l4_off;
		if ((void *)(ports + 2) > data_end)
			return true;
		pkt->sport = ports[0];
		pkt->dport = ports[1];
	}
	return true;
}

/* Attribute one packet to its socket's owner and peer. */
static __always_inline void obs_net_packet(struct __sk_buff *skb,
					   const struct obs_pkt *pkt,
					   bool egress)
{
	struct obs_sock_meta *meta = 0;
	struct net_entry __arena *e;
	struct net_key key = {};
	struct bpf_sock *sk = skb->sk;
	__u64 now = obs_now();
	int status;

	if (sk)
		meta = bpf_sk_storage_get(&obs_i_sock, sk, 0, 0);
	if (meta) {
		key.ident.exe = meta->exe;
		key.ident.cgroup = meta->cgroup;
		key.role = (__u8)meta->role;
	} else {
		key.ident.cgroup = bpf_skb_cgroup_id(skb);
		if (sk && sk->state == BPF_TCP_LISTEN)
			key.role = OBS_ROLE_LISTENER;
	}
	key.family = pkt->family;
	key.proto = pkt->proto;
	/* Inbound peers aggregate by address; their ports are ephemeral. */
	if (key.role != OBS_ROLE_ACCEPTOR && key.role != OBS_ROLE_LISTENER)
		key.port = bpf_ntohs(egress ? pkt->dport : pkt->sport);
	if (egress) {
		key.addr[0] = pkt->daddr[0];
		key.addr[1] = pkt->daddr[1];
		key.addr[2] = pkt->daddr[2];
		key.addr[3] = pkt->daddr[3];
	} else {
		key.addr[0] = pkt->saddr[0];
		key.addr[1] = pkt->saddr[1];
		key.addr[2] = pkt->saddr[2];
		key.addr[3] = pkt->saddr[3];
	}
	e = net_touch(&key, &status);
	if (e) {
		if (status == OBS_TOUCH_CREATED)
			e->val.first_ns = now;
		if (egress) {
			__sync_fetch_and_add(&e->val.tx_pkts, 1);
			__sync_fetch_and_add(&e->val.tx_bytes, skb->len);
		} else {
			__sync_fetch_and_add(&e->val.rx_pkts, 1);
			__sync_fetch_and_add(&e->val.rx_bytes, skb->len);
		}
		e->val.last_ns = now;
	}
	if (egress)
		obs_watch_packet(&key, skb->len, now);
}
