// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * kernel-obs.bpf.c -- host observability: exec, network, DNS, listeners,
 * watched destinations, privilege transitions and sensitive file access.
 *
 * The domains live in the neighbouring files and are included here so
 * that every hook shares one arena, one task identity and one serializer
 * output map.  Nothing in this upatch enforces; every hook observes.
 */

#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "decoder.h"
#include "serializer.h"
#include "obs_common.h"

char _license[] SEC("license") = "Dual BSD/GPL";

/*
 * The exporter associates serializers with named maps and libbpf permits
 * one arena per object, so these one-slot views carry the stable map
 * names while every record lives in obs_i_arena.
 */
#define OBS_VIEW(name)						\
	struct {						\
		__uint(type, BPF_MAP_TYPE_ARRAY);		\
		__uint(max_entries, 1);				\
		__type(key, __u32);				\
		__type(value, __u8);				\
	} name SEC(".maps")

OBS_VIEW(exec);
OBS_VIEW(net);
OBS_VIEW(socket);
OBS_VIEW(listen);
OBS_VIEW(watch);
OBS_VIEW(dns);
OBS_VIEW(priv);
OBS_VIEW(file);

#define OBS_DECODER(sym, map_name, src, signal)				\
	const struct decoder_manifest sym SEC(".rodata") = {	\
		.magic = DECODER_MANIFEST_MAGIC,		\
		.version = UPATCH_DECODER_VERSION,		\
		.language = UPATCH_DECODER_LANG_LUA,		\
		.api_version = 1,					\
		.input_format = UPATCH_DECODER_INPUT_MAP_V1,	\
		.export_signal = signal,				\
		.upatch = "kernel-obs",					\
		.map = map_name,					\
		.source = src,						\
		.entrypoint = "decode",					\
	}

OBS_DECODER(exec_decoder, "exec", "decoders/exec.lua",
	    UPATCH_DECODER_EXPORT_LOG);
OBS_DECODER(net_decoder, "net", "decoders/net.lua",
	    UPATCH_DECODER_EXPORT_LOG);
OBS_DECODER(socket_decoder, "socket", "decoders/socket.lua",
	    UPATCH_DECODER_EXPORT_LOG);
OBS_DECODER(listen_decoder, "listen", "decoders/listen.lua",
	    UPATCH_DECODER_EXPORT_LOG);
OBS_DECODER(watch_decoder, "watch", "decoders/watch.lua",
	    UPATCH_DECODER_EXPORT_LOG);
OBS_DECODER(dns_decoder, "dns", "decoders/dns.lua",
	    UPATCH_DECODER_EXPORT_LOG);
OBS_DECODER(priv_decoder, "priv", "decoders/priv.lua",
	    UPATCH_DECODER_EXPORT_LOG);
OBS_DECODER(file_decoder, "file", "decoders/file.lua",
	    UPATCH_DECODER_EXPORT_LOG);
OBS_DECODER(watch_stat_decoder, "watch_stat", "decoders/watch_stat.lua",
	    UPATCH_DECODER_EXPORT_METRIC);

#include "obs_priv.bpf.c"
#include "obs_exec.bpf.c"
#include "obs_net.bpf.c"
#include "obs_dns.bpf.c"
#include "obs_file.bpf.c"

SEC("cgroup_skb/egress")
int track_dns_query(struct __sk_buff *skb)
{
	struct obs_pkt pkt;
	bool parsed = obs_pkt_parse(skb, &pkt);

	if (parsed)
		obs_net_packet(skb, &pkt, true);
	dns_parse_packet(skb, &pkt, parsed, true);
	return 1;
}

SEC("cgroup_skb/ingress")
int track_dns_response(struct __sk_buff *skb)
{
	struct obs_pkt pkt;
	bool parsed = obs_pkt_parse(skb, &pkt);

	if (parsed)
		obs_net_packet(skb, &pkt, false);
	dns_parse_packet(skb, &pkt, parsed, false);
	return 1;
}

/* Runs once right after attachment and sizes every table in the arena. */
SEC("syscall")
int shirudo_test__kernel_obs(void *ctx __attribute__((__unused__)))
{
	__u64 now = obs_now();
	int ret;

	ret = priv_init(now);
	if (!ret)
		ret = exec_init(now);
	if (!ret)
		ret = net_init(now);
	if (!ret)
		ret = socket_init(now);
	if (!ret)
		ret = listen_init(now);
	if (!ret)
		ret = watch_init(now);
	if (!ret)
		ret = dns_init(now);
	if (!ret)
		ret = file_init(now);
	return ret;
}
