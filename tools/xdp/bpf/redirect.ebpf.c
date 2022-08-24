// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <linux/bpf.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>

#define section(secname) __attribute__((section(secname), used))

#define REDIRECT_DEFAULT XDP_PASS
#define HTONS_ETH_P_IP 0x8     // This is htons(ETH_P_IP).
#define HTONS_ETH_P_ARP 0x608  // This is htons(ETH_P_ARP).

char __license[] section("license") = "Apache-2.0";

// Helper functions are defined positionally in <linux/bpf.h>, and their
// signatures are scattered throughout the kernel. They can be found via the
// defining macro BPF_CALL_[0-5].
// TODO(b/240191988): Use vmlinux instead of this.
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static int (*bpf_redirect_map)(void *bpf_map, __u32 iface_index,
                               __u64 flags) = (void *)51;

struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
};

// A map of devices to redirect to. We only ever use one key: 0.
struct bpf_map_def section("maps") dev_map = {
    .type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 1,
};

// A map of destination IP addresses that should be redirected. We only ever use
// one key: 0.
struct bpf_map_def section("maps") ip_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

// The end of an IPv4 ARP packet.
struct arphdr_addrs {
  unsigned char sender_hw_addr[ETH_ALEN];
  unsigned char sender_ip_addr[4];
  unsigned char target_hw_addr[ETH_ALEN];
  unsigned char target_ip_addr[4];
};

// TODO(b/240191988): A production version of this program should be heavily
// optimized to maximize throughput.
section("xdp") int xdp_prog(struct xdp_md *ctx) {
  int key = 0;
  void *end = (void *)(uint64_t)ctx->data_end;
  struct ethhdr *eth_hdr = (struct ethhdr *)(uint64_t)ctx->data;
  struct iphdr *ip_hdr;
  struct arphdr *arp_hdr;
  struct arphdr_addrs *arp_hdr_addrs;
  __u32 dest_addr;
  __u32 *map_addr;

  if (eth_hdr + 1 > (struct ethhdr *)end) {
    return REDIRECT_DEFAULT;
  }

  switch (eth_hdr->h_proto) {
    case HTONS_ETH_P_IP:
      ip_hdr = (struct iphdr *)(eth_hdr + 1);
      if (ip_hdr + 1 > (struct iphdr *)end) {
        return REDIRECT_DEFAULT;
      }
      dest_addr = ip_hdr->daddr;
      break;

    case HTONS_ETH_P_ARP:
      arp_hdr = (struct arphdr *)(eth_hdr + 1);
      if (arp_hdr + 1 > (struct arphdr *)end) {
        return REDIRECT_DEFAULT;
      }
      // Only allow IPv4 ARP.
      if (arp_hdr->ar_pro != HTONS_ETH_P_IP) {
        return REDIRECT_DEFAULT;
      }
      arp_hdr_addrs = (struct arphdr_addrs *)(arp_hdr + 1);
      if (arp_hdr_addrs + 1 > (struct arphdr_addrs *)end) {
        return REDIRECT_DEFAULT;
      }
      dest_addr = *(uint32_t *)&arp_hdr_addrs->target_ip_addr;
      break;

    default:
      return REDIRECT_DEFAULT;
  }

  // Get the selected IP.
  map_addr = bpf_map_lookup_elem(&ip_map, &key);
  if (!map_addr) {
    return REDIRECT_DEFAULT;
  }

  // Only redirect if this packet is destined for the selected IP.
  if (*map_addr != dest_addr) {
    return REDIRECT_DEFAULT;
  }

  return bpf_redirect_map(&dev_map, key, REDIRECT_DEFAULT);
}
