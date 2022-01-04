/* Copyright 2019-2021 VMware Inc.  All rights reserved. */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */


#define KBUILD_MODNAME "ocatrine_dns_filter"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/udp.h>
#include <bcc/proto.h>

#define MAX_DATA_LENGTH 416

#define LONG_LIMIT 12
#define LONG_LENGTH 32

#define SHORT_LIMIT 3
#define SHORT_LENGTH 8

#define SINGLE_LIMIT 8
#define SINGLE_LENGTH 1

struct packet_data_t {
    unsigned char data[MAX_DATA_LENGTH];
    uint16_t length;
} __attribute__((packed));

BPF_PERF_OUTPUT(dns_events);

struct dns_hdr_t
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} BPF_PACKET_HEADER;


int dns_tracer(struct __sk_buff *ctx) {
    u8 *cursor = 0;
    // Check of ethernet/IP frame.
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if(ethernet->type == ETH_P_IP) {
        // Check for UDP.
        struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
        u16 hlen_bytes = ip->hlen << 2;
        if(ip->nextp == IPPROTO_UDP) {
            // Check for source port 53, DNS answer packet.
            struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));

            if (udp->sport == 53) {
                struct dns_hdr_t *dns_hdr = cursor_advance(cursor, sizeof(*dns_hdr));

                // check for standard query answer with no errors
                if ((dns_hdr->flags >> 11) == 0x10 && (dns_hdr->flags & 0x000F) == 0x00)  {
                    if (dns_hdr->qdcount > 0 && dns_hdr->ancount > 0) {
                        // UDP length value includes the UDP header as well.
                        uint16_t udp_length = udp->length - sizeof(*udp);

                        if (udp_length > 0 && udp_length < MAX_DATA_LENGTH) {
                            int err;
                            struct packet_data_t packet_data = {};
                            packet_data.length = udp_length;
                            u32 data_offset = sizeof(*ethernet) + sizeof(*ip) + sizeof(*udp);
                            void* data_ptr = (void*)packet_data.data;

							// this is a trick needed because bpf_skb_load_bytes() "len"
							// parameter must be fixed for the eBPF verifier to allow it

                            u8 long_count = udp_length / LONG_LENGTH;
                            u8 long_index;

                            #pragma unroll
                            for (long_index = 0; long_index < LONG_LIMIT; long_index++) {
                                if (long_index < long_count) {
                                    err = bpf_skb_load_bytes((const struct __sk_buff*)ctx, data_offset, data_ptr, LONG_LENGTH);
                                    if (err != 0) {
                                        return 3;
                                    }
                                    data_offset += (u32)LONG_LENGTH;
                                    data_ptr += LONG_LENGTH;
                                }
                            }

                            u8 short_count = (udp_length - (long_count * LONG_LENGTH)) / SHORT_LENGTH;
                            u8 short_index;

                            #pragma unroll
                            for (short_index = 0; short_index < SHORT_LIMIT; short_index++) {
                                if (short_index < short_count) {
                                    err = bpf_skb_load_bytes((const struct __sk_buff*)ctx, data_offset, data_ptr, SHORT_LENGTH);
                                    if (err != 0) {
                                        return 3;
                                    }
                                    data_offset += (u32)SHORT_LENGTH;
                                    data_ptr += SHORT_LENGTH;
                                }
                            }

                            u8 single_count = (udp_length - (long_count * LONG_LENGTH) - (short_count * SHORT_LENGTH)) / SINGLE_LENGTH;
                            u8 single_index;

                            #pragma unroll
                            for (single_index = 0; single_index < SINGLE_LIMIT; single_index++) {
                                if (single_index < single_count) {
                                    err = bpf_skb_load_bytes((const struct __sk_buff*)ctx, data_offset, data_ptr, SINGLE_LENGTH);
                                    if (err != 0) {
                                        return 3;
                                    }
                                    data_offset += (u32)SINGLE_LENGTH;
                                    data_ptr += SINGLE_LENGTH;
                                }
                            }

                            dns_events.perf_submit_skb(ctx, ctx->len, &packet_data, sizeof(packet_data));
                        } 
                    }
                }
            }
        }
    }
    return 3;
}
