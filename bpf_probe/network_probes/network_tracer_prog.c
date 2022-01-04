/* Copyright 2019-2021 VMware Inc.  All rights reserved. */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#define KBUILD_MODNAME "tc_filter"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>

BPF_PERF_OUTPUT(network_events);
BPF_PERF_OUTPUT(ids);

#define EXTRACT_OK                          0
#define EXTRACT_INDEX_OUT_OF_RANGE          1
#define EXTRACT_NOT_SUPPORTED_NEXT_PROTOCOL 2

#define REPORT_EVENT_UNDEFINED 0
#define REPORT_EVENT_INIT      1
#define REPORT_EVENT_CLOSE     2
#define REPORT_EVENT_DATA      3

#define APP_LAYER_TLS_BUT_WAIT -1

#define APP_LAYER_UNKNOWN  0
#define APP_LAYER_PLAIN    1
#define APP_LAYER_HTTP     2

#define APP_LAYER_TLS_1_0  3
#define APP_LAYER_TLS_1_1  4
#define APP_LAYER_TLS_1_2  5
#define APP_LAYER_TLS_1_3  6

#define APP_LAYER_SSH_1    7
#define APP_LAYER_SSH_1_5  8
#define APP_LAYER_SSH_1_99 9
#define APP_LAYER_SSH_2    10
#define APP_LAYER_SSH_UNKNOWN    11

#define APP_LAYER_TELNET   12


#define IDS_FILTERING_FALSE 0
#define IDS_FILTERING_TRUE  1

#define STREAM_NOT_BYPASSED 0
#define STREAM_BYPASSED     1

#define TLS_CONTENT_TYPE_CHANGE_CYPHER_SPEC 20
#define TLS_CONTENT_TYPE_ALERT            21
#define TLS_CONTENT_TYPE_HANDSHAKE        22
#define TLS_CONTENT_TYPE_APPLICATION_DATA 23
#define TLS_EXTENSION_VERSIONS_SUPPORTED  43

#define TLS_VERSION_MAJOR_VALUE 3

#define TLS_VERSION_MINOR_1_0 1
#define TLS_VERSION_MINOR_1_1 2
#define TLS_VERSION_MINOR_1_2 3
#define TLS_VERSION_MINOR_1_3 4

#define TLS_HANDSHAKE_TYPE_HELLO_REQUEST 0
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO  1
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO  2

#define STREAM_HASH_MAP_SIZE 65536
#define MAX_BYTES_PER_STREAM 1048576 // 1MB

#define MAX_HTTP_URI_BYTES 128
#define MAX_TLS_EXTENSIONS_TO_PROCESS 4

struct packet_ctx {
    void *data;
    void *data_end;
    uint64_t next_layer_offset;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    uint8_t *tcp_payload;
} __attribute__((packed));

struct stream {
    uint32_t self_ip;
    uint32_t other_ip;
    uint16_t self_port;
    uint16_t other_port;
    uint8_t direction;
} __attribute__((packed));

struct network_event {
    uint32_t self_ip;
    uint32_t other_ip;
    uint16_t self_port;
    uint16_t other_port;
    uint64_t bytes;
    uint8_t event_type;
    uint8_t app_layer;
    uint8_t direction;
} __attribute__((packed));

struct stream_state {
    uint8_t bypass_state;
    uint8_t app_layer;
    uint32_t packets_count;
    uint64_t bytes_count;
    uint64_t timestamp;
} __attribute__((packed));

struct tlshdr {
    uint8_t content_type;
    uint8_t version_major;
    uint8_t version_minor;
    uint16_t length;
} __attribute__((packed));

struct tls_handshake_hdr {
    uint8_t handshake_type;
	uint8_t length[3];
} __attribute__((packed));

struct tls_server_hello {
	uint16_t version;
	uint8_t random[32];
	uint8_t session_id_length;
} __attribute__((packed));

struct tls_server_hello_after_session {
	uint16_t chosen_cipher_suit;
	uint8_t compression_method;
} __attribute__((packed));

struct tls_extensions_hdr {
	uint16_t type;
	uint16_t length;
} __attribute__((packed));

struct iac {
	uint8_t ff_val;
	uint8_t cmd;
	uint8_t option;
}__attribute__((packed));

enum {
    METRIC_COUNTER_DROPPED_PACKETS = 0,

    NUM_METRIC_COUNTERS // keep last
};

BPF_HASH(streams_hash_map, struct stream, struct stream_state, STREAM_HASH_MAP_SIZE);
BPF_HASH(ids_filtering_hash_map, uint32_t, uint8_t);
BPF_ARRAY(metric_counters, int64_t, NUM_METRIC_COUNTERS);


static inline int extract_eth_hdr(struct packet_ctx *pkt) {
    pkt->eth = pkt->data;
    pkt->next_layer_offset += sizeof(struct ethhdr);
    if (pkt->data + pkt->next_layer_offset > pkt->data_end) {
        return EXTRACT_INDEX_OUT_OF_RANGE;
    }
    uint16_t h_proto = pkt->eth->h_proto;
    // parse double vlans
    #pragma unroll
    for (int i=0; i<2; i++) {
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
            struct vlan_hdr *vhdr;
            vhdr = pkt->data + pkt->next_layer_offset;
            pkt->next_layer_offset += sizeof(struct vlan_hdr);
            if (pkt->data + pkt->next_layer_offset > pkt->data_end) {
                return EXTRACT_INDEX_OUT_OF_RANGE;
            }
            h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }
    return EXTRACT_OK;
}


static inline int extract_ip_hdr(struct packet_ctx *pkt) {
    if (pkt->eth->h_proto != htons(ETH_P_IP)) {
        // bpf_trace_printk("-------> Next protocol is not IP, next is: 0x%x\n", ntohs(h_proto));
        return EXTRACT_NOT_SUPPORTED_NEXT_PROTOCOL;
    }
    if (pkt->data + pkt->next_layer_offset + sizeof(struct iphdr) > pkt->data_end) {
        return EXTRACT_INDEX_OUT_OF_RANGE;
    }
    pkt->iph = pkt->data + pkt->next_layer_offset;
    if ((void*)&pkt->iph[1] > pkt->data_end) {
        return EXTRACT_INDEX_OUT_OF_RANGE;
    }
    pkt->next_layer_offset += (pkt->iph->ihl * 4);
    return EXTRACT_OK;
}


static inline int extract_tcp_hdr(struct packet_ctx *pkt) {
    if (pkt->iph->protocol != IPPROTO_TCP) {
        // bpf_trace_printk("-------> Next protocol is not TCP, next is: 0x%x\n", pkt->iph->protocol);
        return EXTRACT_NOT_SUPPORTED_NEXT_PROTOCOL;
    }
    if (pkt->data + pkt->next_layer_offset + sizeof(struct tcphdr) > pkt->data_end) {
        return EXTRACT_INDEX_OUT_OF_RANGE;
    }
    pkt->tcph = pkt->data + pkt->next_layer_offset;
    if ((void*)&pkt->tcph[1] > pkt->data_end) {
        return EXTRACT_INDEX_OUT_OF_RANGE;
    }
    // bpf_trace_printk("-------> TCP src: %u dst: %u\n", ntohs(pkt->tcph->source), ntohs(pkt->tcph->dest));
    // bpf_trace_printk("-------> TCP data offset: %d\n", pkt->tcph->doff * 4);
    pkt->next_layer_offset += (pkt->tcph->doff * 4);
    pkt->tcp_payload = pkt->data + pkt->next_layer_offset;
    return EXTRACT_OK;
}


static inline int read_tls_extensions(register const uint8_t* payload, register const uint8_t* end, uint16_t *ver) {
    
    #pragma unroll(MAX_TLS_EXTENSIONS_TO_PROCESS)
    for(int i=0; i < MAX_TLS_EXTENSIONS_TO_PROCESS; i++) {

        if (payload + sizeof(struct tls_extensions_hdr) > end) { return 0; }
        struct tls_extensions_hdr *h = payload;
        payload += sizeof(struct tls_extensions_hdr);

        uint16_t l = (uint16_t)bpf_ntohs(h->length);
        if (l > 0x1fff) { return 0; } else {l &= 0x1fff;}
        if (payload + l > end) { return 0; }

        if (bpf_ntohs(h->type) == TLS_EXTENSION_VERSIONS_SUPPORTED) {
            if (payload + sizeof(uint16_t) > end) { return 0; }
            uint16_t v = bpf_ntohs(*(uint16_t*)(payload));
            //bpf_trace_printk("[TLS] EXTENSION VERSION MATCH ! :%x\n", v);
            *ver = v;
            return 1;
        }

        payload += l;
    }

    return 0;
}


static inline int tls_ver_to_app_layer(uint16_t v) {
   int r = APP_LAYER_UNKNOWN;
   switch(v) {
   case 0x0301: r = APP_LAYER_TLS_1_0; break;
   case 0x0302: r = APP_LAYER_TLS_1_1; break;
   case 0x0303: r = APP_LAYER_TLS_1_2; break;
   case 0x0304: r = APP_LAYER_TLS_1_3; break;
   }
   // bpf_trace_printk("TLS V %d\n", r);
   return r;
}


static inline int check_for_tls_hdr(register const uint8_t* payload, register const uint8_t* end) {
   int ret = APP_LAYER_UNKNOWN;

   if (payload + sizeof(struct tlshdr) > end) {
       return ret;
   }
   struct tlshdr *tlsh = payload;

   if (tlsh->content_type < TLS_CONTENT_TYPE_CHANGE_CYPHER_SPEC || 
       tlsh->content_type > TLS_CONTENT_TYPE_APPLICATION_DATA) {
       return ret;
   }

   if (tlsh->version_major != TLS_VERSION_MAJOR_VALUE ||
       tlsh->version_minor < TLS_VERSION_MINOR_1_0 ||
       tlsh->version_minor > TLS_VERSION_MINOR_1_3) {
       return ret;
   }

   register uint64_t off = sizeof(struct tlshdr);

   if (tlsh->content_type == TLS_CONTENT_TYPE_HANDSHAKE) 
   {
       if (payload + off + sizeof(struct tls_handshake_hdr) > end) { return ret; }
       struct tls_handshake_hdr *hs = payload + off;
       off += sizeof(struct tls_handshake_hdr);
       
       if (hs->handshake_type == TLS_HANDSHAKE_TYPE_SERVER_HELLO) {
           //uint32_t len = ntohl((uint32_t)*(&hs->length[0]));
           //if (payload + off + len > end) { return ret; }

           if (payload + off + sizeof(struct tls_server_hello) > end) { return ret; }
           struct tls_server_hello *srv_hello = payload + off;
           off += sizeof(struct tls_server_hello);
           
           if (srv_hello->session_id_length > 32) { return ret; }
           off += srv_hello->session_id_length;
           
           if (payload + off + sizeof(struct tls_server_hello_after_session) > end) { return ret; }
           struct tls_server_hello_after_session *srv_hello_post = payload + off;
           off += sizeof(*srv_hello_post);
           
           // TLS 1.3 claims some extensions are mandatory.
           // We use such extension to differentiate between 1.2 and 1.3
           if (payload + off + sizeof(uint16_t) > end) { return ret; }
           uint16_t extensions_len = bpf_ntohs(*(uint16_t*)(payload + off));
           off += sizeof(extensions_len);

           if (payload + off > end) { return ret; }
           if (extensions_len == 0) { return ret; }
           
           ret = (int)bpf_htons(srv_hello->version);
           uint16_t v = 0;
           int r = read_tls_extensions(payload+off, end, &v);
           if( r == 1 && v != 0) {
               if (v > ret) {ret = v;}
           }

           // bpf_trace_printk("[TLS] Version: %x DETECTED\n", ret);
           ret = tls_ver_to_app_layer(ret);
       }
   }

   return ret;
}


static inline int isdigit(int c) {
    return c >= '0' && c <= '9';
}


static inline int check_for_http_response(register const uint8_t *p, register const uint8_t *end) {
    // 'HTTP/X.Y NNN ' matching
    if (p + 13 > end) {
        return 0;
    }

    // Do the actual matching
    return *p++ == 'H' &&
           *p++ == 'T' &&
           *p++ == 'T' &&
           *p++ == 'P' &&
           *p++ == '/' &&
           isdigit(*p++) &&
           *p++ == '.' &&
           isdigit(*p++) &&
           *p++ == ' ' &&
           isdigit(*p++) &&
           isdigit(*p++) &&
           isdigit(*p++) &&
           *p == ' ';
}


static inline int check_for_http_request(register const uint8_t *p, register const uint8_t *end) {
    // 'METHOD URI HTTP/X.Y' matching

    // Verify that the length is at least as big as the shortest possible HTTP request line
    if (p + 8 > end) { // Longest HTTP verb + 1 " "
        return 0;
    }

    // PHASE 1: Check for an all caps HTTP method name
    // No method name is longer than 7 chars so we don't need further space checks in this phase
    switch (*p++) {
        case 'G': // GET
            if (*p++ == 'E' && *p++ == 'T') {
                break;
            }
            return 0;

        case 'P': // POST, PUT, or PATCH
            switch (*p++) {
                case 'O': // POST
                    if (*p++ == 'S' && *p++ == 'T') {
                        break;
                    }
                    return 0;

                case 'U': // PUT
                    if (*p++ == 'T') {
                        break;
                    }
                    return 0;

                case 'A': // PATCH
                    if (*p++ == 'T' && *p++ == 'C' && *p++ == 'H') {
                        break;
                    }
                    // fallthrough
                default:
                    return 0;
            }
            break;

        case 'H': // HEAD
            if (*p++ == 'E' && *p++ == 'A' && *p++ == 'D') {
                break;
            }
            return 0;

        case 'D': // DELETE
            if (*p++ == 'E' && *p++ == 'L' && *p++ == 'E' && *p++ == 'T' && *p++ == 'E') {
                break;
            }
            return 0;

        case 'O': // OPTIONS
            if (*p++ == 'P' && *p++ == 'T' && *p++ == 'I' && *p++ == 'O' && *p++ == 'N' && *p++ == 'S') {
                break;
            }
            return 0;

        case 'C': // CONNECT
            if (*p++ == 'O' && *p++ == 'N' && *p++ == 'N' && *p++ == 'E' && *p++ == 'C' && *p++ == 'T') {
                break;
            }
            return 0;

        case 'T': // TRACE
            if (*p++ == 'R' && *p++ == 'A' && *p++ == 'C' && *p++ == 'E') {
                break;
            }
            // fallthrough
        default:
            return 0;
    }

    // Verify that the successfully matched method is followed by a space
    if (*p++ != ' ') {
        return 0;
    }
	return 1;
}


static inline int check_for_http_hdr(register const uint8_t* payload, register const uint8_t* end) {
    if (check_for_http_response(payload, end)) { return APP_LAYER_HTTP; }
    if (check_for_http_request(payload, end))  { return APP_LAYER_HTTP; }

    return APP_LAYER_UNKNOWN;
}


static inline int check_for_ssh_hdr(register const uint8_t *payload, register const uint8_t* end) {
  int r = APP_LAYER_UNKNOWN;
  const uint32_t ssh_c = htonl(0x5353482d); // "SSH-" in network byte order
  int64_t off = 0;
  uint8_t *p = payload;
  
  if (payload + sizeof(ssh_c) + 4 > end) { 
      // 4 is placeholder for the SSH version: 
      // possible format are: X.X-  e.g. 1.0-, 1.5-, 2.0- 
      // but version 1.99 also exists! So the - at the end is not guaranteed
      return r; 
  }
  
  if (ssh_c == *(uint32_t*)(p)) {
      // ok looks like SSH connection
      r = APP_LAYER_SSH_UNKNOWN;
      
      p += sizeof(ssh_c);
      off += sizeof(ssh_c);
      
      if (isdigit(*p++) && 
          '.'  == *p++  && 
          isdigit(*p++) &&
          ( isdigit(*p) || ('-' == *p) )
      ) {
          // figure out the ssh protocol version
          uint8_t major_ver = *(uint8_t*)(payload + off);
          uint8_t minor_ver = *(uint8_t*)(payload + off + 2);
          
          if (major_ver == '1' && minor_ver == '0') return APP_LAYER_SSH_1;
          if (major_ver == '1' && minor_ver == '5') return APP_LAYER_SSH_1_5;
          if (major_ver == '1' && minor_ver == '9') return APP_LAYER_SSH_1_99;
          if (major_ver == '2' && minor_ver == '0') return APP_LAYER_SSH_2;
      }
  }
  
  return r;
}


static inline int check_for_telnet(register const uint8_t* payload, register const uint8_t* end) {
  // Telnet has no header. Closest thing is IAC - Interpret As Command
  // Well behaved servers usually start with IAC commands and well behaved 
  // clients usually respond to them. Thus detection will be limited to the 
  // first 3 bytes of the packet.

    int r = APP_LAYER_UNKNOWN;
  
    if (payload + sizeof(struct iac) > end) { return r; }

    struct iac *i = (struct iac*) payload;
    
    if (i->ff_val == 0xffu && i->cmd >=0xF0u && i->cmd < 0xFFu && 
        ( (i->option >= 0u && i->option <= 35u) || (i->option == 0xffu) )
    ) { r = APP_LAYER_TELNET; }

    return r;
}


static inline int get_app_layer(register const uint8_t* payload, register const uint8_t* end) {
    int r = APP_LAYER_UNKNOWN ;
    
    r = check_for_http_hdr(payload, end);
    if (r != APP_LAYER_UNKNOWN) { return r; }

    r = check_for_tls_hdr(payload, end);
    if (r != APP_LAYER_UNKNOWN) { return r; }
    
    r = check_for_telnet(payload, end);
    if (r != APP_LAYER_UNKNOWN) { return r; }
    
    r = check_for_ssh_hdr(payload, end);
    if (r != APP_LAYER_UNKNOWN) { return r; }

    return APP_LAYER_PLAIN;
}

static inline int check_for_ids_filtering(uint32_t self_ip, uint32_t other_ip) {
    uint8_t *is_filtered = ids_filtering_hash_map.lookup(&self_ip);
    if (is_filtered != NULL) {
        return 1;
    }
    is_filtered = ids_filtering_hash_map.lookup(&other_ip);
    if (is_filtered != NULL) {
        return 1;
    }
    return 0;
}


static inline void send_packet(struct stream *s, struct __sk_buff* ctx) {
    ids.perf_submit_skb(ctx, ctx->len, s, sizeof(struct stream));
}


int network_tracer(struct __sk_buff *ctx) {
    int rc = TC_ACT_PIPE;
    int filter_ids = IDSFLAG;
    uint8_t event_type = REPORT_EVENT_UNDEFINED;

    struct packet_ctx pkt = {
        .data = (void*)(long)ctx->data,
        .data_end = (void*)(long)ctx->data_end,
        .next_layer_offset = 0,
        .tcp_payload = NULL
    };

    if (extract_eth_hdr(&pkt) != EXTRACT_OK) {
        return rc;
    }
    if (extract_ip_hdr(&pkt) != EXTRACT_OK) {
        return rc;
    }
    if (extract_tcp_hdr(&pkt) != EXTRACT_OK) {
        return rc;
    }

    struct network_event ne = {
#if STREAM_DIRECTION
        .self_ip = ntohl(pkt.iph->daddr),
        .other_ip = ntohl(pkt.iph->saddr),
        .self_port = ntohs(pkt.tcph->dest),
        .other_port = ntohs(pkt.tcph->source),
#else
        .self_ip = ntohl(pkt.iph->saddr),
        .other_ip = ntohl(pkt.iph->daddr),
        .self_port = ntohs(pkt.tcph->source),
        .other_port = ntohs(pkt.tcph->dest),
#endif
        .direction = STREAM_DIRECTION,
        .bytes = 0,
        .event_type = REPORT_EVENT_UNDEFINED,
        .app_layer = APP_LAYER_UNKNOWN,
    };

    if (pkt.tcph->syn && pkt.tcph->ack) {
        ne.event_type = REPORT_EVENT_INIT;
    }
     
    // TCP close is can be 4 way. Leave as is!
    if (pkt.tcph->fin) {
        ne.event_type = REPORT_EVENT_CLOSE;
    }

    struct stream s = {
        .self_ip = ne.self_ip,
        .other_ip = ne.other_ip,
        .self_port = ne.self_port,
        .other_port = ne.other_port,
        .direction = STREAM_DIRECTION
    };

    struct stream_state initial_sstate = {
        .bypass_state = STREAM_NOT_BYPASSED,
        .app_layer = APP_LAYER_UNKNOWN,
        .packets_count = 0,
        .bytes_count = 0,
        .timestamp = bpf_ktime_get_ns()
    };

	uint8_t data[32];

    struct stream_state *sstate = streams_hash_map.lookup_or_try_init(&s, &initial_sstate);
    if (sstate == NULL) {
        return rc;
    }

	uint16_t iph_len = ntohs(pkt.iph->tot_len);
	uint16_t data_left_as_offset = iph_len + ((void*)pkt.iph - pkt.data);
    uint64_t available_to_read_data_len = (pkt.data_end - pkt.data);
	uint32_t left = data_left_as_offset > pkt.next_layer_offset ? data_left_as_offset - pkt.next_layer_offset : 0;

    uint64_t data_bytes_count = (pkt.data_end - pkt.data) - pkt.next_layer_offset;

	// many kernels provide only 66 bytes of data from the packer in the data:data_end window
	// in order to be able to calculate the actual bytes payload do this weirdness.
	uint64_t real_byte_count = iph_len < ctx->len ? left  : data_bytes_count;

	ne.bytes += real_byte_count;
    
	struct stream_state updated_sstate = *sstate;
    updated_sstate.timestamp = bpf_ktime_get_ns();
    updated_sstate.bytes_count += real_byte_count;
    updated_sstate.packets_count++;

	if (updated_sstate.app_layer <= APP_LAYER_PLAIN) {
	
		if (data_bytes_count == 0) {
			uint32_t sz = 0; 
	
			if (available_to_read_data_len < iph_len && iph_len < ctx->len) {
				// min HTTP response
				if (0 == bpf_skb_load_bytes(ctx, pkt.next_layer_offset, &data[0], 16)) {
					sz = 15;
				}
				// min HTTP request
				else if (0 == bpf_skb_load_bytes(ctx, pkt.next_layer_offset, &data[0], 8)) {
					sz = 7;
				// min TLS, ssh-1.x
				} else if (0 == bpf_skb_load_bytes(ctx, pkt.next_layer_offset, &data[0], 6)) {
					sz = 5;
				// min telnet
				} else if (0 == bpf_skb_load_bytes(ctx, pkt.next_layer_offset, &data[0], 4)) {
					sz = 3;
				} 
	
				updated_sstate.app_layer = get_app_layer(&data[0], &data[sz]);
			}

		} else {
			updated_sstate.app_layer = get_app_layer(pkt.tcp_payload, pkt.data_end);
		}

		//bpf_trace_printk("APP LAYER: %d\n", updated_sstate.app_layer);
	
		if (updated_sstate.app_layer >= APP_LAYER_TLS_1_0 && 
			updated_sstate.app_layer <= APP_LAYER_TLS_1_3 ) 
		{
			updated_sstate.bypass_state = STREAM_BYPASSED;
			metric_counters.increment(METRIC_COUNTER_DROPPED_PACKETS);
		}
	}

    if ((filter_ids == IDS_FILTERING_TRUE) && 
        (updated_sstate.bypass_state == STREAM_NOT_BYPASSED)) {
        if (updated_sstate.bytes_count >= MAX_BYTES_PER_STREAM || check_for_ids_filtering(s.self_ip, s.other_ip)) {
            updated_sstate.bypass_state = STREAM_BYPASSED;
            metric_counters.increment(METRIC_COUNTER_DROPPED_PACKETS);
        } else {
            // bpf_trace_printk("-------> Sending data to userspace. pkt_count: %u bytes_count: %u\n", updated_sstate.packets_count, updated_sstate.bytes_count);
            send_packet(&s, ctx);
        }
    }

    streams_hash_map.update(&s, &updated_sstate);

    if (ne.event_type == REPORT_EVENT_UNDEFINED) {
        ne.app_layer = updated_sstate.app_layer;
        if (ne.app_layer != APP_LAYER_UNKNOWN) {
            ne.event_type = REPORT_EVENT_DATA;
        }
    }

    // bpf_trace_printk("-------> SELF: %u:%u\n", ne.self_ip, ne.self_port);
    // bpf_trace_printk("-------> OTHER: %u:%u\n", ne.other_ip, ne.other_port);
    // bpf_trace_printk("-------> Event: %u\n", ne.event_type);
    // bpf_trace_printk("-------> AppLayer: %u\n", ne.app_layer);

    network_events.perf_submit(ctx, &ne, sizeof(struct network_event));
    return rc;
}
