#ifdef TELEMETRY_REPORT_ENABLE
header telemetry_report_header_t telemetry_report_header;

#define TELEMETRY_REPORT_NEXT_PROTO_ETHERNET         0
#define TELEMETRY_REPORT_NEXT_PROTO_MOD              1
#define TELEMETRY_REPORT_NEXT_PROTO_SWITCH_LOCAL     2

parser parse_telemetry_report {
    extract(telemetry_report_header);
    return select(latest.next_proto) {
        default : ingress;
        // For deparser only
#if defined(MIRROR_ON_DROP_ENABLE) || defined(TELEMETRY_STATELESS_SUP_ENABLE)
        TELEMETRY_REPORT_NEXT_PROTO_MOD : parse_mirror_on_drop;
#endif // MIRROR_ON_DROP_ENABLE || TELEMETRY_STATELESS_SUP_ENABLE
#ifdef INT_ENABLE
        TELEMETRY_REPORT_NEXT_PROTO_SWITCH_LOCAL : parse_all_int_meta_value_headers;
#endif // INT_ENABLE
#ifdef POSTCARD_ENABLE
        TELEMETRY_REPORT_NEXT_PROTO_SWITCH_LOCAL : parse_postcard_header;
#endif // POSTCARD_ENABLE
    }
}

parser parse_only_inner_ethernet {
    extract(inner_ethernet);
    return ingress;
}

#endif // TELEMETRY_REPORT_ENABLE

#if defined(MIRROR_ON_DROP_ENABLE) || defined(TELEMETRY_STATELESS_SUP_ENABLE)
@pragma pa_no_overlay egress  mirror_on_drop_header.egress_port
@pragma pa_no_overlay egress  mirror_on_drop_header.ingress_port
header mirror_on_drop_header_t mirror_on_drop_header;

parser parse_mirror_on_drop {
    extract(mirror_on_drop_header);
// only for deparser. don't use parse_inner_ethernet as mis-leads the phv-allocation
    return parse_only_inner_ethernet;
}
#endif /* MIRROR_ON_DROP_ENABLE || TELEMETRY_STATELESS_SUP_ENABLE */

#ifdef POSTCARD_ENABLE
header postcard_header_t postcard_header;

parser parse_postcard_header {
    extract(postcard_header);
// only for deparser. don't use parse_inner_ethernet as mis-leads the phv-allocation
    return parse_only_inner_ethernet;
}
#endif // POSTCARD_ENABLE

#ifdef INT_ENABLE

header int_header_t                             int_header;
header int_switch_id_header_t                   int_switch_id_header;
header int_port_ids_header_t                    int_port_ids_header;
header int_q_occupancy_header_t                 int_q_occupancy_header;
header int_ingress_tstamp_header_t              int_ingress_tstamp_header;
header int_egress_tstamp_header_t               int_egress_tstamp_header;

#define INT_TYPE_INT                           0x01
#define INT_TYPE_DIGEST_INT                    0x03

#ifdef INT_L45_ENABLE
#define INT_EXIT_SINK  parse_intl45_ipv4_next
#else
#define INT_EXIT_SINK  parse_inner_ethernet
#endif

// transit egress goes to ingress after this
// transit egress deparser uses all_int_meta to put packet together then ingress
// source egress deparser uses all_int_meta to put packet together
// then rest of headers
// sink ingress loops through the stack and goes through the rest of headers
// sink ingress total_hop_cnt == 0, rest of headers
// sink e2e egress deparser uses all_int_meta to put packet together
// then inner_ethernet
// source ingress, sink egress, sink i2e egress don't reach here
parser parse_int_header {
    extract(int_header);
#ifdef INT_TRANSIT_ENABLE
    set_metadata(int_metadata.insert_byte_cnt, latest.ins_cnt);
    set_metadata(int_metadata.int_hdr_word_len, latest.ins_cnt);
#endif
#ifdef INT_EP_ENABLE
    // allows int_header to go to tphv at ingress
    set_metadata(int_metadata.digest_enb, latest.d);
#endif
    return select (latest.rsvd1, latest.total_hop_cnt) {
        // reserved bits = 0 and total_hop_cnt == 0
        // no int_values are added by upstream
#ifdef INT_EP_ENABLE
        0x000 mask 0xfff: INT_EXIT_SINK;
#endif
#ifdef INT_TRANSIT_ENABLE
        0x000 mask 0xfff: ingress;
#endif // TRANSIT

#ifdef INT_EP_ENABLE
        // parse INT val headers added by upstream devices (total_hop_cnt != 0)
        // reserved bits must be 0
        0x000 mask 0xf00: parse_int_stack;
#endif
        0 mask 0: ingress;
        // never transition to the following state
        default: parse_all_int_meta_value_headers;
    }
}

#ifdef INT_EP_ENABLE

// sink removes the stack in the ingress parser using force shift

// intl45_head_header.len includes the length of stack + head + int_header + tail = 4 words
// The following states remove the stack using states of two types. Level 1 (L1) and Level 2 (L2).
// The force shift value at L1 nodes considers that the length includes that 4 words.
// Here is how the parse states may call each other.
// This uses much fewer states than a loop that removes one word at a time
// L1-16
//   - L2-8
//       - L2-4
//       - L2-3
//       - L2-2
//       - L2-1
//   - L2-4
//   - L2-3
//   - L2-2
//   - L2-1
// L1-8
//   - L2-4
//   - L2-3
//   - L2-2
//   - L2-1
// L1-4
//   - L2-3
//   - L2-2
//   - L2-1

parser parse_int_stack {
    return select(intl45_head_header.len) {
        0x10 mask 0x10    : parse_int_stack_L1_16_1;
        0x08 mask 0x08    : parse_int_stack_L1_8;
        0x04 mask 0x04    : parse_int_stack_L1_4;
        // len is always >=4 because of head, int_header and tail
        default : ingress;
    }
}

// remove 12 * 32 bit as 4 words are meta headers
// split into two states because of limitation in force_shift
@pragma force_shift ingress 192
parser parse_int_stack_L1_16_1{
    return parse_int_stack_L1_16_2;
}

@pragma force_shift ingress 192
parser parse_int_stack_L1_16_2{
    return select(intl45_head_header.len) {
        0x08 mask 0x08    : parse_int_stack_L2_8_1;
        0x04 mask 0x04    : parse_int_stack_L2_4;
        0x03 mask 0x03    : parse_int_stack_L2_3;
        0x02 mask 0x02    : parse_int_stack_L2_2;
        0x01 mask 0x01    : parse_int_stack_L2_1;
        default : INT_EXIT_SINK;
    }
}

// remove 4 * 32 bit as 4 words are meta headers
@pragma force_shift ingress 128
parser parse_int_stack_L1_8{
    return select(intl45_head_header.len) {
        0x04 mask 0x04    : parse_int_stack_L2_4;
        0x03 mask 0x03    : parse_int_stack_L2_3;
        0x02 mask 0x02    : parse_int_stack_L2_2;
        0x01 mask 0x01    : parse_int_stack_L2_1;
        default : INT_EXIT_SINK;
    }
}

// remove nothing as 4 words are meta headers
parser parse_int_stack_L1_4{
    return select(intl45_head_header.len) {
        0x03 mask 0x03    : parse_int_stack_L2_3;
        0x02 mask 0x02    : parse_int_stack_L2_2;
        0x01 mask 0x01    : parse_int_stack_L2_1;
        default : INT_EXIT_SINK;
    }
}

@pragma force_shift ingress 128
// split into two states because of limitation in force_shift
parser parse_int_stack_L2_8_1{
    return parse_int_stack_L2_8_2;
}

@pragma force_shift ingress 128
parser parse_int_stack_L2_8_2{
    return select(intl45_head_header.len) {
        0x04 mask 0x04    : parse_int_stack_L2_4;
        0x03 mask 0x03    : parse_int_stack_L2_3;
        0x02 mask 0x02    : parse_int_stack_L2_2;
        0x01 mask 0x01    : parse_int_stack_L2_1;
        default : INT_EXIT_SINK;
    }
}

@pragma force_shift ingress 128
parser parse_int_stack_L2_4{
    return select(intl45_head_header.len) {
        0x03 mask 0x03    : parse_int_stack_L2_3;
        0x02 mask 0x02    : parse_int_stack_L2_2;
        0x01 mask 0x01    : parse_int_stack_L2_1;
        default : INT_EXIT_SINK;
    }
}

// 3 is to optimize 1 state
@pragma force_shift ingress 96
parser parse_int_stack_L2_3{
    return INT_EXIT_SINK;
}

@pragma force_shift ingress 64
parser parse_int_stack_L2_2{
    return INT_EXIT_SINK;
}

@pragma force_shift ingress 32
parser parse_int_stack_L2_1{
    return INT_EXIT_SINK;
}

#endif // INT_EP_ENABLE

parser parse_all_int_meta_value_headers {
    // bogus state.. just extract all possible int headers in the
    // correct order to build
    // the correct parse graph for deparser (while adding headers)
    extract(int_switch_id_header);
    extract(int_port_ids_header);
    extract(int_q_occupancy_header);
    extract(int_ingress_tstamp_header);
    extract(int_egress_tstamp_header);
#ifdef INT_ENABLE
    // doesn't matter which field to use
    // select is there to make pathes for deparser
    return select(current(0,8)){
        // for source L45 and VXLAN
        0   mask 0 : INT_EXIT_SINK;
        // A path to inner_ethernet for e2e
        default    : parse_only_inner_ethernet;
    }
#endif
}

#ifdef INT_L45_ENABLE
header intl45_head_header_t  intl45_head_header;
header intl45_tail_header_t  intl45_tail_header;

parser parse_intl45_ipv4{
    extract(ipv4);
    return select(latest.fragOffset, latest.ihl, latest.protocol) {
        IP_PROTOCOLS_IPHL_ICMP : parse_intl45_icmp;
        IP_PROTOCOLS_IPHL_TCP  : parse_intl45_tcp;
        IP_PROTOCOLS_IPHL_UDP  : parse_intl45_udp;
        default                : ingress;
    }
}

parser parse_intl45_icmp {
    extract(icmp);
    set_metadata(l3_metadata.lkp_outer_l4_sport, latest.typeCode);

    return parse_intl45_head_header;
}

parser parse_intl45_tcp {
    extract(tcp);
    set_metadata(l3_metadata.lkp_outer_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_outer_l4_dport, latest.dstPort);

    return parse_intl45_head_header;
}

parser parse_intl45_udp {
    extract(udp);
    set_metadata(l3_metadata.lkp_outer_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_outer_l4_dport, latest.dstPort);

    return parse_intl45_head_header;
}

parser parse_intl45_ipv4_next{
    extract(intl45_tail_header);
    return select(latest.next_proto) {
        IP_PROTOCOLS_ICMP : parse_intl45_icmp_next;
        IP_PROTOCOLS_TCP  : parse_intl45_tcp_next;
        IP_PROTOCOLS_UDP  : parse_intl45_udp_next;
        default           : ingress;
    }
}

parser parse_intl45_icmp_next{
    return select(intl45_tail_header.proto_param) {
        0x8200 mask 0xfe00 : parse_set_prio_med;
        0x8400 mask 0xfc00 : parse_set_prio_med;
        0x8800 mask 0xff00 : parse_set_prio_med;
        default: ingress;
    }
}

parser parse_intl45_tcp_next {
    return select(intl45_tail_header.proto_param) {
        TCP_PORT_BGP : parse_set_prio_med;
        TCP_PORT_MSDP : parse_set_prio_med;
        default: ingress;
    }
}

parser parse_intl45_udp_next {
    return select(intl45_tail_header.proto_param) {
#ifdef TELEMETRY_WATCH_INNER_ENABLE
        UDP_PORT_VXLAN : parse_vxlan;
#ifndef GENEVE_DISABLE
        UDP_PORT_GENV : parse_geneve;
#endif
#endif /* TELEMETRY_WATCH_INNER_ENABLE */
#ifdef ADV_FEATURES
        UDP_PORT_ROCE_V2       : parse_roce_v2;
        UDP_PORT_LISP          : parse_lisp;
#endif
        UDP_PORT_BOOTPS        : parse_set_prio_med;
        UDP_PORT_BOOTPC        : parse_set_prio_med;
        UDP_PORT_DHCPV6_CLIENT : parse_set_prio_med;
        UDP_PORT_DHCPV6_SERVER : parse_set_prio_med;
        UDP_PORT_RIP           : parse_set_prio_med;
        UDP_PORT_RIPNG         : parse_set_prio_med;
        UDP_PORT_HSRP          : parse_set_prio_med;
        UDP_PORT_SFLOW         : parse_sflow;
#ifdef BFD_OFFLOAD_ENABLE
        UDP_PORT_BFD_1HOP      : parse_bfd;
        UDP_PORT_BFD_MHOP      : parse_bfd;
        UDP_PORT_BFD_ECHO      : parse_bfd;
#endif
        default                : ingress;
    }
}

parser parse_intl45_head_header{
    extract(intl45_head_header);
    return parse_int_header;
}

#endif // INT_L45_ENABLE

#endif // INT_ENABLE
