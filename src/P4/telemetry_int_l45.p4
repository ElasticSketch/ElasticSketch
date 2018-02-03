/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.

 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 * $Id: $
 *
 ******************************************************************************/

#ifdef INT_EP_ENABLE

control process_int_watchlist_{
    if (valid(tcp) or valid(udp) or valid (icmp)){
        apply(int_watchlist);
    }
}

action int_sink_update_intl45_v4() {
    remove_header(intl45_head_header);
    remove_header(intl45_tail_header);
    subtract(ipv4.totalLen, ipv4.totalLen, int_metadata.remove_byte_cnt);
    subtract(int_metadata.l4_len, -1, int_metadata.remove_byte_cnt);
    int_remove_header();
}

action int_sink_update_intl45_v4_udp() {
    int_sink_update_intl45_v4();
#ifdef INT_L4_CHECKSUM_UPDATE
    modify_field(udp.checksum, 0);
#endif
    subtract(udp.length_, udp.length_, int_metadata.remove_byte_cnt);
}

action int_sink_update_intl45_v4_all() {
    int_sink_update_intl45_v4();
    modify_field(ipv4.diffserv, 0x00, INTL45_DIFFSERV_MASK);
}

action int_sink_update_intl45_v4_2() {
    int_sink_update_intl45_v4();
    modify_field(ipv4.diffserv, 0x00, 0x4);
}

action int_sink_update_intl45_v4_3() {
    int_sink_update_intl45_v4();
    modify_field(ipv4.diffserv, 0x00, 0x8);
}

action int_sink_update_intl45_v4_4() {
    int_sink_update_intl45_v4();
    modify_field(ipv4.diffserv, 0x00, 0x10);
}

action int_sink_update_intl45_v4_5() {
    int_sink_update_intl45_v4();
    modify_field(ipv4.diffserv, 0x00, 0x20);
}

action int_sink_update_intl45_v4_6() {
    int_sink_update_intl45_v4();
    modify_field(ipv4.diffserv, 0x00, 0x40);
}

action int_sink_update_intl45_v4_7() {
    int_sink_update_intl45_v4();
    modify_field(ipv4.diffserv, 0x00, 0x80);
}

action int_sink_update_intl45_v4_udp_all() {
    int_sink_update_intl45_v4_udp();
    modify_field(ipv4.diffserv, 0x00, INTL45_DIFFSERV_MASK);
}

action int_sink_update_intl45_v4_udp_2() {
    int_sink_update_intl45_v4_udp();
    modify_field(ipv4.diffserv, 0x00, 0x4);
}

action int_sink_update_intl45_v4_udp_3() {
    int_sink_update_intl45_v4_udp();
    modify_field(ipv4.diffserv, 0x00, 0x8);
}

action int_sink_update_intl45_v4_udp_4() {
    int_sink_update_intl45_v4_udp();
    modify_field(ipv4.diffserv, 0x00, 0x10);
}

action int_sink_update_intl45_v4_udp_5() {
    int_sink_update_intl45_v4_udp();
    modify_field(ipv4.diffserv, 0x00, 0x20);
}

action int_sink_update_intl45_v4_udp_6() {
    int_sink_update_intl45_v4_udp();
    modify_field(ipv4.diffserv, 0x00, 0x40);
}

action int_sink_update_intl45_v4_udp_7() {
    int_sink_update_intl45_v4_udp();
    modify_field(ipv4.diffserv, 0x00, 0x80);
}

table int_terminate {
    // This table is used to update the outer(underlay) headers on int_sink
    // to reflect removal of INT headers
    // 0 => update ipv4 and intl45 headers
    // 1 => update ipv4 and intl45 headers + udp
    reads {
        udp : valid;
    }
    actions {
        int_sink_update_intl45_v4_all;
        int_sink_update_intl45_v4_2;
        int_sink_update_intl45_v4_3;
        int_sink_update_intl45_v4_4;
        int_sink_update_intl45_v4_5;
        int_sink_update_intl45_v4_6;
        int_sink_update_intl45_v4_7;
        int_sink_update_intl45_v4_udp_all;
        int_sink_update_intl45_v4_udp_2;
        int_sink_update_intl45_v4_udp_3;
        int_sink_update_intl45_v4_udp_4;
        int_sink_update_intl45_v4_udp_5;
        int_sink_update_intl45_v4_udp_6;
        int_sink_update_intl45_v4_udp_7;
    }
    size : 2;
}

#endif // INT_EP_ENABLE


#ifdef INT_TRANSIT_ENABLE
action int_update_l45_ipv4() {
    add_to_field(ipv4.totalLen, int_metadata.insert_byte_cnt);
    modify_field(int_metadata.l4_len, int_metadata.insert_byte_cnt);
    add_to_field(intl45_head_header.len, int_metadata.int_hdr_word_len);
}

// aplies at transit to update the outer header
// filll at transit enable
table int_outer_encap {
    reads {
        ipv4 : valid;
    }
    actions {
        int_update_l45_ipv4;
        nop;
    }
    default_action: nop;
    size : 2;
}

action intl45_update_udp(){
    add_to_field(udp.length_, int_metadata.insert_byte_cnt);
#ifdef INT_L4_CHECKSUM_UPDATE
    modify_field(udp.checksum, 0);
#endif
}

// fill at transit_enable
table intl45_update_l4 {
    reads {
        udp.valid : exact;
    }
    actions {
        intl45_update_udp;
        nop;
    }
    size: 2;
}
#endif // INT_TRANSIT_ENABLE

#ifdef INT_EP_ENABLE
action int_add_update_l45_ipv4(int_type, total_words, insert_byte_cnt){
    // INT source
    // Add the INT_L45 shim layer
    add_header(intl45_head_header);
    modify_field(intl45_head_header.int_type, int_type);
    modify_field(intl45_head_header.rsvd0, 0);
    modify_field(intl45_head_header.len, total_words);
    modify_field(intl45_head_header.rsvd1, 0);
    add_to_field(ipv4.totalLen, insert_byte_cnt);
    modify_field(int_metadata.l4_len, insert_byte_cnt);
}

action int_add_update_l45_ipv4_all(int_type, total_words, insert_byte_cnt,
    diffserv_value) {
    int_add_update_l45_ipv4(int_type, total_words, insert_byte_cnt);
    modify_field(ipv4.diffserv, diffserv_value, INTL45_DIFFSERV_MASK);
}
action int_add_update_l45_ipv4_2(int_type, total_words, insert_byte_cnt,
    diffserv_value) {
    int_add_update_l45_ipv4(int_type, total_words, insert_byte_cnt);
    modify_field(ipv4.diffserv, diffserv_value, 0x4);
}
action int_add_update_l45_ipv4_3(int_type, total_words, insert_byte_cnt,
    diffserv_value) {
    int_add_update_l45_ipv4(int_type, total_words, insert_byte_cnt);
    modify_field(ipv4.diffserv, diffserv_value, 0x8);
}
action int_add_update_l45_ipv4_4(int_type, total_words, insert_byte_cnt,
    diffserv_value) {
    int_add_update_l45_ipv4(int_type, total_words, insert_byte_cnt);
    modify_field(ipv4.diffserv, diffserv_value, 0x10);
}
action int_add_update_l45_ipv4_5(int_type, total_words, insert_byte_cnt,
    diffserv_value) {
    int_add_update_l45_ipv4(int_type, total_words, insert_byte_cnt);
    modify_field(ipv4.diffserv, diffserv_value, 0x20);
}
action int_add_update_l45_ipv4_6(int_type, total_words, insert_byte_cnt,
    diffserv_value) {
    int_add_update_l45_ipv4(int_type, total_words, insert_byte_cnt);
    modify_field(ipv4.diffserv, diffserv_value, 0x40);
}
action int_add_update_l45_ipv4_7(int_type, total_words, insert_byte_cnt,
    diffserv_value) {
    int_add_update_l45_ipv4(int_type, total_words, insert_byte_cnt);
    modify_field(ipv4.diffserv, diffserv_value, 0x80);
}

// int_outer_encap runs for not mirrored packets
// only expects tunnel_encap_process_outer to run for erspan mirror pkts
@pragma ignore_table_dependency tunnel_encap_process_outer
// too many exact match table at last stage using all hash bits
@pragma ternary 1
table int_outer_encap {
// This table is applied only if it is decided to add INT info
// as part of source functionality
// updates outer headers, options, IP total len etc.
// int_config_session id :
// ID,                   : add_update_l45
    reads {
        int_metadata.config_session_id : exact;
    }
    actions {
        int_add_update_l45_ipv4_all;
        int_add_update_l45_ipv4_2;
        int_add_update_l45_ipv4_3;
        int_add_update_l45_ipv4_4;
        int_add_update_l45_ipv4_5;
        int_add_update_l45_ipv4_6;
        int_add_update_l45_ipv4_7;
    }
    size : TELEMETRY_CONFIG_SESSIONS;
}

action intl45_add_tail(){
    add_header(intl45_tail_header);
    modify_field(intl45_tail_header.next_proto, l3_metadata.lkp_ip_proto);
    modify_field(intl45_tail_header.rsvd, 0);

// proto.param is set in intl45_proto_param as a work around of a fitting issue
// modify_field(intl45_tail_header.proto_param, l3_metadata.lkp_outer_l4_dport);
}

action intl45_update_udp(insert_byte_cnt){
    intl45_add_tail();
    modify_field(intl45_tail_header.proto_param, udp.dstPort);
    add_to_field(udp.length_, insert_byte_cnt);
#ifdef INT_L4_CHECKSUM_UPDATE
    modify_field(udp.checksum, 0);
#endif
}

action intl45_update_tcp(){
    intl45_add_tail();
    modify_field(intl45_tail_header.proto_param, tcp.dstPort);
}

action intl45_update_icmp(){
    intl45_add_tail();
    modify_field(intl45_tail_header.proto_param, icmp.typeCode);
}

table intl45_update_l4 {
// ip_proto, config_session_id:
// 17,       ID,              : update_udp
// 6,        X ,              : update_tcp
// 1,        X ,              : update_icmp
    reads {
        l3_metadata.lkp_ip_proto       : exact;
        int_metadata.config_session_id : ternary;
    }
    actions {
        intl45_update_udp;
        intl45_update_tcp;
        intl45_update_icmp;
        nop;
    }
    size: TELEMETRY_CONFIG_SESSIONS_AND_L4;
}
#endif // INT_EP_ENABLE

control process_int_outer_encap_ {
    apply(int_outer_encap);
    apply(intl45_update_l4);
}
