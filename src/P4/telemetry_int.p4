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
#ifdef INT_ENABLE

#ifdef INT_L45_ENABLE
#include "telemetry_int_l45.p4"
#endif

header_type int_metadata_t {
    fields {
        // INT transit
        insert_byte_cnt   : 16; // ins_cnt * 4 in 16 bits
        int_hdr_word_len  : 8;  // temp variable to keep ins_cnt but 8 bits
        path_tracking_flow: 1;  // set if valid(int_header)

        // INT endpoint
        source            : 1;  // True for INT source
        sink              : 1;  // True for INT sink
        digest_enb        : 1;  // bridged i2e to show if source adds or sink
                                // received digest and signals if per-flow stful
                                // suppression is enabled
        config_session_id : 8;  // INT config session id
        remove_byte_cnt   : 16;
        bfilter_output    : 2;  // for upstream flow state change detection
        l4_len            : 16;
    }
}
#if defined(INT_L45_ENABLE) && defined(INT_EP_ENABLE)
#ifndef INT_L4_CHECKSUM_UPDATE
// proto_param is only used at parser, so it is safe to alias
@pragma pa_alias ingress int_metadata.remove_byte_cnt intl45_tail_header.proto_param
// int45_tail_header will be removed at ingress
// if compiler doesn't allocate int_tail_header even tphv, we may save by not aliasing 
@pragma pa_alias ingress int_metadata.config_session_id intl45_tail_header.next_proto
#endif // INT_L4_CHECKSUM_UPDATE

// at egress tail header only overlaps its write with last read of config_session_id
// if compiler doesn't allocate the header before it is added we don't need this
@pragma pa_alias egress int_metadata.config_session_id intl45_tail_header.next_proto
#endif // INT_L45_ENABLE && INT_EP_ENABLE

metadata int_metadata_t int_metadata;

#endif // INT_ENABLE

/*******************************************************************************
 INT tables for ingress pipeline
 Identify role (src, transit, or sink)
    src is set by int_watchlist table
    sink is set by int_set_sink table
    transit has nothing at ingress.
        At egress transit runs if valid(int_header) and tables are populated

    If sink,
        removes INT and digest headers and updates outer encap
        if statfull suppression is enabled checkes changes
        send upstream i2e report if stateful or stateless suppress see changes
 ******************************************************************************/


/*******************************************************************************
 INT sink ingress control block process_telemetry_int_sink
 if int_header exists
    update bfilters and detect upstream flow state change (if feature enabled)
    remove INT and digest headers and updates outer encap
*******************************************************************************/

control process_telemetry_int_sink{
#ifdef INT_EP_ENABLE
    // must be done BEFORE digest_terminate
    apply(telemetry_make_upstream_digest);
    apply(int_set_sink) {
        int_sink_enable {
#ifdef TELEMETRY_APX_STFUL_SUP_ENABLE
            if (int_metadata.digest_enb == 1) {
                // Note: cannot let control plane choose default action for
                // bfilter tables as miss action doesn't enable hash module
                process_telemetry_upstream_change();
            }
#endif // TELEMETRY_APX_STFUL_SUP_ENABLE
        }
    }
#endif // INT_EP_ENABLE
}

#ifdef INT_EP_ENABLE

action int_remove_header() {
    // remove all INT information from the packet
    // max 24 headers are supported
    // in tofino asic parser removes the stack
    remove_header(int_header);
#ifdef BMV2TOFINO
    remove_header(int_val[0]);
    remove_header(int_val[1]);
    remove_header(int_val[2]);
    remove_header(int_val[3]);
    remove_header(int_val[4]);
    remove_header(int_val[5]);
    remove_header(int_val[6]);
    remove_header(int_val[7]);
    remove_header(int_val[8]);
    remove_header(int_val[9]);
    remove_header(int_val[10]);
    remove_header(int_val[11]);
    remove_header(int_val[12]);
    remove_header(int_val[13]);
    remove_header(int_val[14]);
    remove_header(int_val[15]);
    remove_header(int_val[16]);
    remove_header(int_val[17]);
    remove_header(int_val[18]);
    remove_header(int_val[19]);
    remove_header(int_val[20]);
    remove_header(int_val[21]);
    remove_header(int_val[22]);
    remove_header(int_val[23]);
#endif
}

action int_sink_enable() {
    modify_field(int_metadata.sink, 1);
    
    // convert the word len to byte_cnt (relies on rsvd to be 0 before len)
#ifdef INT_L45_ENABLE
    shift_left(int_metadata.remove_byte_cnt, intl45_head_header.len, 2);
#endif
}

action int_sink_disable() {
    modify_field(int_metadata.sink, 0);

    // convert the word len to byte_cnt (relies on rsvd to be 0 before len)
#ifdef INT_L45_ENABLE
    shift_left(int_metadata.remove_byte_cnt, intl45_head_header.len, 2);
#endif
}

// set default action to int_sink  if sink is enabled
@pragma command_line --parse-state-merge False
table int_set_sink {
    reads{
        int_header : valid;
    }
    actions {
        int_sink_enable;
        int_sink_disable;
    }
#ifndef BMV2TOFINO
    default_action: int_sink_disable;
#endif
    size : 2;
}

/* hash functions to generate 16-bit digests for bloom filters*/
field_list telemetry_upstream_flow_digest {
    telemetry_flow_hash_field;
    int_header.rsvd2_digest;
}

field_list_calculation telemetry_upstream_flow_digest_calc {
    input { telemetry_upstream_flow_digest; }
#if defined(__TARGET_TOFINO__) && !defined(BMV2TOFINO)
    algorithm : crc_16_teledisk;
#else
    algorithm : crc16;
#endif
    output_width : TELEMETRY_DIGEST_WIDTH;
}

// make path+latency digests to store in the filter
action make_upstream_digest() {
    modify_field_with_hash_based_offset(
        int_header.rsvd2_digest, 0,
        telemetry_upstream_flow_digest_calc, TELEMETRY_DIGEST_RANGE);
}

table telemetry_make_upstream_digest {
    actions { make_upstream_digest; }
}

#endif // INT_EP_ENABLE

/*******************************************************************************
 INT sink ingress control block process_telemetry_int_upstream_report
 Send upstream report if upstream flow state change or queue alert detected
 ******************************************************************************/

control process_telemetry_int_upstream_report {
#ifdef INT_EP_ENABLE
    // this should be invoked after acl_mirror
    // favor existing acl mirror session over int mirror
    // moving to before acls, pushes those tables down to
    // after bloom filters and int_upstream_report which uses more stages
    if (i2e_metadata.mirror_session_id == 0 and int_metadata.sink == 1) {
        apply(int_upstream_report);
    }
    if (valid(int_header)){
        apply(int_terminate); // varies per encap
    }
#endif // INT_EP_ENABLE
}

#ifdef INT_EP_ENABLE

field_list int_i2e_mirror_info {
    int_metadata.sink;
    i2e_metadata.mirror_session_id;
    i2e_metadata.ingress_tstamp;
    telemetry_md.dscp_report;
//    hash_metadata.entropy_hash;
}

// control plane shift_left user dscp (6b) by 2 bits for action param (8b)
// the 2 lsb bits are unused
action int_send_to_monitor_i2e (dscp_report) {
    // send the upstream INT information to the
    // pre-processor/monitor. This is done via mirroring
    modify_field(
        i2e_metadata.mirror_session_id, telemetry_md.mirror_session_id);
    modify_field(i2e_metadata.ingress_tstamp, _ingress_global_tstamp_);
    modify_field(telemetry_md.dscp_report, dscp_report);

    clone_ingress_pkt_to_egress(
        telemetry_md.mirror_session_id, int_i2e_mirror_info);
}

// applies to source but not sink 1hop
// watchlist runs at source, int_upstream_report at sink
@pragma ignore_table_dependency int_watchlist
table int_upstream_report {
// priority is set by control plane higher dscp lower priority value
// digest, bfilter, TCP:
//// IF STFUL ENABLED (compile time at sink)
// 0,      xx,      x  : i2e (no stful suppress)
// 1,      1x,      x  : i2e (new flow)
// 1,      00,      x  : i2e (flow change)
//// ELSE
//  ,        ,      x  : i2e
//// END
// x,      xx,      outer TCP & Flags : i2e
// x,      xx,      inner TCP & Flags : i2e

    reads {
#ifdef TELEMETRY_APX_STFUL_SUP_ENABLE
        int_metadata.digest_enb                : ternary;
        int_metadata.bfilter_output            : ternary;
#endif // SUPPRESS

        tcp.valid                              : ternary;
        tcp.flags mask 0x7                     : ternary;
#ifdef TELEMETRY_WATCH_INNER_ENABLE
        inner_tcp_info.flags mask 0x7          : ternary;
        inner_tcp_info.valid                   : ternary;
#endif
    }
    actions {
        int_send_to_monitor_i2e;
        nop;
    }
#ifndef BMV2TOFINO
    default_action : nop;
#endif
    size : 65;  // 6 bit dscp
}
#endif // INT_EP_ENABLE

/*******************************************************************************
 INT source ingress control block process_telemetry_int_watchlist
 ******************************************************************************/

#ifdef INT_EP_ENABLE
control process_telemetry_int_watchlist {
    if (int_metadata.sink == 0){
        // don't apply watchlist on downstream int packets
        // avoid setting source and change digest_enb
        process_int_watchlist_(); // varies per encap
    }
}

// At source, samples if the packet will be monitored
// 100% all flows, use int_not_watch for 0%
action int_watch_sample(digest_enb, config_session_id, sample_index){
    telemetry_int_source_sample_alu.execute_stateful_alu(
        sample_index);
    modify_field(int_metadata.digest_enb, digest_enb);
    modify_field(int_metadata.config_session_id, config_session_id);
}

action int_not_watch() {
    modify_field(int_metadata.source, 0);
    modify_field(int_metadata.digest_enb, 0);
    modify_field(int_metadata.config_session_id, 0);
}

// int_watchlist alwasy overwrites digest_enb if it hits.
// Thus we expect consistent table entries including sample rate
// between source and sink.
// entry with priority 0 can be there just to disable int source
// watchlist runs at source, int_upstream_report at sink
@pragma ignore_table_dependency int_upstream_report
table int_watchlist {
    reads {
        TELEMETRY_FLOW_WATCHLIST
#ifdef TELEMETRY_WATCH_INNER_ENABLE
        TELEMETRY_INNERFLOW_WATCHLIST
#endif
    }
    actions {
        int_watch_sample;
        int_not_watch;
    }
    size : TELEMETRY_WATCHLIST_TABLE_SIZE;
}

register telemetry_int_sample_rate {
    width : 32;
    instance_count : 4096; // 1 sram block
}

blackbox stateful_alu telemetry_int_source_sample_alu{
    reg: telemetry_int_sample_rate;
    condition_lo:  telemetry_md.flow_hash <= register_lo;
    output_predicate: condition_lo;
    output_value: combined_predicate;
    output_dst: int_metadata.source;
}
#endif // INT_EP_ENABLE

#ifdef INT_TRANSIT_ENABLE
control process_telemetry_int_watchlist {
#if defined(MIRROR_ON_DROP_ENABLE) || \
    defined(TELEMETRY_STATELESS_SUP_ENABLE)
    if (valid(int_header)) {
        apply(transit_path_tracking_flow);
    }
#endif // MIRROR_ON_DROP_ENABLE || TELEMETRY_STATELESS_SUP_ENABLE
}

#if defined(MIRROR_ON_DROP_ENABLE) || \
    defined(TELEMETRY_STATELESS_SUP_ENABLE)
action set_transit_path_tracking_flow() {
    modify_field(int_metadata.path_tracking_flow, 1);
}

table transit_path_tracking_flow {
    actions {
        set_transit_path_tracking_flow;
    }
}
#endif // MIRROR_ON_DROP_ENABLE || TELEMETRY_STATELESS_SUP_ENABLE
#endif // INT_TRANSIT_ENABLE

/*******************************************************************************
 INT tables for egress pipeline
 If src/transit
    prepare INT switch data (eg. quantize and digest)
    insert INT data, update meta header
    if digest_enable, also insert/update digest encondings
    update outer encap
 If sink, original pkt
    if local_latency changes or not suppress,
        clone e2e mirror for sink local report
 If sink i2e mirrored (upstream report)
    encap erspan_t3 (via mirroring & tunnel)
    update erspan ft_d_other in int_outer_encap
 If sink e2e mirrored (local report)
    add INT hdrs and stack of local info
    encap erspan_t3 (via mirroring & tunnel)
    update erspan ft_d_other and ip len in int_outer_encap
 ******************************************************************************/

/*******************************************************************************
 Egress control block process_telemetry_local_report_
 This only runs for not mirrored packets at sink
    If stateless suppress (moved to switch.p4 to push its table to stage 0)
        check the thresold
    if statefull suppress
        quantize latency
        compute digest and apply bloom filter
    generate local report through e2e according to suppress and upstream report
 ******************************************************************************/

#ifdef INT_ENABLE
control process_telemetry_local_report1_ {
#ifdef INT_EP_ENABLE
    if(int_metadata.source == 1) {
        apply(int_sink_ports); // check if local 1hop sink
    }
#endif // EP
}

control process_telemetry_local_report2_ {
#if defined(INT_TRANSIT_ENABLE) && \
    defined(TELEMETRY_STATELESS_SUP_ENABLE)
    if (telemetry_md.queue_alert == 1){
        apply(int_transit_qalert);
    }
#endif // TRANSIT && STLESS
#ifdef INT_EP_ENABLE

#ifdef TELEMETRY_APX_STFUL_SUP_ENABLE
    // do it only if sink is enabled to not contaminate bloom filters
    if (int_metadata.sink == 1 and int_metadata.digest_enb == 1) {
        process_telemetry_detect_local_change();
    }
#endif // SUPPRESS

    // sink normal, do e2e clone
    // mirror_session_id can be overwritten by egress_acl later
    apply(int_sink_local_report);

#endif // INT_EP_ENABLE
}
#endif // INT_ENABLE

#ifdef INT_TRANSIT_ENABLE
field_list qalert_mirror_info {
    i2e_metadata.mirror_session_id;
    ingress_metadata.ingress_port;
    egress_metadata.egress_port;
    ig_intr_md_for_tm.qid;
    eg_intr_md.deq_qdepth;
    i2e_metadata.ingress_tstamp;
    eg_intr_md_from_parser_aux.egress_global_tstamp;
    telemetry_md.dscp_report;
    telemetry_md.queue_alert;
    int_metadata.path_tracking_flow;
//    hash_metadata.entropy_hash;
}

action do_int_transit_qalert_set_flow (dscp_report, path_tracking_flow){
    modify_field(int_metadata.path_tracking_flow, path_tracking_flow);
    // send the qalert information to the pre-processor/monitor, via mirroring
    modify_field(
        i2e_metadata.mirror_session_id, telemetry_md.mirror_session_id);
    modify_field(telemetry_md.dscp_report, dscp_report);
    clone_egress_pkt_to_egress(
        telemetry_md.mirror_session_id, qalert_mirror_info);
}

// int_transit_qalert is not for mirrored packets but
// telemetry_x_port_convert is only for mirrored
@pragma ignore_table_dependency telemetry_ig_port_convert
@pragma ignore_table_dependency telemetry_eg_port_convert
table int_transit_qalert {
    reads {
        int_header.valid           : exact;
    }
    actions{
        do_int_transit_qalert_set_flow;
    }
    default_action: do_int_transit_qalert_set_flow;
    size: 2;
}
#endif // INT_TRANSIT_ENABLE

#ifdef INT_EP_ENABLE

field_list int_e2e_mirror_info {
    i2e_metadata.mirror_session_id;
    int_metadata.sink;
    int_metadata.source;
    ingress_metadata.ingress_port;
    egress_metadata.egress_port;
    ig_intr_md_for_tm.qid;
    eg_intr_md.deq_qdepth;
    i2e_metadata.ingress_tstamp;
    eg_intr_md_from_parser_aux.egress_global_tstamp;
    telemetry_md.dscp_report;
    telemetry_md.queue_alert;
//    hash_metadata.entropy_hash;
}

// control plane shift_left user dscp (6b) by 2 bits for action param (8b)
// the lowest bit shows if the packet reported because of INT
// check int_report_encap
action int_send_to_monitor_e2e (dscp_report) {
    modify_field(telemetry_md.dscp_report, dscp_report);
    // send the upstream INT information to the
    // pre-processor/monitor. This is done via mirroring
    modify_field(
        i2e_metadata.mirror_session_id, telemetry_md.mirror_session_id);
    clone_egress_pkt_to_egress(
        telemetry_md.mirror_session_id, int_e2e_mirror_info);
}

// int_sink_local_report sets mirror_session_id for not mirrored packets
// but tunnel_encap_process_outer reads mirror_session_id for mirrored packets
// for erspan_id.span_id
@pragma ignore_table_dependency tunnel_encap_process_outer
// int_sink_local_report only runs for not mirrored ones
// the following tables run only for mirrored packets,
@pragma ignore_table_dependency int_report_encap
@pragma ignore_table_dependency telemetry_ig_port_convert
@pragma ignore_table_dependency telemetry_eg_port_convert
table int_sink_local_report {
// priority is set by control plane higher dscp lower priority value
// sink can be 0 for qalert on non-int packets
// TCP will apply to INT packets and get frame type of INT
// sink, digest, bfilter, alert, TCP:
//// IF STATEFUL ENABLED (compile time at sink)
// 1,    0,      xx,      x,     x  : report all
// 1,    1,      1x,      x,     x  : new flow
// 1,    1,      00,      x,     x  : flow change
//// ELSE
// 1,    x,      xx,      x,     x  : report all
//// ENDIF
//// IF STATELESS ENABLED (compile time at sink) 
// x,    x,      xx,      1,     x  : qalert
//// ENDIF
// 1,    x,      xx,      x,     inner & flag  : tcp
// 1,    x,      xx,      x,     outer & flag  : tcp
    reads {
        int_metadata.sink                      : ternary;
#ifdef TELEMETRY_APX_STFUL_SUP_ENABLE
        int_metadata.digest_enb                : ternary;
        telemetry_md.bfilter_output            : ternary;
#endif // SUPPRESS

#ifdef TELEMETRY_STATELESS_SUP_ENABLE
        telemetry_md.queue_alert               : ternary;
#endif // STATELESS
        tcp.valid                              : ternary;
        tcp.flags mask 0x7                     : ternary;
#ifdef TELEMETRY_WATCH_INNER_ENABLE
        inner_tcp_info.flags mask 0x7          : ternary;
        inner_tcp_info.valid                   : ternary;
#endif
    }
    actions {
        int_send_to_monitor_e2e;
        nop;
    }
    size : 65; // dscp is 6 bits
}

action set_int_sink() {
    modify_field(int_metadata.sink, 1);
}

table int_sink_ports {
    reads {
        eg_intr_md.egress_port : exact;
    }
    actions {
        set_int_sink;
        nop;
    }
    size: 256;
}

#endif // INT_EP_ENABLE

/******************************************************************************
 control block process_telemetry_insert_
 1) at source and e2e adds INT meta header and stack
 2) at source adds INT SUPPRESS digest
 3) at transit updates INT meta header, stack and digest
 ******************************************************************************/

//common for Source and Transit
#ifdef INT_ENABLE

control process_telemetry_insert_ {
#ifdef INT_TRANSIT_ENABLE
    if (valid(int_header)){
        //  max_hop_cnt > total_hop_cnt
        if (int_header.max_hop_cnt != int_header.total_hop_cnt
                and int_header.e == 0){
            apply(int_transit);
#ifdef INT_DIGEST_ENABLE
            // assumes quantize_latency ran before (in local_report)
            apply(int_digest_encode);
#endif // INT_DIGEST_ENABLE
            apply(int_inst_0003);
            apply(int_inst_0407);
            // Later more int_hop_metadata_update when
            // longer table chains are compiled more efficiently
        } else {
            apply(int_meta_header_update_end);
        }
    }
#endif // INT_TRANSIT_ENABLE

#ifdef INT_EP_ENABLE
    // int source
    if (int_metadata.sink == 0 and int_metadata.source == 1){
        apply(int_insert);
#ifdef INT_DIGEST_ENABLE
        if (int_metadata.digest_enb == 1){
            // assumes quantize_latency ran before (in local_report)
            apply(int_digest_insert);
        }
#endif // INT_DIGEST_ENABLE
        apply(int_inst_0003);
        apply(int_inst_0407);
        // Later move int_hop_metadata_update when
        // longer table chains are compiled more efficiently
    }
#endif // INT_EP_ENABLE
}

control process_telemetry_insert_2_ {
#ifdef INT_TRANSIT_ENABLE
    if (valid(int_header) and int_header.e == 0){
        int_hop_metadata_update();
        process_int_outer_encap_(); // varies per encap
    }
#endif
#ifdef INT_EP_ENABLE
    if (int_metadata.source == 1 and int_metadata.sink == 0){
        int_hop_metadata_update();
        process_int_outer_encap_(); // varies per encap
    }
#endif // INT_EP_ENABLE
}

control int_hop_metadata_update {
    if(valid(int_switch_id_header)) {
        apply(int_switch_id);
    }
    if (valid(int_port_ids_header)){
        apply(telemetry_int_eg_port_convert);
        apply(telemetry_int_ig_port_convert);
    }
}

/*******************************************************************************
 Switch h/w port to front panel port conversion
 ******************************************************************************/

action int_ig_port_convert(port) {
    modify_field(int_port_ids_header.ingress_port_id, port);
}

@pragma ignore_table_dependency int_report_encap
// Trade-off 1 TCAM with SRAM+hash bits
@pragma ternary 1
table telemetry_int_ig_port_convert {
    reads {
        int_port_ids_header.ingress_port_id : exact;
    }
    actions {
        int_ig_port_convert;
        nop;
    }
    size: PORTMAP_TABLE_SIZE;
}

action int_eg_port_convert(port) {
    modify_field(int_port_ids_header.egress_port_id, port);
}

@pragma ignore_table_dependency int_report_encap
// Trade-off 1 TCAM with SRAM+hash bits
@pragma ternary 1
table telemetry_int_eg_port_convert {
    reads {
        int_port_ids_header.egress_port_id : exact;
    }
    actions {
        int_eg_port_convert;
        nop;
    }
    size: PORTMAP_TABLE_SIZE;
}

@pragma ignore_table_dependency int_report_encap
table int_switch_id {
    actions { int_switch_id_set; }
    size:1;
}

action int_switch_id_set(switch_id) {
    modify_field(int_switch_id_header.switch_id, switch_id);
}

// used at source and transit to update the digest
field_list telemetry_int_digest_fields {
    telemetry_md.quantized_latency;
    ingress_metadata.ingress_port;
    eg_intr_md.egress_port;
    int_header.rsvd2_digest;
}

field_list_calculation telemetry_int_digest_calc {
    input { telemetry_int_digest_fields; }
    algorithm : crc16;
    output_width : 16;
}

action update_int_digest() {
    modify_field(int_header.d, 1);
    modify_field_with_hash_based_offset(
        int_header.rsvd2_digest, 0, telemetry_int_digest_calc, 65536);
}

action digest_debug_dummy_action(v){
    // bit_and(int_header.rsvd2_digest, int_header.rsvd2_digest, 0xffff);
    modify_field(telemetry_md.quantized_latency, v);
}
#endif // INT_ENABLE

#ifdef INT_TRANSIT_ENABLE

// add action update_int_digest_header at transit enable
// calculating hash requires a table hit so needs a read
table int_digest_encode {
    reads {
        int_header.d: exact;
    }
    actions {
        update_int_digest;
        nop;
    }
#ifndef BMV2TOFINO
    default_action: nop;
#endif
    size : 2;
}

action adjust_insert_byte_cnt() {
    // assumes all int instructions are 4 bytes.
    // At transit insert_byte_cnt doesn't include int_header & digest_header
    shift_left(int_metadata.insert_byte_cnt, int_metadata.insert_byte_cnt, 2);
}

// set default action to adjust_insert_byte_cnt if transit is enabled
table int_transit {
    actions {
        adjust_insert_byte_cnt;
        nop;
    }
#ifndef BMV2TOFINO
    default_action: nop;
#endif
    size : 1;
}

action int_set_e_bit() {
    modify_field(int_header.e, 1);
}

// set default action to int_set_e_bit if transit enabled
table int_meta_header_update_end {
    actions {
        int_set_e_bit;
        nop;
    }
#ifndef BMV2TOFINO
    default_action: nop;
#endif
    size : 1;
}
#endif  // INT_TRANSIT_ENABLE

#ifdef INT_EP_ENABLE

table int_digest_insert {
    actions {update_int_digest;}
}

// assumes hop_cnt > 0
action add_int_header(hop_cnt, ins_cnt, ins_bitmap_0003, ins_bitmap_0407) {
    add_header(int_header);
    modify_field(int_header.ver, 0);
    modify_field(int_header.rep, 0);
    modify_field(int_header.c, 0);
    modify_field(int_header.e, 0);
    modify_field(int_header.d, 0);
    modify_field(int_header.rsvd1, 0);
    modify_field(int_header.ins_cnt, ins_cnt);
    modify_field(int_header.max_hop_cnt, hop_cnt);
    modify_field(int_header.total_hop_cnt, 1);
    modify_field(int_header.instruction_bitmap_0003, ins_bitmap_0003);
    modify_field(int_header.instruction_bitmap_0407, ins_bitmap_0407);
    modify_field(int_header.instruction_bitmap_0811, 0); // not supported
    modify_field(int_header.instruction_bitmap_1215, 0); // not supported
    modify_field(int_header.rsvd2_digest, 0);
}

// It is either INT E2E or MoD
@pragma ignore_table_dependency mirror_on_drop_encap
table int_insert {
    reads {
        int_metadata.config_session_id : exact;
    }
    actions {
        add_int_header;
    }
    default_action: add_int_header(8, 5, 0xd, 0xc);
    size : TELEMETRY_CONFIG_SESSIONS;
}

#endif  // INT_EP_ENABLE

/*******************************************************************************
 control block process_int_outer_encap
 1) updates the outer encapsulation of INT for source, transit, i2e, e2e
 ******************************************************************************/

#ifdef INT_ENABLE

action int_update_outer_encap_common(insert_byte_cnt, udp_port,
                                     path_tracking_flow, congested_queue,
                                     hw_id){
    modify_field(telemetry_report_header.path_tracking_flow,
                 path_tracking_flow);
    modify_field(telemetry_report_header.congested_queue,
                 congested_queue);
    modify_field(telemetry_report_header.hw_id, hw_id);
    modify_field(udp.dstPort, udp_port);
    add_to_field(udp.length_, insert_byte_cnt);
    add_to_field(ipv4.totalLen, insert_byte_cnt);
    modify_field(ipv4.diffserv, telemetry_md.dscp_report, 0xfc);
}

action int_update_outer_encap(insert_byte_cnt, udp_port, path_tracking_flow,
                              congested_queue, hw_id){
    modify_field(telemetry_report_header.next_proto,
                 TELEMETRY_REPORT_NEXT_PROTO_ETHERNET);
    int_update_outer_encap_common(insert_byte_cnt, udp_port,
                                  path_tracking_flow, congested_queue, hw_id);
}

action int_e2e(insert_byte_cnt, switch_id, udp_port, path_tracking_flow,
               congested_queue, hw_id){
    add_header(int_switch_id_header);
    modify_field(int_switch_id_header.switch_id, switch_id);
    int_set_header_1();
    int_set_header_2();
    int_set_header_3();
    int_set_header_5();
    modify_field(telemetry_report_header.next_proto,
                 TELEMETRY_REPORT_NEXT_PROTO_SWITCH_LOCAL);
    int_update_outer_encap_common(insert_byte_cnt, udp_port,
                                  path_tracking_flow, congested_queue, hw_id);
}

#ifdef INT_TRANSIT_ENABLE

// report encap is only for mirror copy,
// telemetry_int_x_port_convert is for regular packets
@pragma ignore_table_dependency telemetry_int_ig_port_convert
@pragma ignore_table_dependency telemetry_int_eg_port_convert
@pragma ignore_table_dependency int_switch_id
@pragma ignore_table_dependency int_inst_0407
@pragma ignore_table_dependency int_inst_0003
table int_report_encap {
// p_t_flow, qalert
// 0,        0       : nop
// 1,        0       : nop, int transit only generates report on qalert or mod
// 0,        1       : int_e2e (path_tracking_flow=0, congested_queue=1)
// 1,        1       : int_e2e (path_tracking_flow=1, congested_queue=1)
    reads {
        int_metadata.path_tracking_flow  : exact;
        telemetry_md.queue_alert         : exact;
    }
    actions {
        int_e2e;
        nop;
    }
    size : 4;
}
#endif // INT_TRANSIT_ENABLE

#ifdef INT_EP_ENABLE
// used in encap files

// int_report_encap is for mirrored packets others are not
@pragma ignore_table_dependency int_sink_local_report
@pragma ignore_table_dependency telemetry_int_ig_port_convert
@pragma ignore_table_dependency telemetry_int_eg_port_convert
@pragma ignore_table_dependency int_switch_id
@pragma ignore_table_dependency int_inst_0407
@pragma ignore_table_dependency int_inst_0003
table int_report_encap {
// priority is not important
// sink, src, clone, qalert
// 1,    0,   1      0      : int_update_outer_encap (p_t_flow=1, con_queue=0)
// 0,    0,   3      1      : int_e2e (path_tracking_flow=0, congested_queue=1)
// 0,    1,   3      1      : int_e2e (path_tracking_flow=1, congested_queue=1)
// 1,    x,   3      0      : int_e2e (path_tracking_flow=1, congested_queue=0)
// 1,    x,   3      1      : int_e2e (path_tracking_flow=1, congested_queue=1)
    reads {
        int_metadata.sink                    : ternary;
        int_metadata.source                  : ternary;
        eg_intr_md_from_parser_aux.clone_src : exact;
#ifdef TELEMETRY_STATELESS_SUP_ENABLE
        telemetry_md.queue_alert             : exact;
#endif // TELEMETRY_STATELESS_SUP_ENABLE
    }
    actions {
        int_update_outer_encap;
        int_e2e;
        nop;
    }
    size : 8;
}

#endif // INT_EP_ENABLE

control process_telemetry_report_encap_ {
#if defined(INT_EP_ENABLE) || \
    (defined(INT_TRANSIT_ENABLE) && defined(TELEMETRY_STATELESS_SUP_ENABLE))
    apply(int_report_encap);
#endif // TRANSIT && STATELESS || EP
}

#endif // INT_ENABLE

/*******************************************************************************
 Tables and actions for INT metadata update, used at egress
 ******************************************************************************/

#ifdef INT_ENABLE
/*
 * INT instruction decode
 * 4 tables, each look at 4 bits of insturction
 * BOS table to set the bottom-of-stack bit on the last INT data
 */

/* Instr Bit 0: switch id */
action int_set_header_0() {
    add_header(int_switch_id_header);
}

/* Instr Bit 1: ingress and egress port ids */
action int_set_header_1() {
    add_header(int_port_ids_header);
    modify_field(
        int_port_ids_header.ingress_port_id, ingress_metadata.ingress_port);
    modify_field(
        int_port_ids_header.egress_port_id, egress_metadata.egress_port);
}

/* Instr Bit 2: hop latency */
action int_set_header_2() {
    //add_header(int_hop_latency_header);
    // hop_latency: timedelta in nanoseconds
    //modify_field(int_hop_latency_header.hop_latency,
    //             eg_intr_md.deq_timedelta);
}

/* Instr Bit 3: qid and queue occupancy */
action int_set_header_3() {
    add_header(int_q_occupancy_header);
    //modify_field(int_q_occupancy_header.rsvd, 0);
    modify_field(int_q_occupancy_header.qid, ig_intr_md_for_tm.qid);
    modify_field(int_q_occupancy_header.q_occupancy0,
                 eg_intr_md.deq_qdepth);
}

/* Instr Bit 4: ingress tstamp */
action int_set_header_4() {
    add_header(int_ingress_tstamp_header);
    modify_field(int_ingress_tstamp_header.ingress_tstamp,
                 i2e_metadata.ingress_tstamp);
}

/* Instr Bit 5: egress timestamp */
action int_set_header_5() {
    add_header(int_egress_tstamp_header);
    modify_field(int_egress_tstamp_header.egress_tstamp,
                 eg_intr_md_from_parser_aux.egress_global_tstamp);
}

/* action function for bits 0-3 combinations, 0 is msb, 3 is lsb */
/* Each bit set indicates that corresponding INT header should be added */
action int_set_header_0003_i0() {
}
action int_set_header_0003_i1() {
    int_set_header_3();
}
action int_set_header_0003_i2() {
    int_set_header_2();
}
action int_set_header_0003_i3() {
    int_set_header_3();
    int_set_header_2();
}
action int_set_header_0003_i4() {
    int_set_header_1();
}
action int_set_header_0003_i5() {
    int_set_header_3();
    int_set_header_1();
}
action int_set_header_0003_i6() {
    int_set_header_2();
    int_set_header_1();
}
action int_set_header_0003_i7() {
    int_set_header_3();
    int_set_header_2();
    int_set_header_1();
}
action int_set_header_0003_i8() {
    int_set_header_0();
}
action int_set_header_0003_i9() {
    int_set_header_3();
    int_set_header_0();
}
action int_set_header_0003_i10() {
    int_set_header_2();
    int_set_header_0();
}
action int_set_header_0003_i11() {
    int_set_header_3();
    int_set_header_2();
    int_set_header_0();
}
action int_set_header_0003_i12() {
    int_set_header_1();
    int_set_header_0();
}
action int_set_header_0003_i13() {
    int_set_header_3();
    int_set_header_1();
    int_set_header_0();
}
action int_set_header_0003_i14() {
    int_set_header_2();
    int_set_header_1();
    int_set_header_0();
}
action int_set_header_0003_i15() {
    int_set_header_3();
    int_set_header_2();
    int_set_header_1();
    int_set_header_0();
}

/* action function for bits 4-7 combinations, 4 is msb, 7 is lsb */
// only action 4-5 is supported now
action int_set_header_0407_i4() {
    int_set_header_5();
    int_header_update();
}
action int_set_header_0407_i8() {
    int_set_header_4();
    int_header_update();
}
action int_set_header_0407_i12() {
    int_set_header_4();
    int_set_header_5();
    int_header_update();
}

@pragma ternary 1
@pragma ignore_table_dependency int_report_encap
table int_inst_0003 {
    reads {
        int_header.instruction_bitmap_0003 : exact;
    }
    actions {
        int_set_header_0003_i0;
        int_set_header_0003_i1;
        int_set_header_0003_i2;
        int_set_header_0003_i3;
        int_set_header_0003_i4;
        int_set_header_0003_i5;
        int_set_header_0003_i6;
        int_set_header_0003_i7;
        int_set_header_0003_i8;
        int_set_header_0003_i9;
        int_set_header_0003_i10;
        int_set_header_0003_i11;
        int_set_header_0003_i12;
        int_set_header_0003_i13;
        int_set_header_0003_i14;
        int_set_header_0003_i15;
    }
#ifndef BMV2TOFINO
    default_action: int_set_header_0003_i0;
#endif
    size : 16;
}

@pragma ignore_table_dependency int_report_encap
table int_inst_0407 {
    reads {
        int_header.instruction_bitmap_0407 : ternary;
    }
    actions {
        int_set_header_0407_i4;
		int_set_header_0407_i8;
        int_set_header_0407_i12;
        int_header_update;
        nop;
    }
#ifndef BMV2TOFINO
    default_action: nop;
#endif
    size : 16;
}

// update the INT metadata header
action int_header_update() {
#ifdef INT_TRANSIT_ENABLE
    add_to_field(int_header.total_hop_cnt, 1);

    // insert_byte_cnt got shift_lefted by 2 from 5bit ins_cnt
    // reset the most significant 9 (16-2-5) bits
    // that could have been contaminated
    // similarly for int_hdr_word_len
    bit_and(int_metadata.insert_byte_cnt, int_metadata.insert_byte_cnt, 0x007F);
    bit_and(int_metadata.int_hdr_word_len, int_metadata.int_hdr_word_len, 0x1F);
#endif //INT_TRANSIT_ENABLE

}

#endif // INT_ENABLE


/*******************************************************************************
 Bloom Filters for detecting path flow state changes at ingress, INT EP only
 ******************************************************************************/

#if defined(INT_EP_ENABLE) && defined(TELEMETRY_APX_STFUL_SUP_ENABLE)

register telemetry_ig_bfilter_reg_1{
    width : TELEMETRY_DIGEST_WIDTH;
    static : telemetry_ig_bfilter_1;
    instance_count : TELEMETRY_BLOOM_FILTER_SIZE;
}
register telemetry_ig_bfilter_reg_2{
    width : TELEMETRY_DIGEST_WIDTH;
    static : telemetry_ig_bfilter_2;
    instance_count : TELEMETRY_BLOOM_FILTER_SIZE;
}
register telemetry_ig_bfilter_reg_3{
    width : TELEMETRY_DIGEST_WIDTH;
    static : telemetry_ig_bfilter_3;
    instance_count : TELEMETRY_BLOOM_FILTER_SIZE;
}
register telemetry_ig_bfilter_reg_4{
    width : TELEMETRY_DIGEST_WIDTH;
    static : telemetry_ig_bfilter_4;
    instance_count : TELEMETRY_BLOOM_FILTER_SIZE;
}

blackbox stateful_alu telemetry_ig_bfilter_alu_1{
    reg: telemetry_ig_bfilter_reg_1;

    // encode 'old==0' into high bit, 'new==old' into low bit of alu_hi
    condition_hi: register_lo == 0;
    condition_lo: register_lo == int_header.rsvd2_digest;
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
    update_lo_1_value: int_header.rsvd2_digest;

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: int_metadata.bfilter_output;
    reduction_or_group: or_group_ingress;
}

blackbox stateful_alu telemetry_ig_bfilter_alu_2{
    reg: telemetry_ig_bfilter_reg_2;

    condition_hi: register_lo == 0;
    condition_lo: register_lo == int_header.rsvd2_digest;
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
    update_lo_1_value: int_header.rsvd2_digest;

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: int_metadata.bfilter_output;
    reduction_or_group: or_group_ingress;
}

blackbox stateful_alu telemetry_ig_bfilter_alu_3{
    reg: telemetry_ig_bfilter_reg_3;

    condition_hi: register_lo == 0;
    condition_lo: register_lo == int_header.rsvd2_digest;
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
    update_lo_1_value: int_header.rsvd2_digest;

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: int_metadata.bfilter_output;
    reduction_or_group: or_group_ingress;
}

blackbox stateful_alu telemetry_ig_bfilter_alu_4{
    reg: telemetry_ig_bfilter_reg_4;

    condition_hi: register_lo == 0;
    condition_lo: register_lo == int_header.rsvd2_digest;
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
    update_lo_1_value: int_header.rsvd2_digest;

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: int_metadata.bfilter_output;
    reduction_or_group: or_group_ingress;
}

/*  actions to execute the filters */
action run_telemetry_ig_bfilter_1() {
    telemetry_ig_bfilter_alu_1.execute_stateful_alu_from_hash(telemetry_hash_1);
}
action run_telemetry_ig_bfilter_2() {
    telemetry_ig_bfilter_alu_2.execute_stateful_alu_from_hash(telemetry_hash_2);
}
action run_telemetry_ig_bfilter_3() {
    telemetry_ig_bfilter_alu_3.execute_stateful_alu_from_hash(telemetry_hash_3);
}
action run_telemetry_ig_bfilter_4() {
    telemetry_ig_bfilter_alu_4.execute_stateful_alu_from_hash(telemetry_hash_4);
}

/* separate tables to run the bloom filters. */
// hash calclation action must be a hit action or only action
table telemetry_ig_bfilter_1 {
    actions {run_telemetry_ig_bfilter_1;}
}
table telemetry_ig_bfilter_2 {
    actions {run_telemetry_ig_bfilter_2;}
}
table telemetry_ig_bfilter_3 {
    actions {run_telemetry_ig_bfilter_3;}
}
table telemetry_ig_bfilter_4 {
    actions {run_telemetry_ig_bfilter_4;}
}

control process_telemetry_upstream_change {
    // Use bloom filter to detect any change in path or latency
    // If there is need to report,
    apply(telemetry_ig_bfilter_1);
    apply(telemetry_ig_bfilter_2);
    apply(telemetry_ig_bfilter_3);
    apply(telemetry_ig_bfilter_4);
}

#endif // INT_EP_ENABLE && TELEMETRY_APX_STFUL_SUP_ENABLE
