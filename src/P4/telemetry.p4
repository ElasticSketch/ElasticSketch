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

/*
 * Telemetry code shared by INT, Postcard, Mirror on Drop
 */

#define TELEMETRY_FLOW_HASH_WIDTH 32
#define TELEMETRY_FLOW_HASH_RANGE 4294967296 // 2^32
#define TELEMETRY_DIGEST_WIDTH    16         // size of each cell
#define TELEMETRY_DIGEST_RANGE    65536      // 2^16

#define TELEMETRY_FLOW_WATCHLIST \
        telemetry_md.port_lag_label     : ternary; \
        ethernet.etherType              : ternary; \
        ipv4.valid                      : ternary; \
        ipv4.srcAddr                    : ternary; \
        ipv4.dstAddr                    : ternary; \
        ipv4.protocol                   : ternary; \
        ipv4.diffserv mask 0xFC         : ternary; \
        l3_metadata.lkp_l4_sport        : range; \
        l3_metadata.lkp_l4_dport        : range;

#define TELEMETRY_INNERFLOW_WATCHLIST \
        tunnel_metadata.tunnel_vni      : ternary; \
        inner_ethernet.etherType        : ternary; \
        inner_ipv4.valid                : ternary; \
        inner_ipv4.srcAddr              : ternary; \
        inner_ipv4.dstAddr              : ternary; \
        inner_ipv4.protocol             : ternary; \
        inner_l4_ports.srcPort          : range; \
        inner_l4_ports.dstPort          : range;

header_type telemetry_metadata_t {
    fields {
        // flow hash for mirror load balancing and flow state change detection
        flow_hash           : TELEMETRY_FLOW_HASH_WIDTH;

        // mirror id for mirror load balancing
        mirror_session_id   : 10;

        // quantized latency for flow state change detection
        quantized_latency   : 32;

        // local digest at egress pipe for flow state change detection
        local_digest        : TELEMETRY_DIGEST_WIDTH;

        // encodes 2 bit information for flow state change detection
        // MSB = 1 if old == 0 in any filter --> new flow.
        // LSB = 1 if new == old in any filter --> no value change
        // suppress report if bfilter_output == 1 (MSB == 0 and LSB == 1).
        bfilter_output      : 2;

        // indicates if queue latency and/or depth exceed thresholds
        queue_alert         : 1;

        // common index for port-qid tuple for queue report tables
        queue_alert_index   : 10;

        // for regular egress indicates if queue latency and/or depth changed
        queue_change        : 1;

        // is 1 if we can still send more queue_report packets that have not changes
        queue_report_quota  : 1;

        // True if hit Mirror on Drop watchlist with watch action
        // higher bit is set if DoD is requested in the watchlist
        mod_watchlist_hit   : 2;

        // True if queue-based deflect on drop is enabled
        queue_dod_enable    : 1;

        // lower 2 bits are used for report control say from ingress to egress
        dscp_report         : 8;

        // set by ingress_port_properties, matched in watchlists
        port_lag_label      : 8;
    }
}
#if defined(INT_L45_ENABLE) && defined(INT_EP_ENABLE) && \
    !defined(INT_L4_CHECKSUM_UPDATE)
// no other info in the containers if checksum update is enabled
// intl45_head_header will be removed at ingress
// if compiler doesn't allocate it to even tphv we don't need this alias
@pragma pa_alias ingress telemetry_md.port_lag_label intl45_head_header.rsvd1
// local_digest is used at sink, int_header is only valid at source
@pragma pa_alias egress telemetry_md.local_digest int_header.rsvd2_digest
#endif // INT_L45_ENABLE && INT_EP_ENABLE && !INT_L4_CHECKSUM_UPDATE

// telemetry_md.flow_hash is only used in not mirrored packets. seq number is only for mirrors
@pragma pa_alias egress telemetry_md.flow_hash telemetry_report_header.sequence_number

// queue_alert is input to SALU put it solitary to save hash bits
@pragma pa_solitary egress telemetry_md.queue_alert

metadata telemetry_metadata_t telemetry_md;

/*******************************************************************************
 Control blocks exposed to switch.p4
 ******************************************************************************/
control process_telemetry_ingress_prepare {
#ifdef TELEMETRY_APX_STFUL_SUP_ENABLE
    apply(telemetry_flow_hash_outer);
#endif // TELEMETRY_APX_STFUL_SUP_ENABLE
}

control process_telemetry_watchlist {
#ifdef TELEMETRY_MIRROR_LB_ENABLE
    apply(telemetry_mirror_session);
#endif
#ifdef POSTCARD_ENABLE
    process_telemetry_postcard_watchlist();
#endif
#if defined(INT_EP_ENABLE) || defined(INT_TRANSIT_ENABLE)
    process_telemetry_int_watchlist();
#endif
}

control process_telemetry_mod_watchlist {
#ifdef MIRROR_ON_DROP_ENABLE
    apply(mirror_on_drop_watchlist);
#endif // MIRROR_ON_DROP_ENABLE
}

control process_telemetry_queue_watchlist {
// must be after egress port and qid are resolved

#ifdef TELEMETRY_STATELESS_SUP_ENABLE
    // must be after mod watchlist if it sets dod bit to false
    apply(deflect_on_drop_queue_config);
#endif // TELEMETRY_STATELESS_SUP_ENABLE
}

control process_telemetry_prepare_egress {
#if defined(TELEMETRY_STATELESS_SUP_ENABLE) || \
    defined(TELEMETRY_APX_STFUL_SUP_ENABLE) || \
    defined(INT_DIGEST_ENABLE)
    apply(telemetry_quantize_latency);
#endif // STATELESS || STFUL || DIGEST

#ifdef TELEMETRY_STATELESS_SUP_ENABLE
    apply(telemetry_queue_alert);
#endif // STATELESS
}

control process_telemetry_deflect_on_drop {
#ifdef TELEMETRY_STATELESS_SUP_ENABLE
   if (telemetry_md.queue_dod_enable == 1){
      // only update quota if dod is because of queue_report
      apply(telemetry_queue_report_dod_quota);
   }
#endif
}

control process_telemetry_local_report2 {
    // run only for not mirrored packets
    // separated from report1 to break the chain
#ifdef TELEMETRY_STATELESS_SUP_ENABLE
    // put this before next condition to let not mirror condition attach to it
    process_telemetry_queue_alert_update();
#endif
    // defined in telemetry_int.p4 and telemetry_postcard.p4
#if defined(INT_ENABLE) || defined(POSTCARD_ENABLE)
    process_telemetry_local_report2_();
#endif // INT or POSTCARD
}

control process_telemetry_local_report1 {
    // run only for not mirrored packets
#ifdef TELEMETRY_APX_STFUL_SUP_ENABLE
    apply(telemetry_make_local_digest);
#endif

#ifdef TELEMETRY_STATELESS_SUP_ENABLE
    if (telemetry_md.queue_alert == 1){
        apply(telemetry_queue_change);
    }
    apply(telemetry_queue_report_quota);
#endif
#if defined(INT_ENABLE) || defined(POSTCARD_ENABLE)
    process_telemetry_local_report1_();
#endif
}

control process_telemetry_insert {
// run only for not mirrored packets
#if defined(INT_ENABLE)
    // defined in telemetry_int.p4
    process_telemetry_insert_();
#endif
}

control process_telemetry_port_convert {
// run only for mirrored packets
// convert h/w port to front panel port for telemetry mirror packets
#if defined(INT_EP_ENABLE) || defined(POSTCARD_ENABLE) || \
    defined(MIRROR_ON_DROP_ENABLE) || \
    defined(TELEMETRY_STATELESS_SUP_ENABLE)

#ifdef INT_EP_ENABLE
#define TELEMETRY_VALID_FLOW (int_metadata.sink == 1)
#endif
#ifdef POSTCARD_ENABLE
#define TELEMETRY_VALID_FLOW (postcard_md.report == 1)
#endif
#ifdef MIRROR_ON_DROP_ENABLE
#define TELEMETRY_VALID_MOD (ingress_metadata.drop_reason != 0)
#endif
#ifdef TELEMETRY_STATELESS_SUP_ENABLE
#define TELEMETRY_VALID_QUEUE (telemetry_md.queue_alert == 1)
#endif

    if (
#ifdef TELEMETRY_VALID_FLOW
        TELEMETRY_VALID_FLOW
#endif // TELEMETRY_VALID_FLOW

#ifdef TELEMETRY_VALID_MOD
#ifdef TELEMETRY_VALID_FLOW
        or
#endif
        TELEMETRY_VALID_MOD
#endif // TELEMETRY_VALID_MOD

#ifdef TELEMETRY_VALID_QUEUE
#if defined(TELEMETRY_VALID_FLOW) || defined(TELEMETRY_VALID_MOD)
        or
#endif
        TELEMETRY_VALID_QUEUE
#endif // TELEMETRY_VALID_QUEUE
){
        apply(telemetry_ig_port_convert);
        apply(telemetry_eg_port_convert);
    }
#endif // INT_EP_ENABLE || POSTCARD_ENABLE || MIRROR_ON_DROP_ENABLE ||
        // STATELESS
}

control process_telemetry_report_encap {
// run only for mirrored packets
// must happen after process_tunnel_encap_outer
#if defined(MIRROR_ON_DROP_ENABLE) || \
    defined(TELEMETRY_STATELESS_SUP_ENABLE)

#if defined(INT_ENABLE) || defined(POSTCARD_ENABLE)
        apply(mirror_on_drop_encap){
            nop{
                // defined in telemetry_int.p4 and telemetry_postcard.p4
                process_telemetry_report_encap_();
            }
        }
#else
        apply(mirror_on_drop_encap);
#endif // int_enable || postcard_enable

#elif defined(INT_ENABLE) || defined(POSTCARD_ENABLE)
    // defined in telemetry_int.p4 and telemetry_postcard.p4
    process_telemetry_report_encap_();
#endif // MIRROR_ON_DROP_ENABLE || TELEMETRY_STATELESS_SUP_ENABLE

#ifdef TELEMETRY_REPORT_ENABLE
    if (valid(telemetry_report_header)){
        apply(telemetry_report_header_update);
    }
#endif
}

control process_telemetry_insert_2 {
// separated from insert just to be after tunnel_encap_process_outer for fitting
#ifdef INT_ENABLE
    // defined in telemetry_int.p4
    process_telemetry_insert_2_();
#endif // INT_ENABLE
}

control process_telemetry_record_egress_port {
#if defined(MIRROR_ON_DROP_ENABLE) || \
    defined(TELEMETRY_STATELESS_SUP_ENABLE) ||\
    defined(INT_EP_ENABLE) || \
    defined(POSTCARD_ENABLE)
    apply(telemetry_record_egress_port);
#endif // MIRROR_ON_DROP_ENABLE || TELEMETRY_STATELESS_SUP_ENABLE ||\
       // INT_EP_ENABLE || POSTCARD_ENABLE
}

/*******************************************************************************
 Common logic for telemetry_report_header
 ******************************************************************************/

#ifdef TELEMETRY_REPORT_ENABLE
register telemetry_report_header_seqnum {
    width : 32;
    instance_count : 1024; // # mirror sessions
}

blackbox stateful_alu telemetry_report_header_seqnum_alu{
    reg: telemetry_report_header_seqnum;
    update_lo_1_value: register_lo + 1;
    output_value: register_lo;
    output_dst: telemetry_report_header.sequence_number;
}

action update_report_header(){
    telemetry_report_header_seqnum_alu.execute_stateful_alu(i2e_metadata.mirror_session_id);
}

table telemetry_report_header_update {
    actions {
        update_report_header;
    }
}
#endif // TELEMETRY_REPORT_ENABLE

/*******************************************************************************
 Record egress port
 ******************************************************************************/

#if defined(MIRROR_ON_DROP_ENABLE) || \
    defined(TELEMETRY_STATELESS_SUP_ENABLE) ||\
    defined(INT_EP_ENABLE) || \
    defined(POSTCARD_ENABLE)

action record_eg_port_from_ig() {
    modify_field(egress_metadata.egress_port,
                 ig_intr_md_for_tm.ucast_egress_port);
}

action record_eg_port_from_eg() {
    modify_field(egress_metadata.egress_port, eg_intr_md.egress_port);
}

action record_eg_port_invalid() {
    modify_field(egress_metadata.egress_port, INVALID_PORT_ID);
}

// deflection, rid  -> action
// 0,          *    -> record_eg_port_from_eg
// 1,          0    -> record_eg_port_from_ig
// 1,          *    -> record_eg_port_invalid
table telemetry_record_egress_port {
    reads {
        eg_intr_md.deflection_flag  : exact;
        eg_intr_md.egress_rid       : ternary;
    }
    actions {
        record_eg_port_from_eg;
        record_eg_port_from_ig;
        record_eg_port_invalid;
    }
    size: 3;
}

#endif // MIRROR_ON_DROP_ENABLE || TELEMETRY_STATELESS_SUP_ENABLE ||\
       // INT_EP_ENABLE || POSTCARD_ENABLE

/*******************************************************************************
 Switch h/w port to front panel port conversion
 ******************************************************************************/

action ig_port_convert(port) {
// assume telemetry mirror packet will not be copied to CPU by egress_system_acl
    modify_field(ingress_metadata.ingress_port, port);
}


// telemetry_ig_port_convert runs for mirror copy,
// others run for not a mirror copy
@pragma ignore_table_dependency int_transit_qalert
@pragma ignore_table_dependency telemetry_postcard_e2e
@pragma ignore_table_dependency int_sink_local_report
@pragma ternary 1
table telemetry_ig_port_convert {
    reads {
        ingress_metadata.ingress_port : exact;
    }
    actions {
        ig_port_convert;
        nop;
    }
    size: PORTMAP_TABLE_SIZE;
}

action eg_port_convert(port) {
    modify_field(egress_metadata.egress_port, port);
}

// telemetry_eg_port_convert runs for mirror copy,
// others run for not a mirror copy
@pragma ignore_table_dependency int_transit_qalert
@pragma ignore_table_dependency telemetry_postcard_e2e
@pragma ignore_table_dependency int_sink_local_report
@pragma ternary 1
table telemetry_eg_port_convert {
    reads {
        egress_metadata.egress_port   : exact;
    }
    actions {
        eg_port_convert;
        nop;
    }
    size: PORTMAP_TABLE_SIZE;
}

/*******************************************************************************
 Mirror on Drop
 ******************************************************************************/
#ifdef MIRROR_ON_DROP_ENABLE
action mod_watch_dod() {
    modify_field(telemetry_md.mod_watchlist_hit, 0x3);
    deflect_on_drop(TRUE);
}

action mod_watch_nodod(dod_watchlist) {
    modify_field(telemetry_md.mod_watchlist_hit, dod_watchlist);
}

table mirror_on_drop_watchlist {
    reads {
        TELEMETRY_FLOW_WATCHLIST
    }
    actions {
        mod_watch_dod;
        mod_watch_nodod;
    }
    size: TELEMETRY_WATCHLIST_TABLE_SIZE;
}
#endif // MIRROR_ON_DROP_ENABLE

#if defined(MIRROR_ON_DROP_ENABLE) || \
    defined(TELEMETRY_STATELESS_SUP_ENABLE)
action mirror_on_drop_outer_update(udp_port, path_tracking_flow,
                                   congested_queue, hw_id, dscp) {
    modify_field(telemetry_report_header.dropped, 1);
    modify_field(telemetry_report_header.congested_queue,
                 congested_queue);
    modify_field(telemetry_report_header.path_tracking_flow,
                 path_tracking_flow);
    modify_field(telemetry_report_header.hw_id, hw_id);
    modify_field(telemetry_report_header.next_proto,
                 TELEMETRY_REPORT_NEXT_PROTO_MOD);
    modify_field(udp.dstPort, udp_port);
    add_to_field(udp.length_, 12); // mirror_on_drop header size is 12B
    add_to_field(ipv4.totalLen, 12); // mirror_on_drop header size is 12B
    modify_field(ipv4.diffserv, dscp, 0xfc);
}

action mirror_on_drop_insert_common(switch_id) {
    add_header(mirror_on_drop_header);
    modify_field(mirror_on_drop_header.switch_id, switch_id);
    modify_field(mirror_on_drop_header.ingress_port,
                 ingress_metadata.ingress_port);
    modify_field(mirror_on_drop_header.egress_port,
                 egress_metadata.egress_port);
    modify_field(mirror_on_drop_header.queue_id, ig_intr_md_for_tm.qid);
    modify_field(mirror_on_drop_header.drop_reason,
                 ingress_metadata.drop_reason);
}

action mirror_on_drop_insert(switch_id, udp_port, path_tracking_flow,
                             congested_queue, hw_id, dscp) {
    mirror_on_drop_insert_common(switch_id);
    mirror_on_drop_outer_update(udp_port, path_tracking_flow, congested_queue,
        hw_id, dscp);
}

// for all cases priority is not important except DOD with higher priority 
// nop highest priority
// dod can happen because of mod or queue_dod or both
// control plane will not add cases that have "mod" in their dscp if mod disabled
// control plane will not add cases with congested_q=1 if queue_report disabled
table mirror_on_drop_encap {
#ifdef INT_EP_ENABLE
// source, sink, qalert, drop_reason, mod:
// x,      x,    x,      0,           xx : nop (high priority)
// 1,      x,    0,      x,           x1 : path_tracking=1,congested_q=0,dscp=flow_all+mod
// 0,      1,    0,      x,           x1 : path_tracking=1,congested_q=0,dscp=flow_all+mod
// 0,      0,    1,      DOD,         0x : path_tracking=0,congested_q=1,dscp=qalert_dod
// 1,      x,    1,      DOD,         0x : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all
// 0,      1,    1,      DOD,         0x : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all
// 0,      0,    1,      DOD,         1x : path_tracking=0,congested_q=1,dscp=qalert_dod+mod
// 1,      x,    1,      DOD,         1x : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all+mod
// 0,      1,    1,      DOD,         1x : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all+mod
// 0,      0,    1,      x,           x1 : path_tracking=0,congested_q=1,dscp=qalert+mod
// 1,      x,    1,      x,           x1 : path_tracking=1,congested_q=1,dscp=qalert+flow_all+mod
// 0,      1,    1,      x,           x1 : path_tracking=1,congested_q=1,dscp=qalert+flow_all+mod
// 0,      0,    0,      x,           x1 : path_tracking=0,congested_q=0,dscp=mod
    reads {
        ingress_metadata.drop_reason   : ternary;
        int_metadata.source            : ternary;
        int_metadata.sink              : ternary;
#ifdef TELEMETRY_STATELESS_SUP_ENABLE
        telemetry_md.queue_alert       : ternary;
#endif
#ifdef MIRROR_ON_DROP_ENABLE
        telemetry_md.mod_watchlist_hit : ternary;
#endif // MIRROR_ON_DROP_ENABLE
    }
#elif defined(INT_TRANSIT_ENABLE)
// path_tracking, qalert, drop_reason, mod:
// x,             x,      0,           xx : nop (high priorty)
// 1,             0,      x,           x1 : path_tracking=1,congested_q=0,dscp=flow_all+mod
// 0,             1,      DOD,         0x : path_tracking=0,congested_q=1,dscp=qalert_dod
// 1,             1,      DOD,         0x : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all
// 0,             1,      DOD,         1x : path_tracking=0,congested_q=1,dscp=qalert_dod+mod
// 1,             1,      DOD,         1x : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all+mod
// 0,             1,      x,           x1 : path_tracking=0,congested_q=1,dscp=qalert+mod
// 1,             1,      x,           x1 : path_tracking=1,congested_q=1,dscp=qalert+flow_all+mod
// 0,             0,      x,           x1 : path_tracking=0,congested_q=0,dscp=mod
    reads {
        ingress_metadata.drop_reason    : ternary;
        int_metadata.path_tracking_flow : ternary;
#ifdef TELEMETRY_STATELESS_SUP_ENABLE
        telemetry_md.queue_alert        : ternary;
#endif // TELEMETRY_STATELESS_SUP_ENABLE
#ifdef MIRROR_ON_DROP_ENABLE
        telemetry_md.mod_watchlist_hit  : ternary;
#endif // MIRROR_ON_DROP_ENABLE
    }
#elif defined(POSTCARD_ENABLE)
// report, qalert, drop_reason, mod:
// x,      x,      0,           xx : nop (high priorty)
// 1,      0,      x,           x1 : path_tracking=1,congested_q=0,dscp=flow_all+mod
// 0,      1,      DOD,         0x : path_tracking=0,congested_q=1,dscp=qalert_dod
// 1,      1,      DOD,         0x : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all
// 0,      1,      DOD,         1x : path_tracking=0,congested_q=1,dscp=qalert_dod+mod
// 1,      1,      DOD,         1x : path_tracking=1,congested_q=1,dscp=qalert_dod+flow_all+mod
// 0,      1,      x,           x1 : path_tracking=0,congested_q=1,dscp=qalert+mod
// 1,      1,      x,           x1 : path_tracking=1,congested_q=1,dscp=qalert+flow_all+mod
// 0,      0,      x,           x1 : path_tracking=0,congested_q=0,dscp=mod
    reads {
        ingress_metadata.drop_reason   : ternary;
        postcard_md.report             : ternary;
#ifdef TELEMETRY_STATELESS_SUP_ENABLE
        telemetry_md.queue_alert       : ternary;
#endif // TELEMETRY_STATELESS_SUP_ENABLE
#ifdef MIRROR_ON_DROP_ENABLE
        telemetry_md.mod_watchlist_hit : ternary;
#endif // MIRROR_ON_DROP_ENABLE
    }
#else
// qalert, drop_reason, mod:
// x,      0,           xx : nop (high priorty)
// 1,      DOD,         0x : path_tracking=0,congested_q=1,dscp=qalert_dod
// 1,      DOD,         1x : path_tracking=0,congested_q=1,dscp=qalert_dod+mod
// 1,      x,           x1 : path_tracking=0,congested_q=1,dscp=qalert+mod
// 0,      x,           x1 : path_tracking=0,congested_q=0,dscp=mod
    reads {
        ingress_metadata.drop_reason   : ternary;
#ifdef TELEMETRY_STATELESS_SUP_ENABLE
        telemetry_md.queue_alert       : ternary;
#endif // TELEMETRY_STATELESS_SUP_ENABLE
#ifdef MIRROR_ON_DROP_ENABLE
        telemetry_md.mod_watchlist_hit : ternary;
#endif // MIRROR_ON_DROP_ENABLE
    }
#endif
    actions {
        mirror_on_drop_insert;
        nop; // high priority action if drop reason == 0
    }
    size : MIRROR_ON_DROP_ENCAP_TABLE_SIZE;
}

#endif // MIRROR_ON_DROP_ENABLE || TELEMETRY_STATELESS_SUP_ENABLE

/*******************************************************************************
 Telemetry flow hash
 ******************************************************************************/
field_list telemetry_flow_hash_fields_outer {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    l3_metadata.lkp_outer_l4_sport;
    l3_metadata.lkp_outer_l4_dport;
}

field_list telemetry_flow_hash_fields_inner {
    lkp_ipv4_hash1_fields;
#ifdef TELEMETRY_WATCH_INNER_ENABLE
    tunnel_metadata.tunnel_vni;
#endif
}

field_list_calculation telemetry_flow_hash_outer_calc {
    input { telemetry_flow_hash_fields_outer; }
#if defined(__TARGET_TOFINO__) && !defined(BMV2TOFINO)
    algorithm : crc32_msb;
#else
    algorithm : crc32;
#endif
    output_width : TELEMETRY_FLOW_HASH_WIDTH;
}

field_list_calculation telemetry_flow_hash_inner_calc {
    input { telemetry_flow_hash_fields_inner; }
#if defined(__TARGET_TOFINO__) && !defined(BMV2TOFINO)
    algorithm : crc32_lsb;
#else
    algorithm : crc32;
#endif
    output_width : TELEMETRY_FLOW_HASH_WIDTH;
}

action compute_flow_hash_outer() {
    modify_field_with_hash_based_offset(
        telemetry_md.flow_hash, 0,
        telemetry_flow_hash_outer_calc, TELEMETRY_FLOW_HASH_RANGE);
}

action compute_flow_hash_inner() {
    modify_field_with_hash_based_offset(
        telemetry_md.flow_hash, 0,
        telemetry_flow_hash_inner_calc, TELEMETRY_FLOW_HASH_RANGE);
}

table telemetry_flow_hash_outer {
    actions { compute_flow_hash_outer; }
}

// run before adjust_lkp table as it changes the fields that telemetry_flow_hash_inner needs
table telemetry_flow_hash_inner {
    actions { compute_flow_hash_inner; }
}

field_list telemetry_flow_hash_field {
    telemetry_md.flow_hash;
}

field_list telemetry_flow_eg_hash_fields {
    telemetry_md.flow_hash;
#ifndef MULTICAST_DISABLE
    eg_intr_md.egress_rid;
#endif /* MULTICAST DISABLE */
}

/*******************************************************************************
 Telemetry mirror session selection
 ******************************************************************************/


field_list telemetry_session_selection_hash_fields {
    hash_metadata.hash1;
}

field_list_calculation session_selection_hash {
    input {
        telemetry_session_selection_hash_fields;
    }
    algorithm : crc16;
    output_width : 14;
}

action_selector telemetry_session_selector {
    selection_key : session_selection_hash;
    selection_mode : fair;
}

action set_mirror_session(mirror_id) {
    modify_field(telemetry_md.mirror_session_id, mirror_id);
}

action_profile telemetry_selector_action_profile {
    actions {
        nop;
        set_mirror_session;
    }
    size : TELEMETRY_MAX_MIRROR_SESSION_PER_GROUP;
    dynamic_action_selection : telemetry_session_selector;
}

table telemetry_mirror_session {
    reads { ethernet: valid; }
    action_profile: telemetry_selector_action_profile;
    //size : TELEMETRY_MAX_SESSION_GROUP;
    size: 2;
}

/*******************************************************************************
 Queue latency and depth threshold detection
 ******************************************************************************/

#ifdef TELEMETRY_STATELESS_SUP_ENABLE

action run_telemetry_queue_alert(index) {
    telemetry_queue_alert_alu.execute_stateful_alu(index);
    modify_field(telemetry_md.queue_alert_index, index);
}

@pragma stage 1
table telemetry_queue_alert {
    reads {
        eg_intr_md.egress_port : exact;
        ig_intr_md_for_tm.qid  : exact;
    }
    actions {
        run_telemetry_queue_alert;
        nop;
    }
    size: TELEMETRY_QUEUE_TABLE_SIZE;
}

#define TELEMETRY_QUEUE_REPORT_STAGE 2

register telemetry_queue_alert_threshold {
    width : 64;
    instance_count : TELEMETRY_QUEUE_TABLE_SIZE;
}

blackbox stateful_alu telemetry_queue_alert_alu{
    reg: telemetry_queue_alert_threshold;
    condition_lo:  eg_intr_md.deq_qdepth >= register_lo;
    condition_hi:  eg_intr_md.deq_timedelta >= register_hi;
    output_predicate: condition_lo or condition_hi;
    output_value: combined_predicate;
    output_dst: telemetry_md.queue_alert;
}

action run_telemetry_queue_change() {
    telemetry_queue_change_alu.execute_stateful_alu(
        telemetry_md.queue_alert_index);
}

// keeping it in the same state as quota tables saves hash bits
@pragma stage TELEMETRY_QUEUE_REPORT_STAGE
table telemetry_queue_change {
    actions {
        run_telemetry_queue_change;
    }
}

register telemetry_queue_change_reg {
    width : 32;
    instance_count : TELEMETRY_QUEUE_TABLE_SIZE;
}

blackbox stateful_alu telemetry_queue_change_alu {
    reg: telemetry_queue_change_reg;
    condition_lo:  telemetry_md.quantized_latency != register_lo;
    update_lo_1_value: telemetry_md.quantized_latency;
    output_predicate: condition_lo;
    output_value: combined_predicate;
    output_dst: telemetry_md.queue_change;
}

action run_telemetry_queue_report_quota() {
    telemetry_queue_report_quota_alu.execute_stateful_alu(
        telemetry_md.queue_alert_index);
}

// keep telemetry_queue_report_quota and telemetry_queue_report_dod_quota
// in the same stage
@pragma stage TELEMETRY_QUEUE_REPORT_STAGE
table telemetry_queue_report_quota {
    actions {
        run_telemetry_queue_report_quota;
    }
}

action telemetry_update_dod_quota(index) {
    telemetry_queue_report_dod_quota_alu.execute_stateful_alu(index);
}

// keep telemetry_queue_report_quota and telemetry_queue_report_dod_quota
// in the same stage
@pragma stage TELEMETRY_QUEUE_REPORT_STAGE
table telemetry_queue_report_dod_quota {
    reads {
        ig_intr_md_for_tm.ucast_egress_port : exact;
        ig_intr_md_for_tm.qid  : exact;
    }
    actions {
        telemetry_update_dod_quota;
        nop;
    }
    size: TELEMETRY_QUEUE_TABLE_SIZE;
}

register telemetry_queue_report_quota_reg {
    width : 32;
    instance_count : TELEMETRY_QUEUE_TABLE_SIZE;
}

/* counter in low and threshold in hi
 * upon reset, it copies threshold to low
 * decrements on each report. If zero stops and 0s the telemetry_md.queue_report_quota flag
 * couldn't increment the counter from 0 to threshold as cannot compare low and hi
 * in a condition (only one operand from register)
 * threshold must be > 0
 * quota value and threshold cannot be 0 even if the index is not used thus set it to nonzero
 * at default and when an index is released
 */
blackbox stateful_alu telemetry_queue_report_quota_alu{
    reg: telemetry_queue_report_quota_reg;
    condition_lo:  register_lo != 0;
    condition_hi:  telemetry_md.queue_alert == 1;
    update_lo_2_predicate: condition_hi and condition_lo;
    update_lo_2_value: register_lo - 1;
    update_lo_1_predicate: not condition_hi;
    update_lo_1_value: register_hi;

    output_predicate: condition_lo;
    output_value: combined_predicate;
    output_dst: telemetry_md.queue_report_quota;
}

// reset doesn't happen at dod packets
// if register_lo==0, condition_lo=false, so it resets queue_dod_enable
blackbox stateful_alu telemetry_queue_report_dod_quota_alu{
    reg: telemetry_queue_report_quota_reg;
    condition_lo:  register_lo != 0;
    update_lo_2_predicate: condition_lo;
    update_lo_2_value: register_lo - 1;

    output_predicate: condition_lo;
    output_value: combined_predicate;
    output_dst: telemetry_md.queue_dod_enable;
}

action telemetry_update_queue_alert(){
    bit_not(telemetry_md.queue_alert, telemetry_md.queue_alert);
}
action telemetry_set_queue_alert(){
    modify_field(telemetry_md.queue_alert, 1);
}
action telemetry_unset_queue_alert(){
    modify_field(telemetry_md.queue_alert, 0);
}

// if qalert == 1 and quota finished and no change, set qalert = 0
// if qalert == 0 and quota finished, set qalert = 1 to indicate it just went below threshold
// so flipping qalert (qalert=!qalert) in these cases is enough
// (note if qalert == 0 anyway qchange = 0)
// add as a matching table vs. an if on this table and negation 
// in order to allow the control plane to disable the use of change or quota
// This table usually sits with eg bloom filter, it is better to be ternary
#if defined(INT_EP_ENABLE) || defined(POSTCARD_ENABLE)
@pragma ternary 1
#endif // INT_EP || POSTCARD
table telemetry_queue_alert_update {
// qalert, quota, qchange: new qalert
// 0,      0,     0        1  to show when it went below threshold
// 1,      0,     0        0  to prevent sending packets
    reads {
        telemetry_md.queue_alert        : exact;
        telemetry_md.queue_report_quota : exact;
        telemetry_md.queue_change       : exact;
    }
    actions{
        //telemetry_update_queue_alert;
        telemetry_unset_queue_alert;
        telemetry_set_queue_alert;
        nop;
    }
    size:8;
}

control process_telemetry_queue_alert_update{
#ifdef TELEMETRY_STATELESS_SUP_ENABLE
        apply(telemetry_queue_alert_update);
#endif // TELEMETRY_STATELESS_SUP_ENABLE
}


action queue_dod_enb() {
    modify_field(telemetry_md.queue_dod_enable, TRUE);
    deflect_on_drop(TRUE);
}

table deflect_on_drop_queue_config {
    reads {
        ig_intr_md_for_tm.ucast_egress_port : exact;
        ig_intr_md_for_tm.qid  : exact;
    }
    actions {
        queue_dod_enb;
        nop;
    }
    size: TELEMETRY_QUEUE_TABLE_SIZE;
}

#endif // TELEMETRY_STATELESS_SUP_ENABLE

/*******************************************************************************
 Stateful flow state change detection
 ******************************************************************************/

#ifdef TELEMETRY_APX_STFUL_SUP_ENABLE
// 4 Hash computation for ingress flow state change detection.
field_list_calculation telemetry_hash_1 {
    input { telemetry_flow_hash_field; }
#if defined(__TARGET_TOFINO__) && !defined(BMV2TOFINO)
    algorithm : crc_16;
#else
    algorithm : csum16;
#endif
    output_width : TELEMETRY_HASH_WIDTH;
}

field_list_calculation telemetry_hash_2 {
    input { telemetry_flow_hash_field; }
#if defined(__TARGET_TOFINO__) && !defined(BMV2TOFINO)
    algorithm : crc_16_dect;
#else
    algorithm : crc32;
#endif
    output_width : TELEMETRY_HASH_WIDTH;
}

field_list_calculation telemetry_hash_3 {
    input { telemetry_flow_hash_field; }
#if defined(__TARGET_TOFINO__) && !defined(BMV2TOFINO)
    algorithm : crc_16_dnp;
#else
    algorithm : crc16;
#endif
    output_width : TELEMETRY_HASH_WIDTH;
}

field_list_calculation telemetry_hash_4 {
    input { telemetry_flow_hash_field; }
#if defined(__TARGET_TOFINO__) && !defined(BMV2TOFINO)
// random algorihtm selected at compile time per p4 program
    algorithm : crc_16_genibus;
#else
    algorithm : crcCCITT;
#endif
    output_width : TELEMETRY_HASH_WIDTH;
}

// 4 Hash computation for egress flow state change detection.
field_list_calculation telemetry_eg_hash_1 {
    input { telemetry_flow_eg_hash_fields; }
#if defined(__TARGET_TOFINO__) && !defined(BMV2TOFINO)
    algorithm : crc_16;
#else
    algorithm : csum16;
#endif
    output_width : TELEMETRY_HASH_WIDTH;
}

field_list_calculation telemetry_eg_hash_2 {
    input { telemetry_flow_eg_hash_fields; }
#if defined(__TARGET_TOFINO__) && !defined(BMV2TOFINO)
    algorithm : crc_16_dect;
#else
    algorithm : crc32;
#endif
    output_width : TELEMETRY_HASH_WIDTH;
}

field_list_calculation telemetry_eg_hash_3 {
    input { telemetry_flow_eg_hash_fields; }
#if defined(__TARGET_TOFINO__) && !defined(BMV2TOFINO)
    algorithm : crc_16_dnp;
#else
    algorithm : crc16;
#endif
    output_width : TELEMETRY_HASH_WIDTH;
}

field_list_calculation telemetry_eg_hash_4 {
    input { telemetry_flow_eg_hash_fields; }
#if defined(__TARGET_TOFINO__) && !defined(BMV2TOFINO)
// random algorihtm selected at compile time per p4 program
    algorithm : crc_16_genibus;
#else
    algorithm : crcCCITT;
#endif
    output_width : TELEMETRY_HASH_WIDTH;
}

// Bloom Filters for detecting local flow state changes.

// A bit vector representing the filter. Replicated per hash function.
register telemetry_eg_bfilter_reg_1{
    width : TELEMETRY_DIGEST_WIDTH;
    static : telemetry_eg_bfilter_1;
    instance_count : TELEMETRY_BLOOM_FILTER_SIZE;
}
register telemetry_eg_bfilter_reg_2{
    width : TELEMETRY_DIGEST_WIDTH;
    static : telemetry_eg_bfilter_2;
    instance_count : TELEMETRY_BLOOM_FILTER_SIZE;
}
register telemetry_eg_bfilter_reg_3{
    width : TELEMETRY_DIGEST_WIDTH;
    static : telemetry_eg_bfilter_3;
    instance_count : TELEMETRY_BLOOM_FILTER_SIZE;
}
register telemetry_eg_bfilter_reg_4{
    width : TELEMETRY_DIGEST_WIDTH;
    static : telemetry_eg_bfilter_4;
    instance_count : TELEMETRY_BLOOM_FILTER_SIZE;
}

blackbox stateful_alu telemetry_eg_bfilter_alu_1{
    reg: telemetry_eg_bfilter_reg_1;

    condition_hi: register_lo == 0;
    condition_lo: register_lo == telemetry_md.local_digest;
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
    update_lo_1_value: telemetry_md.local_digest;

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: telemetry_md.bfilter_output;
    reduction_or_group: or_group_egress;
}

blackbox stateful_alu telemetry_eg_bfilter_alu_2{
    reg: telemetry_eg_bfilter_reg_2;

    condition_hi: register_lo == 0;
    condition_lo: register_lo == telemetry_md.local_digest;
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
    update_lo_1_value: telemetry_md.local_digest;

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: telemetry_md.bfilter_output;
    reduction_or_group: or_group_egress;
}

blackbox stateful_alu telemetry_eg_bfilter_alu_3{
    reg: telemetry_eg_bfilter_reg_3;

    condition_hi: register_lo == 0;
    condition_lo: register_lo == telemetry_md.local_digest;
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
    update_lo_1_value: telemetry_md.local_digest;

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: telemetry_md.bfilter_output;
    reduction_or_group: or_group_egress;
}

blackbox stateful_alu telemetry_eg_bfilter_alu_4{
    reg: telemetry_eg_bfilter_reg_4;

    condition_hi: register_lo == 0;
    condition_lo: register_lo == telemetry_md.local_digest;
    update_hi_2_predicate: condition_hi;
    update_hi_2_value: 2;
    update_hi_1_predicate: condition_lo;
    update_hi_1_value: 1;
    update_lo_1_value: telemetry_md.local_digest;

    output_predicate: condition_lo or condition_hi;
    output_value: alu_hi;
    output_dst: telemetry_md.bfilter_output;
    reduction_or_group: or_group_egress;
}

action run_telemetry_eg_bfilter_1() {
    telemetry_eg_bfilter_alu_1.execute_stateful_alu_from_hash(
        telemetry_eg_hash_1);
}
action run_telemetry_eg_bfilter_2() {
    telemetry_eg_bfilter_alu_2.execute_stateful_alu_from_hash(
        telemetry_eg_hash_2);
}
action run_telemetry_eg_bfilter_3() {
    telemetry_eg_bfilter_alu_3.execute_stateful_alu_from_hash(
        telemetry_eg_hash_3);
}
action run_telemetry_eg_bfilter_4() {
    telemetry_eg_bfilter_alu_4.execute_stateful_alu_from_hash(
        telemetry_eg_hash_4);
}

/* Four separate tables to run the bloom filter. */
/* pragmas to keep tables in the same stage */
#if defined(ENT_FIN_LEAF_PROFILE) ||\
    defined(MSDC_LEAF_TELEMETRY_INT_PROFILE)
#define TELEMETRY_EG_BF_STAGE 4
#else
#define TELEMETRY_EG_BF_STAGE 3
#endif
#ifdef TELEMETRY_EG_BF_STAGE
@pragma stage TELEMETRY_EG_BF_STAGE
#endif
table telemetry_eg_bfilter_1 {
    actions { run_telemetry_eg_bfilter_1; }
}
#ifdef TELEMETRY_EG_BF_STAGE
@pragma stage TELEMETRY_EG_BF_STAGE
#endif
table telemetry_eg_bfilter_2 {
    actions { run_telemetry_eg_bfilter_2; }
}
#ifdef TELEMETRY_EG_BF_STAGE
@pragma stage TELEMETRY_EG_BF_STAGE
#endif
table telemetry_eg_bfilter_3 {
    actions { run_telemetry_eg_bfilter_3; }
}
#ifdef TELEMETRY_EG_BF_STAGE
@pragma stage TELEMETRY_EG_BF_STAGE
#endif
table telemetry_eg_bfilter_4 {
    actions { run_telemetry_eg_bfilter_4; }
}

field_list telemetry_local_digest_fields {
// includes flow hash to avoid canceling reports of microbursts
// for two different flows
    telemetry_md.flow_hash;
#ifndef MULTICAST_DISABLE
    eg_intr_md.egress_rid;
#endif /* MULTICAST DISABLE */
    telemetry_md.quantized_latency;
    ingress_metadata.ingress_port;
    eg_intr_md.egress_port;
}

field_list_calculation telemetry_local_digest_calc {
    input { telemetry_local_digest_fields; }
#if defined(__TARGET_TOFINO__) && !defined(BMV2TOFINO)
    algorithm : crc_16_teledisk;
#else
    algorithm : crc16;
#endif
    output_width : TELEMETRY_DIGEST_WIDTH;
}

action make_local_digest() {
    modify_field_with_hash_based_offset(
        telemetry_md.local_digest, 0,
        telemetry_local_digest_calc, TELEMETRY_DIGEST_RANGE);
}

table telemetry_make_local_digest {
    actions { make_local_digest; }
}

control process_telemetry_detect_local_change {
    // Use bloom filter to detect change in quantized local latency
    // This should be executed before tunnel_decap
    apply(telemetry_eg_bfilter_1);
    apply(telemetry_eg_bfilter_2);
    apply(telemetry_eg_bfilter_3);
    apply(telemetry_eg_bfilter_4);
}
#endif // TELEMETRY_APX_STFUL_SUP_ENABLE

#if defined(TELEMETRY_APX_STFUL_SUP_ENABLE) || defined(INT_DIGEST_ENABLE)
action copy_latency() {
    modify_field(telemetry_md.quantized_latency,
                 eg_intr_md.deq_timedelta, 0x1FFFF);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action quantize_latency_1() {
    modify_field_with_shift(telemetry_md.quantized_latency,
                            eg_intr_md.deq_timedelta, 1, 0xFFFF);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action quantize_latency_2() {
    modify_field_with_shift(telemetry_md.quantized_latency,
                            eg_intr_md.deq_timedelta, 2, 0x7FFF);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action quantize_latency_3() {
    modify_field_with_shift(telemetry_md.quantized_latency,
                            eg_intr_md.deq_timedelta, 3, 0x3FFF);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action quantize_latency_4() {
    modify_field_with_shift(telemetry_md.quantized_latency,
                            eg_intr_md.deq_timedelta, 4, 0x1FFF);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action quantize_latency_5() {
    modify_field_with_shift(telemetry_md.quantized_latency,
                            eg_intr_md.deq_timedelta, 5, 0xFFF);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action quantize_latency_6() {
    modify_field_with_shift(telemetry_md.quantized_latency,
                            eg_intr_md.deq_timedelta, 6, 0x7FF);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action quantize_latency_7() {
    modify_field_with_shift(telemetry_md.quantized_latency,
                            eg_intr_md.deq_timedelta, 7, 0x3FF);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action quantize_latency_8() {
    modify_field_with_shift(telemetry_md.quantized_latency,
                            eg_intr_md.deq_timedelta, 8, 0x1FF);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action quantize_latency_9() {
    modify_field_with_shift(telemetry_md.quantized_latency,
                            eg_intr_md.deq_timedelta, 9, 0xFF);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action quantize_latency_10() {
    modify_field_with_shift(telemetry_md.quantized_latency,
                            eg_intr_md.deq_timedelta, 10, 0x7F);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action quantize_latency_11() {
    modify_field_with_shift(telemetry_md.quantized_latency,
                            eg_intr_md.deq_timedelta, 11, 0x3F);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action quantize_latency_12() {
    modify_field_with_shift(telemetry_md.quantized_latency,
                            eg_intr_md.deq_timedelta, 12, 0x1F);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action quantize_latency_13() {
    modify_field_with_shift(telemetry_md.quantized_latency,
                            eg_intr_md.deq_timedelta, 13, 0xF);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action quantize_latency_14() {
    modify_field_with_shift(telemetry_md.quantized_latency,
                            eg_intr_md.deq_timedelta, 14, 0x7);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action quantize_latency_15() {
    modify_field_with_shift(telemetry_md.quantized_latency,
                            eg_intr_md.deq_timedelta, 15, 0x3);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}
action zero_latency() {
    modify_field(telemetry_md.quantized_latency, 0);
    modify_field(eg_intr_md.deq_timedelta, 0, 0xFFFE0000);
}

@pragma stage 0
table telemetry_quantize_latency {
    actions {
        // control plane will choose the quantization action
        quantize_latency_1;
        quantize_latency_2;
        quantize_latency_3;
        quantize_latency_4;
        quantize_latency_5;
        quantize_latency_6;
        quantize_latency_7;
        quantize_latency_8;
        quantize_latency_9;
        quantize_latency_10;
        quantize_latency_11;
        quantize_latency_12;
        quantize_latency_13;
        quantize_latency_14;
        quantize_latency_15;
        zero_latency;
        copy_latency;
    }
#ifndef BMV2TOFINO
    default_action: zero_latency;
#endif
    size: 1;
}
#endif // TELEMETRY_APX_STFUL_SUP_ENABLE || INT_DIGEST_DISABLE
