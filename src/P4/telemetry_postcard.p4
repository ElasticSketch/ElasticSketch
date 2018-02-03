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
 * Postcard processing
 */

header_type postcard_metadata_t {
    fields {
        report : 1;
        suppress_enb : 1;
    }
}
metadata postcard_metadata_t postcard_md;

#ifdef POSTCARD_ENABLE

control process_telemetry_postcard_watchlist {
    apply(postcard_watchlist);
}

control process_telemetry_local_report1_ {
}

control process_telemetry_local_report2_ {
#ifdef TELEMETRY_APX_STFUL_SUP_ENABLE
    if(postcard_md.report == 1 and postcard_md.suppress_enb == 1) {
        process_telemetry_detect_local_change();
    }
#endif // TELEMETRY_APX_STFUL_SUP_ENABLE

    apply(telemetry_postcard_e2e);
}

control process_telemetry_report_encap_ {
    apply(telemetry_postcard_insert);
}

// watches if the packet will be monitored
// 100% all flows, use postcard_not_watch for 0%
action postcard_watch_sample(suppress_enb, sample_index){
    telemetry_postcard_sample_alu.execute_stateful_alu(
        sample_index);
    modify_field(postcard_md.suppress_enb, suppress_enb);
}

action postcard_not_watch() {
    modify_field(postcard_md.report, 0);
    modify_field(postcard_md.suppress_enb, 0);
}

#ifdef TEST_ENT_DC_POSTCARD_PROFILE
@pragma command_line --placement-order egress_before_ingress
#endif
table postcard_watchlist {
    reads {
        TELEMETRY_FLOW_WATCHLIST
#ifdef TELEMETRY_WATCH_INNER_ENABLE
        TELEMETRY_INNERFLOW_WATCHLIST
#endif
    }
    actions {
        postcard_watch_sample;
        postcard_not_watch;
    }
    size: TELEMETRY_WATCHLIST_TABLE_SIZE;
}

field_list postcard_mirror_info {
    ingress_metadata.ingress_port;
    egress_metadata.egress_port;
    i2e_metadata.mirror_session_id;
    i2e_metadata.ingress_tstamp;
    ig_intr_md_for_tm.qid;
    eg_intr_md.deq_qdepth;
    eg_intr_md_from_parser_aux.egress_global_tstamp;
    postcard_md.report;
    telemetry_md.dscp_report;
    telemetry_md.queue_alert;
//    hash_metadata.entropy_hash;
}

// control plane shift_left user dscp (6b) by 2 bits for action param (8b)
action postcard_e2e(dscp_report) {
    modify_field(i2e_metadata.mirror_session_id,
                 telemetry_md.mirror_session_id);
    modify_field(telemetry_md.dscp_report, dscp_report);
    clone_egress_pkt_to_egress(telemetry_md.mirror_session_id,
                               postcard_mirror_info);
}

// telemetry_postcard_e2e shall not run for mirrored packets
// mirror, telemetry_postcard_insert and telemetry_postcard_encap only run
// for mirrored packets (compiler has hard time to find the independence)
@pragma ignore_table_dependency mirror
@pragma ignore_table_dependency telemetry_postcard_insert
@pragma ignore_table_dependency tunnel_encap_process_outer
@pragma ignore_table_dependency telemetry_ig_port_convert
@pragma ignore_table_dependency telemetry_eg_port_convert
table telemetry_postcard_e2e {
// priority is important
// report, enb, bfilter, alert, TCP:
//// IF STATEFUL ENABLED
// 1,      0,   xx,      x,     x  : report all
// 1,      1,   1x,      x,     x  : new flow
// 1,      1,   00,      x,     x  : flow change
//// ELSE
// 1,       ,     ,       ,     x  : postcard
//// ENDIF
//// IF STATELESS ENABLED
// x,       ,     ,      1,     x  : qalert
//// ENDIF
// 1,      x,   xx,      x,     inner & flag  : tcp
// 1,      x,   xx,      x,     outer & flag  : tcp
    reads{
        postcard_md.report                 : ternary;
#ifdef TELEMETRY_APX_STFUL_SUP_ENABLE
        postcard_md.suppress_enb           : ternary;
        telemetry_md.bfilter_output        : ternary;
#endif
#ifdef TELEMETRY_STATELESS_SUP_ENABLE
        telemetry_md.queue_alert           : ternary;
#endif
        tcp.valid                          : ternary;
        tcp.flags mask 0x7                 : ternary;
#ifdef TELEMETRY_WATCH_INNER_ENABLE
        inner_tcp_info.flags mask 0x7      : ternary;
        inner_tcp_info.valid               : ternary;
#endif
    }
    actions {
        postcard_e2e;
        nop;
    }
#ifndef BMV2TOFINO
    default_action : nop;
#endif
    size: 16;
}

action postcard_outer_update(udp_port, path_tracking_flow, congested_queue,
                             hw_id) {
    modify_field(telemetry_report_header.next_proto,
                 TELEMETRY_REPORT_NEXT_PROTO_SWITCH_LOCAL);
    modify_field(telemetry_report_header.congested_queue, congested_queue);
    modify_field(telemetry_report_header.path_tracking_flow,
                 path_tracking_flow);
    modify_field(telemetry_report_header.hw_id, hw_id);
    modify_field(udp.dstPort, udp_port);
    add_to_field(udp.length_, 16); // postcard header size is 16B
    add_to_field(ipv4.totalLen, 16); // postcard header size is 16B
    modify_field(ipv4.diffserv, telemetry_md.dscp_report, 0xfc);
}

action postcard_insert_common(switch_id) {
    add_header(postcard_header);
    modify_field(postcard_header.switch_id, switch_id);
    modify_field(postcard_header.ingress_port, ingress_metadata.ingress_port);
    modify_field(postcard_header.egress_port, egress_metadata.egress_port);
    modify_field(postcard_header.queue_id, ig_intr_md_for_tm.qid);
    modify_field(postcard_header.queue_depth, eg_intr_md.deq_qdepth);
    modify_field(postcard_header.egress_tstamp,
                 eg_intr_md_from_parser_aux.egress_global_tstamp);
}

action postcard_insert(switch_id, udp_port, path_tracking_flow,
                       congested_queue, hw_id) {
    postcard_insert_common(switch_id);
    postcard_outer_update(udp_port, path_tracking_flow, congested_queue, hw_id);
}

@pragma ignore_table_dependency telemetry_postcard_e2e
table telemetry_postcard_insert {
// report, qalert:
// 0     , 0     : nop
// 0     , 1     : postcard_insert (path_tracking_flow=0, congested_queue=1)
// 1     , 0     : postcard_insert (path_tracking_flow=1, congested_queue=0)
// 1     , 1     : postcard_insert (path_tracking_flow=1, congested_queue=1)
    reads {
        postcard_md.report       : exact;
        telemetry_md.queue_alert : exact;
    }
    actions {
        postcard_insert;
        nop;
    }
    size: 4;
}

register telemetry_postcard_sample_rate {
    width : 32;
    instance_count : 4096; // 1 sram block
}

blackbox stateful_alu telemetry_postcard_sample_alu{
    reg: telemetry_postcard_sample_rate;
    condition_lo:  telemetry_md.flow_hash <= register_lo;
    output_predicate: condition_lo;
    output_value: combined_predicate;
    output_dst: postcard_md.report;
}

#endif // POSTCARD_ENABLE
