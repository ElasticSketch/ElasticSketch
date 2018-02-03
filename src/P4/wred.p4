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
 * WRED processing
 */

#ifdef WRED_ENABLE
header_type wred_metadata_t {
    fields {
        drop_flag : 1;
        index : 8;
        stats_index : 13;
    }
}
metadata wred_metadata_t wred_metadata;

/*****************************************************************************/
/* Ingress Classification                                                    */
/*****************************************************************************/

action set_ingress_tc_and_color_for_ecn(tc, color) {
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
}

table ecn_acl {
  reads {
        acl_metadata.port_lag_label : ternary;
        l3_metadata.lkp_dscp: ternary;
        tcp.flags : ternary;
  }
  actions {
    nop;
    set_ingress_tc_and_color_for_ecn;
  }
 size : INGRESS_ECN_ACL_TABLE_SIZE;
}
#endif /* WRED_ENABLE */

control process_ecn_acl {
#ifdef WRED_ENABLE
  apply(ecn_acl);
#endif /* WRED_ENABLE */
}    

#ifdef WRED_ENABLE
/*****************************************************************************/
/* Egress ECN Marking                                                        */
/*****************************************************************************/

blackbox wred wred_early_drop {
    wred_input : eg_intr_md.deq_qdepth;
    static : wred_index;
    instance_count : WRED_TABLE_SIZE;
    drop_value: 1;
    no_drop_value: 0;
}

/*
 *  +-----+-----+
 *  | ECN FIELD |
 *  +-----+-----+
 *    ECT   CE
 *    0     0         Not-ECT
 *    0     1         ECT(1)
 *    1     0         ECT(0)
 *    1     1         CE
 */
#define ECN_CODEPOINT_CE 0x3

counter wred_mark {
    type : packets_and_bytes;
    instance_count : WRED_INDEX_TABLE_SIZE;
    min_width : 32;
}

action set_ipv4_ecn_bits() {
    count(wred_mark, wred_metadata.stats_index);
    modify_field(wred_metadata.drop_flag, FALSE);
    modify_field(ipv4.diffserv, ECN_CODEPOINT_CE, 0x03);
}

action set_ipv6_ecn_bits() {
    count(wred_mark, wred_metadata.stats_index);
    modify_field(wred_metadata.drop_flag, FALSE);
    modify_field(ipv6.trafficClass, ECN_CODEPOINT_CE, 0x03);
}

action wred_drop() {
    modify_field(wred_metadata.drop_flag, TRUE);
    drop();
}

action wred_set_index(index, stats_index) {
    wred_early_drop.execute(wred_metadata.drop_flag, index);
    modify_field(wred_metadata.index, index);
    modify_field(wred_metadata.stats_index, stats_index);
}

table wred_action {
    reads {
        wred_metadata.index : exact;
        wred_metadata.drop_flag : exact;
        ipv4.diffserv mask 0x03 : ternary;
#ifndef IPV6_DISABLE
        ipv6.trafficClass mask 0x03 : ternary;
#endif /* IPV6_DISABLE */
        ipv4.valid : ternary;
        ipv6.valid : ternary;
    }

    actions {
        nop;
#ifdef WRED_DROP_ENABLE
        wred_drop;
#endif /* WRED_DROP_ENABLE */
#ifndef IPV6_DISABLE
        set_ipv6_ecn_bits;
#endif /* IPV6_DISABLE */
        set_ipv4_ecn_bits;
    }
    size : WRED_ACTION_TABLE_SIZE;
}

table wred_index {
    reads {
        ig_intr_md_for_tm.qid : exact;
        eg_intr_md.egress_port : exact;
        meter_metadata.packet_color : exact;
    }
    actions {
        wred_set_index;
    }
    size : WRED_INDEX_TABLE_SIZE;
}
#endif /* WRED_ENABLE */

control process_wred {
#ifdef WRED_ENABLE
    apply(wred_index);
    apply(wred_action);
#endif /* WRED_ENABLE */
}
