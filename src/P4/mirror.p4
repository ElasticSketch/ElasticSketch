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
 * Mirror processing
 */

action set_mirror_nhop(nhop_idx, session_id) {
    modify_field(l3_metadata.nexthop_index, nhop_idx);
    modify_field(i2e_metadata.mirror_session_id, session_id);
}

action set_mirror_bd(bd, session_id) {
    modify_field(egress_metadata.bd, bd);
    modify_field(i2e_metadata.mirror_session_id, session_id);
}

@pragma ternary 1
@pragma ignore_table_dependency rid
table mirror {
    reads {
        i2e_metadata.mirror_session_id : exact;
    }
    actions {
        nop;
        set_mirror_nhop;
        set_mirror_bd;
#ifdef SFLOW_ENABLE
        sflow_pkt_to_cpu;
#endif
    }
    size : MIRROR_SESSIONS_TABLE_SIZE;
}

control process_mirroring {
#ifndef MIRROR_DISABLE
    apply(mirror);
#endif /* MIRROR_DISABLE */
}

/*****************************************************************************/
/* ERSPAN rewrite
/*****************************************************************************/
#if !defined(MIRROR_DISABLE) && defined(MIRROR_NEXTHOP_DISABLE)
action ipv4_erspan_t3_rewrite_all(smac, dmac, sip, dip, tos, ttl) {
    f_insert_erspan_t3_header();
    add_header(ipv4);
    modify_field(ipv4.protocol, IP_PROTOCOLS_GRE);
    modify_field(ipv4.ttl, ttl);
    modify_field(ipv4.version, 0x4);
    modify_field(ipv4.ihl, 0x5);
    modify_field(ipv4.identification, 0);
    modify_field(ipv4.flags, 0x2);
    modify_field(ipv4.diffserv, tos);
    // IPv4 (20) + GRE (4) + Erspan (12) + Ethernet (14)
    add(ipv4.totalLen, egress_metadata.payload_length, 50);
    modify_field(ipv4.srcAddr, sip);
    modify_field(ipv4.dstAddr, dip);
    modify_field(ethernet.srcAddr, smac);
    modify_field(ethernet.dstAddr, dmac);
}

table erspan_rewrite {
    reads {
        i2e_metadata.mirror_session_id : exact;
    }
    actions {
        nop;
        ipv4_erspan_t3_rewrite_all;
    }
    size : MIRROR_SESSIONS_TABLE_SIZE;
}
#endif /* !MIRROR_DISABLE && MIRROR_NEXTHOP_DISABLE */

control process_erspan_rewrite {
#if !defined(MIRROR_DISABLE) && defined(MIRROR_NEXTHOP_DISABLE)
  apply(erspan_rewrite);
#endif /* !MIRROR_DISABLE && MIRROR_NEXTHOP_DISABLE */
}
