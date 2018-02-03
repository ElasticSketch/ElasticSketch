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
 * Layer-2 processing
 */

header_type l2_metadata_t {
    fields {
        lkp_mac_sa : 48;
        lkp_mac_da : 48;
        lkp_pkt_type : 3;
        lkp_mac_type : 16;
        lkp_pcp: 3;
        non_ip_packet : 1;                     /* non ip packet */
        arp_opcode : 2;                        /* encoded opcode for arp/rarp frames */

        l2_nexthop : NEXTHOP_BIT_WIDTH;        /* next hop from l2 */
        l2_nexthop_type : 1;                   /* ecmp or nexthop */
        l2_redirect : 1;                       /* l2 redirect action */
        l2_src_miss : 1;                       /* l2 source miss */
        l2_src_move : IFINDEX_BIT_WIDTH;       /* l2 source interface mis-match */
        l2_dst_miss : 1;                       /* l2 uc/mc/bc destination miss */
        stp_group: 10;                         /* spanning tree group id */
        stp_state : 3;                         /* spanning tree port state */
        bd_stats_idx : 16;                     /* ingress BD stats index */
        learning_enabled : 1;                  /* is learning enabled on vlan */
        port_learning_enabled : 1;             /* is learning enabled on port */
        port_vlan_mapping_miss : 1;            /* port vlan mapping miss */
        same_if_check : IFINDEX_BIT_WIDTH;     /* same interface check */
    }
}

#ifdef TUNNEL_PARSING_DISABLE
@pragma pa_alias ingress l2_metadata.lkp_mac_sa ethernet.srcAddr
@pragma pa_alias ingress l2_metadata.lkp_mac_da ethernet.dstAddr
#endif
#ifdef TUNNEL_DISABLE
@pragma pa_alias ingress l2_metadata.lkp_mac_sa ethernet.srcAddr
@pragma pa_alias ingress l2_metadata.lkp_mac_da ethernet.dstAddr
#endif
@pragma pa_container_size ingress l2_metadata.same_if_check 16
#ifdef MSDC_LEAF_TELEMETRY_INT_PROFILE
@pragma pa_container_size ingress l2_metadata.lkp_pcp 8
#endif
metadata l2_metadata_t l2_metadata;

#if !defined(L2_DISABLE) && !defined(STP_DISABLE)
/*****************************************************************************/
/* Spanning tree lookup                                                      */
/*****************************************************************************/
action set_stp_state(stp_state) {
    modify_field(l2_metadata.stp_state, stp_state);
}

#ifndef STP_TCAM_DISABLE
@pragma ternary 1
#endif
table spanning_tree {
    reads {
        ingress_metadata.ifindex : exact;
        l2_metadata.stp_group: exact;
    }
    actions {
        set_stp_state;
    }
    size : SPANNING_TREE_TABLE_SIZE;
}
#endif /* !L2_DISABLE, !STP_DISABLE */

control process_spanning_tree {
#if !defined(L2_DISABLE) && !defined(STP_DISABLE)
    if ((ingress_metadata.port_type == PORT_TYPE_NORMAL) and
        (l2_metadata.stp_group != STP_GROUP_NONE)) {
        apply(spanning_tree);
    }
#endif /* !L2_DISABLE, !STP_DISABLE */
}

#ifndef L2_DISABLE
/*****************************************************************************/
/* Source MAC lookup                                                         */
/*****************************************************************************/
action smac_miss() {
    modify_field(l2_metadata.l2_src_miss, TRUE);
}

action smac_hit(ifindex) {
    bit_xor(l2_metadata.l2_src_move, ingress_metadata.ifindex, ifindex);
}

#if defined(L2_PROFILE)
@pragma idletime_precision 2
#endif
table smac {
    reads {
        ingress_metadata.bd : exact;
        l2_metadata.lkp_mac_sa : exact;
    }
    actions {
        nop;
        smac_miss;
        smac_hit;
    }
    size : MAC_TABLE_SIZE;
    support_timeout: true;
}

/*****************************************************************************/
/* Destination MAC lookup                                                    */
/*****************************************************************************/
action dmac_hit(ifindex, port_lag_index) {
    modify_field(ingress_metadata.egress_ifindex, ifindex);
    modify_field(ingress_metadata.egress_port_lag_index, port_lag_index);
    bit_xor(l2_metadata.same_if_check, l2_metadata.same_if_check, ifindex);
}

action dmac_multicast_hit(mc_index) {
    modify_field(ig_intr_md_for_tm.mcast_grp_b, mc_index);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
}

action dmac_miss() {
    modify_field(ingress_metadata.egress_ifindex, IFINDEX_FLOOD);
    modify_field(l2_metadata.l2_dst_miss, TRUE);
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, FABRIC_DEVICE_MULTICAST);
#endif /* FABRIC_ENABLE */
}

action dmac_redirect_nexthop(nexthop_index) {
    modify_field(l2_metadata.l2_redirect, TRUE);
    modify_field(l2_metadata.l2_nexthop, nexthop_index);
    modify_field(l2_metadata.l2_nexthop_type, NEXTHOP_TYPE_SIMPLE);
}

action dmac_redirect_ecmp(ecmp_index) {
    modify_field(l2_metadata.l2_redirect, TRUE);
    modify_field(l2_metadata.l2_nexthop, ecmp_index);
    modify_field(l2_metadata.l2_nexthop_type, NEXTHOP_TYPE_ECMP);
}

action dmac_drop() {
    drop();
}

table dmac {
    reads {
        ingress_metadata.bd : exact;
        l2_metadata.lkp_mac_da : exact;
    }
    actions {
#ifdef OPENFLOW_ENABLE
        openflow_apply;
        openflow_miss;
#endif /* OPENFLOW_ENABLE */
        nop;
        dmac_hit;
        dmac_multicast_hit;
        dmac_miss;
        dmac_redirect_nexthop;
        dmac_redirect_ecmp;
        dmac_drop;
    }
    size : MAC_TABLE_SIZE;
}
#endif /* L2_DISABLE */

control process_mac {
#ifndef L2_DISABLE
    if (DO_LOOKUP(SMAC_CHK) and
        (ingress_metadata.port_type == PORT_TYPE_NORMAL)) {
        apply(smac);
    }
    if (DO_LOOKUP(L2)) {
        apply(dmac);
    }
#endif /* L2_DISABLE */
}

#ifndef L2_DISABLE
/*****************************************************************************/
/* MAC learn notification                                                    */
/*****************************************************************************/
field_list mac_learn_digest {
    ingress_metadata.bd;
    l2_metadata.lkp_mac_sa;
    ingress_metadata.ifindex;
}

action generate_learn_notify() {
    generate_digest(MAC_LEARN_RECEIVER, mac_learn_digest);
}

table learn_notify {
    reads {
        l2_metadata.l2_src_miss : ternary;
        l2_metadata.l2_src_move : ternary;
        l2_metadata.stp_state : ternary;
    }
    actions {
        nop;
        generate_learn_notify;
    }
    size : LEARN_NOTIFY_TABLE_SIZE;
}
#endif /* L2_DISABLE */

control process_mac_learning {
#ifndef L2_DISABLE
  if ((l2_metadata.learning_enabled == TRUE) and (l2_metadata.port_learning_enabled == TRUE)){
        apply(learn_notify);
    }
#endif /* L2_DISABLE */
}


/*****************************************************************************/
/* Validate packet                                                           */
/*****************************************************************************/
action set_unicast() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
}

action set_unicast_and_ipv6_src_is_link_local() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(ipv6_metadata.ipv6_src_is_link_local, TRUE);
}

action set_multicast() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    add_to_field(l2_metadata.bd_stats_idx, 1);
}

action set_multicast_and_ipv6_src_is_link_local() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(ipv6_metadata.ipv6_src_is_link_local, TRUE);
    add_to_field(l2_metadata.bd_stats_idx, 1);
}

action set_broadcast() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    add_to_field(l2_metadata.bd_stats_idx, 2);
}

action set_malformed_packet(drop_reason) {
    modify_field(ingress_metadata.drop_flag, TRUE);
    modify_field(ingress_metadata.drop_reason, drop_reason);
}

table validate_packet {
    reads {
        l2_metadata.lkp_mac_sa : ternary;
        l2_metadata.lkp_mac_da : ternary;
        l3_metadata.lkp_ip_type : ternary;
        l3_metadata.lkp_ip_ttl : ternary;
        l3_metadata.lkp_ip_version : ternary;
#ifndef TUNNEL_DISABLE
        tunnel_metadata.tunnel_terminate : ternary;
        inner_ipv4.ihl : ternary;
#endif /* TUNNEL_DISABLE */
        ipv4_metadata.lkp_ipv4_sa mask 0xFF000000 : ternary;
#ifndef IPV6_DISABLE
        ipv6_metadata.lkp_ipv6_sa mask 0xFFFF0000000000000000000000000000 : ternary;
#endif /* IPV6_DISABLE */
    }
    actions {
        nop;
        set_unicast;
        set_unicast_and_ipv6_src_is_link_local;
        set_multicast;
        set_multicast_and_ipv6_src_is_link_local;
        set_broadcast;
        set_malformed_packet;
    }
    size : VALIDATE_PACKET_TABLE_SIZE;
}

control process_validate_packet {
    if (DO_LOOKUP(PKT_VALIDATION) and
        (ingress_metadata.drop_flag == FALSE)) {
        apply(validate_packet);
    }
}


/*****************************************************************************/
/* Egress BD lookup                                                          */
/*****************************************************************************/
#ifndef STATS_DISABLE
counter egress_bd_stats {
    type : packets_and_bytes;
    direct : egress_bd_stats;
    min_width : 32;
}

table egress_bd_stats {
    reads {
        egress_metadata.bd : exact;
        l2_metadata.lkp_pkt_type: exact;
    }
    actions {
        nop;
    }
    size : EGRESS_BD_STATS_TABLE_SIZE;
}
#endif /* STATS_DISABLE */

control process_egress_bd_stats {
#ifndef STATS_DISABLE
    apply(egress_bd_stats);
#endif /* STATS_DISABLE */
}

#ifndef L3_DISABLE
action set_egress_bd_properties(smac_idx, mtu_index, nat_mode, bd_label) {
    modify_field(egress_metadata.smac_idx, smac_idx);
    modify_field(nat_metadata.egress_nat_mode, nat_mode);
    modify_field(acl_metadata.egress_bd_label, bd_label);
    modify_field(l3_metadata.mtu_index, mtu_index);
}


table egress_bd_map {
    reads {
        egress_metadata.bd : exact;
    }
    actions {
        nop;
        set_egress_bd_properties;
    }
    size : EGRESS_BD_MAPPING_TABLE_SIZE;
}

#endif /* L3_DISABLE */
control process_egress_bd {
#ifndef L3_DISABLE
    apply(egress_bd_map);
#endif /* L3_DISABLE */
}

#ifdef TUNNEL_OPT
/*****************************************************************************/
/* Egress Outer BD lookup                                                    */
/*****************************************************************************/
#ifdef EGRESS_OUTER_BD_STATS_ENABLE
counter egress_outer_bd_stats {
    type : packets_and_bytes;
    direct : egress_outer_bd_stats;
    min_width : 32;
}

table egress_outer_bd_stats {
    reads {
        egress_metadata.outer_bd : exact;
        l2_metadata.lkp_pkt_type: exact;
    }
    actions {
        nop;
    }
    size : EGRESS_OUTER_BD_STATS_TABLE_SIZE;
}
#endif /* EGRESS_OUTER_BD_STATS_ENABLE */

control process_egress_outer_bd_stats {
#ifdef EGRESS_OUTER_BD_STATS_ENABLE
    apply(egress_outer_bd_stats);
#endif /* EGRESS_OUTER_BD_STATS_ENABLE */
}

#if !defined(TUNNEL_DISABLE)
action set_egress_outer_bd_properties(smac_idx, sip_idx, mtu_index, outer_bd_label) {
    modify_field(tunnel_metadata.tunnel_smac_index, smac_idx);
    modify_field(tunnel_metadata.tunnel_src_index, sip_idx);
    
//    modify_field(l3_metadata.mtu_index, mtu_index);
}


table egress_outer_bd_map {
    reads {
        egress_metadata.outer_bd : exact;
    }
    actions {
        nop;
        set_egress_outer_bd_properties;
    }
    size : EGRESS_OUTER_BD_MAPPING_TABLE_SIZE;
}

#endif /* TUNNEL_DISABLE */
control process_egress_outer_bd {
#ifndef TUNNEL_DISABLE
    apply(egress_outer_bd_map);
#endif /* TUNNEL_DISABLE */
}
#endif /* TUNNEL_OPT */

/*****************************************************************************/
/* Egress VLAN decap                                                         */
/*****************************************************************************/

action remove_vlan_single_tagged() {
    modify_field(ethernet.etherType, vlan_tag_[0].etherType);
    remove_header(vlan_tag_[0]);
}

#ifndef DOUBLE_TAGGED_DISABLE
action remove_vlan_double_tagged() {
    modify_field(ethernet.etherType, vlan_tag_[1].etherType);
    remove_header(vlan_tag_[0]);
    remove_header(vlan_tag_[1]);
}
#endif /* !DOUBLE_TAGGED_DISABLE */

#if !defined(INT_ENABLE) && !defined(POSTCARD_ENABLE)
@pragma ternary 1
#endif
table vlan_decap {
    reads {
#ifdef QINQ_ENABLE
        ig_intr_md.ingress_port : exact;
#endif
        vlan_tag_[0] : valid;
#ifndef DOUBLE_TAGGED_DISABLE
        vlan_tag_[1] : valid;
#endif /* !DOUBLE_TAGGED_DISABLE */
    }
    actions {
        nop;
        remove_vlan_single_tagged;
#ifndef DOUBLE_TAGGED_DISABLE
        remove_vlan_double_tagged;
#endif /* !DOUBLE_TAGGED_DISABLE */
    }
    size: VLAN_DECAP_TABLE_SIZE;
}

control process_vlan_decap {
    apply(vlan_decap);
}
