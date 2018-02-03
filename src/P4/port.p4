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
 * Input processing - port and packet related
 */

/*****************************************************************************/
/* Validate outer packet header                                              */
/*****************************************************************************/
action set_valid_outer_unicast_packet_untagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
}

action set_valid_outer_unicast_packet_single_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[0].etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
}

#ifndef DOUBLE_TAGGED_DISABLE
action set_valid_outer_unicast_packet_double_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[1].etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
}
#endif /* !DOUBLE_TAGGED_DISABLE */

action set_valid_outer_unicast_packet_qinq_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_UNICAST);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
}

action set_valid_outer_multicast_packet_untagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
}

action set_valid_outer_multicast_packet_single_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[0].etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
}

#ifndef DOUBLE_TAGGED_DISABLE
action set_valid_outer_multicast_packet_double_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[1].etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
}
#endif /* !DOUBLE_TAGGED_DISABLE */

action set_valid_outer_multicast_packet_qinq_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_MULTICAST);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
}

action set_valid_outer_broadcast_packet_untagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
}

action set_valid_outer_broadcast_packet_single_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[0].etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
}

#ifndef DOUBLE_TAGGED_DISABLE
action set_valid_outer_broadcast_packet_double_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_type, vlan_tag_[1].etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
}
#endif /* !DOUBLE_TAGGED_DISABLE */

action set_valid_outer_broadcast_packet_qinq_tagged() {
    modify_field(l2_metadata.lkp_pkt_type, L2_BROADCAST);
    modify_field(l2_metadata.lkp_mac_type, ethernet.etherType);
    modify_field(l2_metadata.lkp_pcp, vlan_tag_[0].pcp);
}

action malformed_outer_ethernet_packet(drop_reason) {
    modify_field(ingress_metadata.drop_flag, TRUE);
    modify_field(ingress_metadata.drop_reason, drop_reason);
}

table validate_outer_ethernet {
    reads {
        ethernet.srcAddr : ternary;
        ethernet.dstAddr : ternary;
        vlan_tag_[0].valid : ternary;
#if !defined(DOUBLE_TAGGED_DISABLE) || defined(QINQ_ENABLE)
        vlan_tag_[1].valid : ternary;
#endif /* !DOUBLE_TAGGED_DISABLE */
    }
    actions {
        malformed_outer_ethernet_packet;
        set_valid_outer_unicast_packet_untagged;
        set_valid_outer_unicast_packet_single_tagged;
#ifndef DOUBLE_TAGGED_DISABLE
        set_valid_outer_unicast_packet_double_tagged;
        set_valid_outer_multicast_packet_double_tagged;
        set_valid_outer_broadcast_packet_double_tagged;
#endif /* !DOUBLE_TAGGED_DISABLE */
        set_valid_outer_unicast_packet_qinq_tagged;
        set_valid_outer_multicast_packet_untagged;
        set_valid_outer_multicast_packet_single_tagged;
        set_valid_outer_multicast_packet_qinq_tagged;
        set_valid_outer_broadcast_packet_untagged;
        set_valid_outer_broadcast_packet_single_tagged;
        set_valid_outer_broadcast_packet_qinq_tagged;
    }
    size : VALIDATE_PACKET_TABLE_SIZE;
}

control process_validate_outer_header {
    /* validate the ethernet header */
    apply(validate_outer_ethernet) {
        malformed_outer_ethernet_packet {
        }
        default {
            if (valid(ipv4)) {
                validate_outer_ipv4_header();
            } else {
                if (valid(ipv6)) {
                    validate_outer_ipv6_header();
                }
            }
#ifndef MPLS_DISABLE
            if (valid(mpls[0])) {
                validate_mpls_header();
            }
#endif
        }
    }
}


/*****************************************************************************/
/* Ingress port lookup                                                       */
/*****************************************************************************/

action set_port_lag_index(port_lag_index, port_type) {
    modify_field(ingress_metadata.port_lag_index, port_lag_index);
    modify_field(ingress_metadata.port_type, port_type);
}

table ingress_port_mapping {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        set_port_lag_index;
    }
    size : PORTMAP_TABLE_SIZE;
}

action set_ingress_port_properties(port_lag_label, exclusion_id,
                                   qos_group, tc_qos_group,
                                   tc, color,
				   learning_enabled,
                                   trust_dscp, trust_pcp,
                                   telemetry_port_lag_label) {
    modify_field(ig_intr_md_for_tm.level2_exclusion_id, exclusion_id);
    modify_field(acl_metadata.port_lag_label, port_lag_label);
    modify_field(qos_metadata.ingress_qos_group, qos_group);
    modify_field(qos_metadata.tc_qos_group, tc_qos_group);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
    modify_field(qos_metadata.trust_dscp, trust_dscp);
    modify_field(qos_metadata.trust_pcp, trust_pcp);
    modify_field(l2_metadata.port_learning_enabled, learning_enabled);
#if defined(POSTCARD_ENABLE) || defined(INT_EP_ENABLE) || \
    defined(MIRROR_ON_DROP_ENABLE)
    modify_field(telemetry_md.port_lag_label, telemetry_port_lag_label);
#endif
}

table ingress_port_properties {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        set_ingress_port_properties;
    }
    size : PORTMAP_TABLE_SIZE;
}

control process_ingress_port_mapping {
    if (ig_intr_md.resubmit_flag == 0) {
        apply(ingress_port_mapping);
    }
    apply(ingress_port_properties);
}


/*****************************************************************************/
/* Ingress port-vlan mapping lookup                                          */
/*****************************************************************************/
action set_bd_properties(bd, vrf, stp_group, learning_enabled,
                         bd_label, stats_idx, rmac_group,
                         ipv4_unicast_enabled, ipv6_unicast_enabled,
                         ipv4_urpf_mode, ipv6_urpf_mode,
                         igmp_snooping_enabled, mld_snooping_enabled,
                         ipv4_multicast_enabled, ipv6_multicast_enabled,
                         mrpf_group,
                         ipv4_mcast_key, ipv4_mcast_key_type,
                         ipv6_mcast_key, ipv6_mcast_key_type) {
    modify_field(ingress_metadata.bd, bd);
    modify_field(ingress_metadata.outer_bd, bd);
    modify_field(acl_metadata.bd_label, bd_label);
    modify_field(l2_metadata.stp_group, stp_group);
    modify_field(l2_metadata.bd_stats_idx, stats_idx);
    modify_field(l2_metadata.learning_enabled, learning_enabled);

    modify_field(l3_metadata.vrf, vrf);
    modify_field(ipv4_metadata.ipv4_unicast_enabled, ipv4_unicast_enabled);
    modify_field(ipv6_metadata.ipv6_unicast_enabled, ipv6_unicast_enabled);
#ifndef URPF_DISABLE
    modify_field(ipv4_metadata.ipv4_urpf_mode, ipv4_urpf_mode);
    modify_field(ipv6_metadata.ipv6_urpf_mode, ipv6_urpf_mode);
#endif /* !URPF_DISABLE */
    modify_field(l3_metadata.rmac_group, rmac_group);

    modify_field(multicast_metadata.igmp_snooping_enabled,
                 igmp_snooping_enabled);
    modify_field(multicast_metadata.mld_snooping_enabled, mld_snooping_enabled);
    modify_field(multicast_metadata.ipv4_multicast_enabled,
                 ipv4_multicast_enabled);
    modify_field(multicast_metadata.ipv6_multicast_enabled,
                 ipv6_multicast_enabled);
    modify_field(multicast_metadata.bd_mrpf_group, mrpf_group);
#ifndef OUTER_MULTICAST_BRIDGE_DISABLE
    modify_field(multicast_metadata.ipv4_mcast_key_type, ipv4_mcast_key_type);
    modify_field(multicast_metadata.ipv4_mcast_key, ipv4_mcast_key);
    modify_field(multicast_metadata.ipv6_mcast_key_type, ipv6_mcast_key_type);
    modify_field(multicast_metadata.ipv6_mcast_key, ipv6_mcast_key);
#endif /* !OUTER_MULTICAST_BRIDGE_DISABLE */
}

#ifdef QINQ_ENABLE
action port_vlan_mapping_miss() {
}

action port_mapping_miss() {
    modify_field(l2_metadata.port_vlan_mapping_miss, TRUE);
}
#else
action port_vlan_mapping_miss() {
    modify_field(l2_metadata.port_vlan_mapping_miss, TRUE);
}
#endif

action_profile bd_action_profile {
    actions {
        set_bd_properties;
        port_vlan_mapping_miss;
    }
    size : BD_TABLE_SIZE;
}

table port_vlan_to_bd_mapping {
    reads {
        ingress_metadata.port_lag_index : exact;
        vlan_tag_[0] : valid;
        vlan_tag_[0].vid : exact;
#ifndef DOUBLE_TAGGED_DISABLE
        vlan_tag_[1] : valid;
        vlan_tag_[1].vid : exact;
#endif /* !DOUBLE_TAGGED_DISABLE */
    }
    action_profile: bd_action_profile;
    size : PORT_VLAN_TABLE_SIZE;
}

#ifdef QINQ_ENABLE
table port_to_bd_mapping {
    reads {
        ingress_metadata.port_lag_index : exact;
    }
    actions {
        set_bd_properties;
        port_mapping_miss;
    }
}
#endif

action set_ingress_interface_properties(ingress_rid, ifindex, if_label) {
    modify_field(ig_intr_md_for_tm.rid, ingress_rid);
    modify_field(ingress_metadata.ifindex, ifindex);
    modify_field(l2_metadata.same_if_check, ifindex);
    //modify_field(acl_metadata.if_label, if_label);
}

action copy_ifindex_from_cpu_header() {
    modify_field(ingress_metadata.ifindex, fabric_header_cpu.ingressIfindex);
    modify_field(ig_intr_md_for_tm.qid, fabric_header_cpu.egressQueue);
}

table cpu_pkt_ifindex {
    actions {
        copy_ifindex_from_cpu_header;
    }
    default_action: copy_ifindex_from_cpu_header;
}

table port_vlan_to_ifindex_mapping {
    reads {
        ingress_metadata.port_lag_index : exact;
        vlan_tag_[0] : valid;
        vlan_tag_[0].vid : exact;
#ifndef DOUBLE_TAGGED_DISABLE
        vlan_tag_[1] : valid;
        vlan_tag_[1].vid : exact;
#endif /* !DOUBLE_TAGGED_DISABLE */
    }

    actions {
        set_ingress_interface_properties;
        nop;
    }

    size : PORT_VLAN_TABLE_SIZE;
}

#ifdef DC_BASIC_PROFILE
@pragma ways 1
#endif
table cpu_packet_transform {
    reads {
        fabric_header_cpu.ingressBd : exact;
    }
    action_profile: bd_action_profile;
    size : CPU_BD_TABLE_SIZE;
}

control process_port_vlan_mapping {
    if(valid(fabric_header_cpu)) {
        apply(cpu_packet_transform);
    }
    else {
#ifdef QINQ_ENABLE
        apply(port_vlan_to_bd_mapping) {
            port_vlan_mapping_miss { apply(port_to_bd_mapping); }
        }
#else
        apply(port_vlan_to_bd_mapping);
#endif
    }
#if 0
    if(valid(fabric_header_cpu)) {
        apply(cpu_pkt_ifindex);
    }
    else {
#endif
        apply(port_vlan_to_ifindex_mapping);
#if 0
    }
#endif
#if defined(TUNNEL_DISABLE) && !defined(TUNNEL_PARSING_DISABLE)
    apply(adjust_lkp_fields);
#endif
}


/*****************************************************************************/
/* Ingress BD stats based on packet type                                     */
/*****************************************************************************/
#ifndef STATS_DISABLE
counter ingress_bd_stats {
    type : packets_and_bytes;
    instance_count : BD_STATS_TABLE_SIZE;
    min_width : 32;
}

action update_ingress_bd_stats() {
    count(ingress_bd_stats, l2_metadata.bd_stats_idx);
}

table ingress_bd_stats {
    actions {
        update_ingress_bd_stats;
    }
    size : BD_STATS_TABLE_SIZE;
}
#endif /* STATS_DISABLE */

control process_ingress_bd_stats {
#ifndef STATS_DISABLE
    apply(ingress_bd_stats);
#endif /* STATS_DISABLE */
}


/*****************************************************************************/
/* LAG lookup/resolution                                                     */
/*****************************************************************************/
field_list lag_hash_fields {
#if defined(RESILIENT_HASH_ENABLE)
#ifndef HASH_32BIT_ENABLE
    hash_metadata.hash1;
    hash_metadata.hash2;
#endif
    hash_metadata.hash1;
#endif /* RESILIENT_HASH_ENABLE */
    hash_metadata.hash2;
#ifdef FLOWLET_ENABLE
    flowlet_metadata.id;
#endif /* FLOWLET_ENABLE */
}

field_list_calculation lag_hash {
    input {
        lag_hash_fields;
    }
#if defined(RESILIENT_HASH_ENABLE)
    algorithm : identity;
    output_width : 52;
#elif defined(FLOWLET_ENABLE)
    algorithm : crc16;
    output_width : 14;
#else
    algorithm : identity;
    output_width : 14;
#endif /* RESILIENT_HASH_ENABLE */
}

action_selector lag_selector {
    selection_key : lag_hash;
#ifdef RESILIENT_HASH_ENABLE
    selection_mode : resilient;
#else
    selection_mode : fair;
#endif /* RESILIENT_HASH_ENABLE */
}

#ifdef FABRIC_ENABLE
action set_lag_remote_port(device, port) {
    modify_field(fabric_metadata.dst_device, device);
    modify_field(fabric_metadata.dst_port, port);
}
#endif /* FABRIC_ENABLE */

#ifdef FAST_FAILOVER_ENABLE
action set_lag_port(port, fallback_check) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, port);
    modify_field(failover_metadata.fallback_check, fallback_check);
}
#else
action set_lag_port(port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, port);
}
#endif /* FAST_FAILOVER_ENABLE */

action set_lag_miss() {
}

action_profile lag_action_profile {
    actions {
        set_lag_miss;
        set_lag_port;
#ifdef FABRIC_ENABLE
        set_lag_remote_port;
#endif /* FABRIC_ENABLE */
    }
    size : LAG_GROUP_TABLE_SIZE;
    dynamic_action_selection : lag_selector;
}

table lag_group {
    reads {
        ingress_metadata.egress_port_lag_index : exact;
    }
    action_profile: lag_action_profile;
    size : LAG_SELECT_TABLE_SIZE;
}

control process_lag {
#ifdef FAST_FAILOVER_ENABLE
    if (valid(pktgen_port_down)) {
        apply(lag_failover);
        apply(lag_failover_recirc);
    } else {
#endif
        apply(lag_group);
#ifdef FAST_FAILOVER_ENABLE
    }
#endif /* FAST_FAILOVER_ENABLE */
}


/*****************************************************************************/
/* Egress port lookup                                                        */
/*****************************************************************************/
action egress_port_type_normal(qos_group, port_lag_label) {
    modify_field(egress_metadata.port_type, PORT_TYPE_NORMAL);
    modify_field(qos_metadata.egress_qos_group, qos_group);
    modify_field(l3_metadata.l3_mtu_check, 0xFFFF);
    modify_field(acl_metadata.egress_port_lag_label, port_lag_label);
#ifdef PTP_ENABLE
    modify_field(eg_intr_md_for_oport.capture_tstamp_on_tx, egress_metadata.capture_tstamp_on_tx);
#endif /* PTP_ENABLE */
}

action egress_port_type_fabric() {
#if defined(FABRIC_ENABLE)
    modify_field(egress_metadata.port_type, PORT_TYPE_FABRIC);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_FABRIC);
    modify_field(l3_metadata.l3_mtu_check, 0xFFFF);
#endif /* FABRIC_ENABLE */
}

action egress_port_type_cpu() {
    modify_field(egress_metadata.port_type, PORT_TYPE_CPU);
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_CPU);
    modify_field(l3_metadata.l3_mtu_check, 0xFFFF);
#if defined(EGRESS_TUNNEL_CPU_DISABLE)
    cpu_rx_rewrite();
#endif 
}

table egress_port_mapping {
    reads {
        eg_intr_md.egress_port : exact;
    }
    actions {
        egress_port_type_normal;
        egress_port_type_fabric;
        egress_port_type_cpu;
    }
    size : PORTMAP_TABLE_SIZE;
}


/*****************************************************************************/
/* Egress VLAN translation                                                   */
/*****************************************************************************/
#ifndef DOUBLE_TAGGED_DISABLE
action set_egress_if_params_double_tagged(s_tag, c_tag, egress_if_label) {
    //modify_field(acl_metadata.egress_if_label, egress_if_label);
    add_header(vlan_tag_[1]);
    modify_field(vlan_tag_[1].etherType, ethernet.etherType);
    modify_field(vlan_tag_[1].vid, c_tag);
    add_header(vlan_tag_[0]);
    modify_field(vlan_tag_[0].etherType, ETHERTYPE_VLAN);
    modify_field(vlan_tag_[0].vid, s_tag);
    modify_field(ethernet.etherType, ETHERTYPE_QINQ);
#ifdef QOS_MARKING_ENABLE
    //    modify_field(vlan_tag_[1].pcp, l2_metadata.lkp_pcp);
    //    modify_field(vlan_tag_[0].pcp, l2_metadata.lkp_pcp);
#endif /* QOS_MARKING_ENABLE */
}
#endif /* !DOUBLE_TAGGED_DISABLE */

#ifdef QINQ_ENABLE
action set_egress_if_params_qinq_tagged(s_tag, egress_if_label) {
    copy_header(vlan_tag_[1], vlan_tag_[0]);
    modify_field(vlan_tag_[0].etherType, ETHERTYPE_VLAN);
    modify_field(vlan_tag_[0].vid, s_tag);
    modify_field(ethernet.etherType, ETHERTYPE_QINQ);
}
#endif

action set_egress_if_params_tagged(vlan_id, egress_if_label) {
    //modify_field(acl_metadata.egress_if_label, egress_if_label);
    add_header(vlan_tag_[0]);
    modify_field(vlan_tag_[0].etherType, ethernet.etherType);
    modify_field(vlan_tag_[0].vid, vlan_id);
#ifdef QOS_MARKING_ENABLE
    //    modify_field(vlan_tag_[0].pcp, l2_metadata.lkp_pcp);
#endif /* QOS_MARKING_ENABLE */
    modify_field(ethernet.etherType, ETHERTYPE_VLAN);
}

action set_egress_if_params_untagged(egress_if_label) {
    //modify_field(acl_metadata.egress_if_label, egress_if_label);
}

action set_ingress_port_mirror_index(session_id) {
  modify_field(i2e_metadata.mirror_session_id, session_id);
  clone_ingress_pkt_to_egress(session_id, i2e_mirror_info);
}

table ingress_port_mirror {
  reads {
    ig_intr_md.ingress_port : exact;
  }
  actions {
    set_ingress_port_mirror_index;
    nop;
  }
  size: PORTMAP_TABLE_SIZE;
}

control process_ingress_port_mirroring {
  apply(ingress_port_mirror);
}

table egress_vlan_xlate {
    reads {
        ingress_metadata.egress_ifindex: exact;
#ifdef TUNNEL_OPT
        egress_metadata.outer_bd : exact;
#else 
        egress_metadata.bd : exact;
#endif /* TUNNEL_OPT */
    }
    actions {
        set_egress_if_params_untagged;
        set_egress_if_params_tagged;
#ifdef QINQ_ENABLE
        set_egress_if_params_qinq_tagged;
#endif
#ifndef DOUBLE_TAGGED_DISABLE
        set_egress_if_params_double_tagged;
#endif /* !DOUBLE_TAGGED_DISABLE */
    }
    size : EGRESS_VLAN_XLATE_TABLE_SIZE;
}

control process_vlan_xlate {
    apply(egress_vlan_xlate);
}
