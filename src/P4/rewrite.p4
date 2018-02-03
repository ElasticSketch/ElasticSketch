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
 * Packet rewrite processing
 */


/*****************************************************************************/
/* Packet rewrite lookup and actions                                         */
/*****************************************************************************/
action set_l2_rewrite_with_tunnel(tunnel_index, tunnel_type) {
    modify_field(egress_metadata.routed, FALSE);
    modify_field(egress_metadata.bd, ingress_metadata.bd);
#ifndef TUNNEL_INDEX_BRIDGE_ENABLE
    modify_field(tunnel_metadata.tunnel_index, tunnel_index);
#endif /* TUNNEL_INDEX_BRIDGE_ENABLE */
#ifdef TUNNEL_V4_VXLAN_ONLY
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV4_VXLAN);
#else
    modify_field(tunnel_metadata.egress_tunnel_type, tunnel_type);
#endif /* TUNNEL_V4_VXLAN_ONLY */
}

action set_l2_rewrite() {
    modify_field(egress_metadata.routed, FALSE);
    modify_field(egress_metadata.bd, ingress_metadata.bd);
    modify_field(egress_metadata.outer_bd, ingress_metadata.bd);
}

action set_l3_rewrite_with_tunnel(bd, dmac, tunnel_index, tunnel_type) {
    modify_field(egress_metadata.routed, TRUE);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(egress_metadata.bd, bd);
#ifndef TUNNEL_INDEX_BRIDGE_ENABLE
    modify_field(tunnel_metadata.tunnel_index, tunnel_index);
#endif /* TUNNEL_INDEX_BRIDGE_ENABLE */
#ifdef TUNNEL_V4_VXLAN_ONLY
    modify_field(tunnel_metadata.egress_tunnel_type, EGRESS_TUNNEL_TYPE_IPV4_VXLAN);
#else
    modify_field(tunnel_metadata.egress_tunnel_type, tunnel_type);
#endif /* TUNNEL_V4_VXLAN_ONLY */
}

action set_l3_rewrite(bd, dmac) {
    modify_field(egress_metadata.routed, TRUE);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(egress_metadata.bd, bd);
    modify_field(egress_metadata.outer_bd, bd);
}

#ifndef MPLS_DISABLE
action set_mpls_core(tunnel_index, header_count) {
    modify_field(egress_metadata.routed, l3_metadata.routed);
    modify_field(tunnel_metadata.tunnel_index, tunnel_index);
    modify_field(tunnel_metadata.egress_header_count, header_count);
}

action set_mpls_push_rewrite_l2(tunnel_index, header_count) {
    set_mpls_core(tunnel_index, header_count);
    modify_field(egress_metadata.bd, ingress_metadata.bd);
    modify_field(tunnel_metadata.egress_tunnel_type,
                 EGRESS_TUNNEL_TYPE_MPLS_L2VPN);
}

action set_mpls_ipv4_udp_push_rewrite_l2(tunnel_index, header_count) {
    set_mpls_core(tunnel_index, header_count);
    modify_field(egress_metadata.bd, ingress_metadata.bd);
    modify_field(tunnel_metadata.egress_tunnel_type,
                 EGRESS_TUNNEL_TYPE_IPV4_MPLS_UDP_L2VPN);
}

action set_mpls_ipv6_udp_push_rewrite_l2(tunnel_index, header_count) {
    set_mpls_core(tunnel_index, header_count);
    modify_field(egress_metadata.bd, ingress_metadata.bd);
    modify_field(tunnel_metadata.egress_tunnel_type,
                 EGRESS_TUNNEL_TYPE_IPV6_MPLS_UDP_L2VPN);
}

action set_mpls_swap_push_rewrite_l3(bd, dmac, label, tunnel_index,
                                     header_count) {
    modify_field(mpls[0].label, label);
    set_mpls_core(tunnel_index, header_count);
    modify_field(egress_metadata.bd, bd);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(tunnel_metadata.egress_tunnel_type,
                 EGRESS_TUNNEL_TYPE_MPLS_L3VPN);
}

action set_mpls_push_rewrite_l3(bd, dmac, tunnel_index, header_count) {
    set_mpls_core(tunnel_index, header_count);
    modify_field(egress_metadata.bd, bd);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(tunnel_metadata.egress_tunnel_type,
                 EGRESS_TUNNEL_TYPE_MPLS_L3VPN);
}

action set_mpls_ipv4_udp_swap_push_rewrite_l3(bd, dmac, label, tunnel_index,
                                              header_count) {
    set_mpls_core(tunnel_index, header_count);
    modify_field(mpls[0].label, label);
    modify_field(egress_metadata.bd, bd);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(tunnel_metadata.egress_tunnel_type,
                 EGRESS_TUNNEL_TYPE_IPV4_MPLS_UDP_L3VPN);
}

action set_mpls_ipv6_udp_swap_push_rewrite_l3(bd, dmac, label, tunnel_index,
                                              header_count) {
    set_mpls_core(tunnel_index, header_count);
    modify_field(mpls[0].label, label);
    modify_field(egress_metadata.bd, bd);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(tunnel_metadata.egress_tunnel_type,
                 EGRESS_TUNNEL_TYPE_IPV6_MPLS_UDP_L3VPN);
}

action set_mpls_ipv4_udp_push_rewrite_l3(bd, dmac, tunnel_index, header_count) {
    set_mpls_core(tunnel_index, header_count);
    modify_field(egress_metadata.bd, bd);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(tunnel_metadata.egress_tunnel_type,
                 EGRESS_TUNNEL_TYPE_IPV4_MPLS_UDP_L3VPN);
}

action set_mpls_ipv6_udp_push_rewrite_l3(bd, dmac, tunnel_index, header_count) {
    set_mpls_core(tunnel_index, header_count);
    modify_field(egress_metadata.bd, bd);
    modify_field(egress_metadata.mac_da, dmac);
    modify_field(tunnel_metadata.egress_tunnel_type,
                 EGRESS_TUNNEL_TYPE_IPV6_MPLS_UDP_L3VPN);
}
#endif /* MPLS_DISABLE */

#ifdef TEST_ENT_DC_POSTCARD_PROFILE
@pragma stage 2
#endif
table rewrite {
    reads {
        l3_metadata.nexthop_index : exact;
    }
    actions {
        nop;
        set_l2_rewrite;
#if !defined(TUNNEL_DISABLE) || !defined(MIRROR_NEXTHOP_DISABLE)
        set_l2_rewrite_with_tunnel;
#endif /* TUNNEL_DISABLE */
#ifndef L3_DISABLE
        set_l3_rewrite;
#if !defined(TUNNEL_DISABLE) || !defined(MIRROR_NEXTHOP_DISABLE)
        set_l3_rewrite_with_tunnel;
#endif /* TUNNEL_DISABLE */
#endif /* L3_DISABLE */
#ifndef MPLS_DISABLE
        set_mpls_push_rewrite_l2;
        set_mpls_swap_push_rewrite_l3;
        set_mpls_push_rewrite_l3;
#ifdef MPLS_UDP_ENABLE
        set_mpls_ipv4_udp_push_rewrite_l2;
        set_mpls_ipv4_udp_swap_push_rewrite_l3;
        set_mpls_ipv4_udp_push_rewrite_l3;
        set_mpls_ipv6_udp_push_rewrite_l2;
        set_mpls_ipv6_udp_swap_push_rewrite_l3;
        set_mpls_ipv6_udp_push_rewrite_l3;
#endif /* MPLS_UDP_ENABLE */
#endif /* MPLS_DISABLE */
    }
    size : NEXTHOP_TABLE_SIZE;
}

action rewrite_ipv4_multicast() {
    modify_field(ethernet.dstAddr, ipv4.dstAddr, 0x007FFFFF);
}

action rewrite_ipv6_multicast() {
}

table rewrite_multicast {
    reads {
        ipv4 : valid;
        ipv6 : valid;
        ipv4.dstAddr mask 0xF0000000 : ternary;
#ifndef IPV6_DISABLE
        ipv6.dstAddr mask 0xFF000000000000000000000000000000 : ternary;
#endif /* IPV6_DISABLE */
    }
    actions {
        nop;
        rewrite_ipv4_multicast;
#ifndef IPV6_DISABLE
        rewrite_ipv6_multicast;
#endif /* IPV6_DISABLE */
    }
}

control process_rewrite {
#ifdef L3_MULTICAST_DISABLE
    apply(rewrite);
#else
    if ((egress_metadata.routed == TRUE) and
        (l3_metadata.nexthop_index == 0)) {
        apply(rewrite_multicast);
    } else {
        apply(rewrite);
    }
#endif /* L3_MULTICAST_DISABLE */
}
