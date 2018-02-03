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
/* enable all advanced features */
//#define ADV_FEATURES
#define ETHERTYPE_BF_FABRIC     0x9000
#define ETHERTYPE_BF_PKTGEN     0x9001
#define ETHERTYPE_VLAN          0x8100
#define ETHERTYPE_QINQ          0x9100
#define ETHERTYPE_MPLS          0x8847
#define ETHERTYPE_IPV4          0x0800
#define ETHERTYPE_IPV6          0x86dd
#define ETHERTYPE_ARP           0x0806
#define ETHERTYPE_RARP          0x8035
#define ETHERTYPE_NSH           0x894f
#define ETHERTYPE_ETHERNET      0x6558
#define ETHERTYPE_ROCE          0x8915
#define ETHERTYPE_FCOE          0x8906
#define ETHERTYPE_TRILL         0x22f3
#define ETHERTYPE_VNTAG         0x8926
#define ETHERTYPE_LLDP          0x88cc
#define ETHERTYPE_LACP          0x8809
#define ETHERTYPE_PTP           0x88f7
#define ETHERTYPE_FIP           0x8914

#define IPV4_MULTICAST_MAC 0x01005E
#define IPV6_MULTICAST_MAC 0x3333

/* Tunnel types */
#define INGRESS_TUNNEL_TYPE_NONE               0
#define INGRESS_TUNNEL_TYPE_VXLAN              1
#define INGRESS_TUNNEL_TYPE_GRE                2
#define INGRESS_TUNNEL_TYPE_IP_IN_IP           3
#define INGRESS_TUNNEL_TYPE_GENEVE             4
#define INGRESS_TUNNEL_TYPE_NVGRE              5
#define INGRESS_TUNNEL_TYPE_MPLS               6
#define INGRESS_TUNNEL_TYPE_VXLAN_GPE          12
#define INGRESS_TUNNEL_TYPE_MPLS_IN_UDP        13
#define INGRESS_TUNNEL_TYPE_SRV6             14

#ifndef ADV_FEATURES
#ifdef FCOE_ACL_ENABLE
#define PARSE_ETHERTYPE                                    \
        ETHERTYPE_VLAN : parse_vlan;                       \
        ETHERTYPE_QINQ : parse_qinq;                       \
        ETHERTYPE_MPLS : parse_mpls;                       \
        ETHERTYPE_IPV4 : parse_ipv4;                       \
        ETHERTYPE_IPV6 : parse_ipv6;                       \
        ETHERTYPE_ARP : parse_arp_rarp;                    \
        ETHERTYPE_LLDP  : parse_set_prio_high;             \
        ETHERTYPE_LACP  : parse_set_prio_high;             \
        ETHERTYPE_FCOE  : parse_fcoe_fc;                   \
        ETHERTYPE_FIP   : parse_fip;                       \
        default: ingress

#define PARSE_ETHERTYPE_MINUS_VLAN                         \
        ETHERTYPE_MPLS : parse_mpls;                       \
        ETHERTYPE_IPV4 : parse_ipv4;                       \
        ETHERTYPE_IPV6 : parse_ipv6;                       \
        ETHERTYPE_ARP : parse_arp_rarp;                    \
        ETHERTYPE_LLDP  : parse_set_prio_high;             \
        ETHERTYPE_LACP  : parse_set_prio_high;             \
        ETHERTYPE_FCOE  : parse_fcoe_fc;                   \
        ETHERTYPE_FIP   : parse_fip;                       \
        default: ingress
#else
#define PARSE_ETHERTYPE                                    \
        ETHERTYPE_VLAN : parse_vlan;                       \
        ETHERTYPE_QINQ : parse_qinq;                       \
        ETHERTYPE_MPLS : parse_mpls;                       \
        ETHERTYPE_IPV4 : parse_ipv4;                       \
        ETHERTYPE_IPV6 : parse_ipv6;                       \
        ETHERTYPE_ARP : parse_arp_rarp;                    \
        ETHERTYPE_LLDP  : parse_set_prio_high;             \
        ETHERTYPE_LACP  : parse_set_prio_high;             \
        default: ingress

#define PARSE_ETHERTYPE_MINUS_VLAN                         \
        ETHERTYPE_MPLS : parse_mpls;                       \
        ETHERTYPE_IPV4 : parse_ipv4;                       \
        ETHERTYPE_IPV6 : parse_ipv6;                       \
        ETHERTYPE_ARP : parse_arp_rarp;                    \
        ETHERTYPE_LLDP  : parse_set_prio_high;             \
        ETHERTYPE_LACP  : parse_set_prio_high;             \
        default: ingress

#endif

#define PARSE_ETHERTYPE_MINUS_VLAN                         \
        ETHERTYPE_MPLS : parse_mpls;                       \
        ETHERTYPE_IPV4 : parse_ipv4;                       \
        ETHERTYPE_IPV6 : parse_ipv6;                       \
        ETHERTYPE_ARP : parse_arp_rarp;                    \
        ETHERTYPE_LLDP  : parse_set_prio_high;             \
        ETHERTYPE_LACP  : parse_set_prio_high;             \
        default: ingress
#else
#define PARSE_ETHERTYPE                                    \
        ETHERTYPE_VLAN : parse_vlan;                       \
        ETHERTYPE_QINQ : parse_qinq;                       \
        ETHERTYPE_MPLS : parse_mpls;                       \
        ETHERTYPE_IPV4 : parse_ipv4;                       \
        ETHERTYPE_IPV6 : parse_ipv6;                       \
        ETHERTYPE_ARP : parse_arp_rarp;                    \
        ETHERTYPE_RARP : parse_arp_rarp;                   \
        ETHERTYPE_NSH : parse_nsh;                         \
        ETHERTYPE_ROCE : parse_roce;                       \
        ETHERTYPE_FCOE : parse_fcoe;                       \
        ETHERTYPE_TRILL : parse_trill;                     \
        ETHERTYPE_VNTAG : parse_vntag;                     \
        ETHERTYPE_LLDP  : parse_set_prio_high;             \
        ETHERTYPE_LACP  : parse_set_prio_high;             \
        default: ingress

#define PARSE_ETHERTYPE_MINUS_VLAN                         \
        ETHERTYPE_MPLS : parse_mpls;                       \
        ETHERTYPE_IPV4 : parse_ipv4;                       \
        ETHERTYPE_IPV6 : parse_ipv6;                       \
        ETHERTYPE_ARP : parse_arp_rarp;                    \
        ETHERTYPE_RARP : parse_arp_rarp;                   \
        ETHERTYPE_NSH : parse_nsh;                         \
        ETHERTYPE_ROCE : parse_roce;                       \
        ETHERTYPE_FCOE : parse_fcoe;                       \
        ETHERTYPE_TRILL : parse_trill;                     \
        ETHERTYPE_VNTAG : parse_vntag;                     \
        ETHERTYPE_LLDP  : parse_set_prio_high;             \
        ETHERTYPE_LACP  : parse_set_prio_high;             \
        default: ingress
#endif

parser start {
    return select(current(96, 16)) { // ether.type
#ifdef PKTGEN_ENABLE
        ETHERTYPE_BF_PKTGEN : parse_pktgen_header;
#endif /* PKTGEN_ENABLE */
        default : parse_ethernet;
    }
}

#ifdef TELEMETRY_REPORT_ENABLE
@pragma packet_entry
parser start_i2e_mirrored {
    extract(ethernet);
    return ingress;
}

@pragma packet_entry
parser start_e2e_mirrored {
    extract(ethernet);
    return ingress;
}
#endif /* TELEMETRY_REPORT_ENABLE */


#ifdef PKTGEN_ENABLE
parser parse_pktgen_header {
    return select(current(5, 3)) {
#ifdef BFD_OFFLOAD_ENABLE
        P4_PKTGEN_APP_BFD : parse_pktgen_generic;
#endif
#ifdef FAST_FAILOVER_ENABLE
        P4_PKTGEN_APP_LAG_FAILOVER : parse_pktgen_port_down;
        P4_PKTGEN_APP_ECMP_FAILOVER : parse_pktgen_recirc;
#endif
        default : ingress;
    }
}

parser parse_pktgen_port_down {
    extract(pktgen_port_down);
    return select(latest.app_id) {
#ifdef FAST_FAILOVER_ENABLE
        P4_PKTGEN_APP_LAG_FAILOVER : parse_failover_port_down;
#endif
        default : ingress;
    }
}

parser parse_pktgen_recirc {
    extract(pktgen_recirc);
    return select(latest.app_id) {
#ifdef FAST_FAILOVER_ENABLE
        P4_PKTGEN_APP_ECMP_FAILOVER : parse_failover_nhop_down;
#endif
        default : ingress;
    }
}

parser parse_pktgen_timer {
    extract(pktgen_timer);
    return ingress;
}

parser parse_pktgen_generic {
    extract(pktgen_generic);
    return select(latest.batch_id, latest.app_id) {
#ifdef BFD_OFFLOAD_ENABLE
        P4_PKTGEN_APP_BFD : parse_pktgen_bfd_ipv4;
#endif
        default : ingress;
    }
}

header pktgen_ext_header_t pktgen_ext_header;

#ifdef FAST_FAILOVER_ENABLE
parser parse_failover_nhop_down {
    extract(pktgen_ext_header);
    return select(latest.etherType) {
        0 mask 0: ingress;
        // never transition to the following state
        default: parse_ethernet;
    }
}

parser parse_failover_port_down {
    extract(pktgen_ext_header);
    return ingress;
}
#endif /* FAST_FAILOVER_ENABLE */

#ifdef BFD_OFFLOAD_ENABLE
parser parse_pktgen_bfd_ipv4 {
    // pktgen buffer has ipv4, udp and bfd headers
    // fixed members such as version, len etc are initialized for all headers
    extract(pktgen_ext_header);
    set_metadata(bfd_meta.pkt_tx, 1);
    return parse_ipv4;
}

parser parse_pktgen_bfd_ipv6 {
    extract(pktgen_ext_header);
    set_metadata(bfd_meta.pkt_tx, 1);
    return parse_ipv6;
}
#endif /* BFD_OFFLOAD_ENABLE */

#endif /* PKTGEN_ENABLE */

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        0 mask 0xfe00: parse_llc_header;
        0 mask 0xfa00: parse_llc_header;
        ETHERTYPE_BF_FABRIC : parse_fabric_header;
        PARSE_ETHERTYPE;
    }
}

header llc_header_t llc_header;

parser parse_llc_header {
    extract(llc_header);
    return select(llc_header.dsap, llc_header.ssap) {
        0xAAAA : parse_snap_header;
        0xFEFE : parse_set_prio_med;
        default: ingress;
    }
}

header snap_header_t snap_header;

parser parse_snap_header {
    extract(snap_header);
    return select(latest.type_) {
        PARSE_ETHERTYPE;
    }
}

header roce_header_t roce;

parser parse_roce {
    extract(roce);
    return ingress;
}

header fcoe_header_t fcoe;

parser parse_fcoe {
    extract(fcoe);
    return ingress;
}

header fcoe_fc_header_t fcoe_fc;

parser parse_fcoe_fc {
    extract(fcoe_fc);
    return ingress;
}

header fip_header_t fip;

parser parse_fip {
    extract(fip);
    return ingress;
}

#define VLAN_DEPTH 2
header vlan_tag_t vlan_tag_[VLAN_DEPTH];

parser parse_vlan {
    extract(vlan_tag_[0]);
    return select(latest.etherType) {
        PARSE_ETHERTYPE_MINUS_VLAN;
    }
}

parser parse_qinq {
    extract(vlan_tag_[0]);
    return select(latest.etherType) {
        ETHERTYPE_VLAN : parse_qinq_vlan;
        default : ingress;
    }
}

parser parse_qinq_vlan {
    extract(vlan_tag_[1]);
    return select(latest.etherType) {
        PARSE_ETHERTYPE_MINUS_VLAN;
    }
}

#define MPLS_DEPTH 3
/* all the tags but the last one */
header mpls_t mpls[MPLS_DEPTH];

/* TODO: this will be optimized when pushed to the chip ? */
parser parse_mpls {
#ifndef MPLS_DISABLE
    extract(mpls[next]);
    return select(latest.bos) {
        0 : parse_mpls;
        1 : parse_mpls_bos;
        default: ingress;
    }
#else
    return ingress;
#endif
}

parser parse_mpls_bos {
    //TODO: last keyword is not supported in compiler yet.
    // replace mpls[0] to mpls[last]
//#ifndef __TARGET_TOFINO__
//    return select(mpls[0].label) {
//        0 : parse_inner_ipv4;
//        2 : parse_inner_ipv6;
//        0x20000 mask 0xc0000 : parse_mpls_inner_ipv4;
//        0x40000 mask 0xc0000 : parse_mpls_inner_ipv6;
//        0x60000 mask 0xc0000 : parse_vpls;
//        0x80000 mask 0xc0000 : parse_eompls;
//        0xa0000 mask 0xc0000 : parse_pw;
//        default : parse_eompls;
//    }
//#else
    return select(current(0, 4)) {
#ifndef MPLS_DISABLE
        0x4 : parse_mpls_inner_ipv4;
        0x6 : parse_mpls_inner_ipv6;
#endif
        default: parse_eompls;
    }
//#endif
}

parser parse_mpls_udp {
    set_metadata(tunnel_metadata.mpls_in_udp, TRUE);
    return parse_mpls;
}

parser parse_mpls_inner_ipv4 {
    set_metadata(tunnel_metadata.ingress_tunnel_type, INGRESS_TUNNEL_TYPE_MPLS);
    return parse_inner_ipv4;
}

parser parse_mpls_inner_ipv6 {
    set_metadata(tunnel_metadata.ingress_tunnel_type, INGRESS_TUNNEL_TYPE_MPLS);
    return parse_inner_ipv6;
}

parser parse_vpls {
    return ingress;
}

parser parse_pw {
    return ingress;
}

#define IP_PROTOCOLS_ICMP              1
#define IP_PROTOCOLS_IGMP              2
#define IP_PROTOCOLS_IPV4              4
#define IP_PROTOCOLS_TCP               6
#define IP_PROTOCOLS_UDP               17
#define IP_PROTOCOLS_IPV6              41
#define IP_PROTOCOLS_SR                43
#define IP_PROTOCOLS_GRE               47
#define IP_PROTOCOLS_IPSEC_ESP         50
#define IP_PROTOCOLS_IPSEC_AH          51
#define IP_PROTOCOLS_ICMPV6            58
#define IP_PROTOCOLS_EIGRP             88
#define IP_PROTOCOLS_OSPF              89
#define IP_PROTOCOLS_ETHERIP           97
#define IP_PROTOCOLS_PIM               103
#define IP_PROTOCOLS_VRRP              112

#define IP_PROTOCOLS_IPHL_ICMP         0x501
#define IP_PROTOCOLS_IPHL_IPV4         0x504
#define IP_PROTOCOLS_IPHL_TCP          0x506
#define IP_PROTOCOLS_IPHL_UDP          0x511
#define IP_PROTOCOLS_IPHL_IPV6         0x529
#define IP_PROTOCOLS_IPHL_GRE          0x52f


// This ensures hdrChecksum and protocol fields are allocated to different
// containers so that the deparser can calculate the IPv4 checksum correctly.
// We are enforcing a stronger constraint than necessary. In reality, even if
// protocol and hdrChecksum are allocated to the same 32b container, it is OK
// as long as hdrChecksum occupies the first or last 16b. It should just not be
// in the middle of the 32b container. But, there is no pragma to enforce such
// a constraint precisely. So, using pa_fragment.
@pragma pa_fragment ingress ipv4.hdrChecksum
@pragma pa_fragment egress ipv4.hdrChecksum
header ipv4_t ipv4;

field_list ipv4_checksum_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
#ifdef __TARGET_TOFINO__
    verify ipv4_checksum;
    update ipv4_checksum;
#else
    verify ipv4_checksum if (ipv4.ihl == 5);
    update ipv4_checksum if (ipv4.ihl == 5);
#endif
}

#ifdef INT_L45_ENABLE

#define INTL45_DIFFSERV       0x5c
#define INTL45_DIFFSERV_MASK  0xfc

@pragma parser_value_set_size 1
parser_value_set int_diffserv; // default value: 0x5c, mask: 0xfc

parser parse_ipv4 {
   return select(current(8,8)){ //ipv4.diffserv
       int_diffserv: parse_intl45_ipv4;
       default: parse_ipv4_original;
    }
}
#endif

#ifdef INT_L45_ENABLE
parser parse_ipv4_original {
#else
parser parse_ipv4 {
#endif
    extract(ipv4);
#if defined(TUNNEL_PARSING_DISABLE)
    set_metadata(l3_metadata.lkp_ip_proto, latest.protocol);
    set_metadata(l3_metadata.lkp_ip_ttl, latest.ttl);
    //    set_metadata(l3_metadata.lkp_dscp, latest.diffserv);
#endif /* TUNNEL_PARSING_DISABLE */
    return select(latest.fragOffset, latest.ihl, latest.protocol) {
        IP_PROTOCOLS_IPHL_ICMP : parse_icmp;
        IP_PROTOCOLS_IPHL_TCP : parse_tcp;
        IP_PROTOCOLS_IPHL_UDP : parse_udp;

#if !defined(TUNNEL_DISABLE) || !defined(MIRROR_DISABLE)
        IP_PROTOCOLS_IPHL_GRE : parse_gre;
#endif /* !TUNNEL_DISABLE || INT_EP_ENABLE */
#ifndef TUNNEL_DISABLE
        IP_PROTOCOLS_IPHL_IPV4 : parse_ipv4_in_ip;
        IP_PROTOCOLS_IPHL_IPV6 : parse_ipv6_in_ip;
#endif /* TUNNEL_DISABLE */
        IP_PROTOCOLS_IGMP : parse_igmp;
        IP_PROTOCOLS_EIGRP : parse_set_prio_med;
        IP_PROTOCOLS_OSPF : parse_set_prio_med;
        IP_PROTOCOLS_PIM : parse_set_prio_med;
        IP_PROTOCOLS_VRRP : parse_set_prio_med;
        default: ingress;
    }
}

parser parse_ipv4_in_ip {
    set_metadata(tunnel_metadata.ingress_tunnel_type,
                 INGRESS_TUNNEL_TYPE_IP_IN_IP);
    return parse_inner_ipv4;
}

parser parse_ipv6_in_ip {
    set_metadata(tunnel_metadata.ingress_tunnel_type,
                 INGRESS_TUNNEL_TYPE_IP_IN_IP);
    return parse_inner_ipv6;
}

#define UDP_PORT_BOOTPS                67
#define UDP_PORT_BOOTPC                68
#define UDP_PORT_RIP                   520
#define UDP_PORT_RIPNG                 521
#define UDP_PORT_DHCPV6_CLIENT         546
#define UDP_PORT_DHCPV6_SERVER         547
#define UDP_PORT_HSRP                  1985
#define UDP_PORT_BFD_1HOP              3784
#define UDP_PORT_BFD_ECHO              3785
#define UDP_PORT_LISP                  4341
#define UDP_PORT_BFD_MHOP              4784
#define UDP_PORT_VXLAN                 4789
#define UDP_PORT_VXLAN_GPE             4790
#define UDP_PORT_ROCE_V2               4791
#define UDP_PORT_GENV                  6081
#define UDP_PORT_SFLOW                 6343
#define UDP_PORT_MPLS                  6635

#if defined(FAST_FAILOVER_PROFILE)
@pragma pa_container_size egress ipv6.dstAddr 32
#endif
#if defined(MSDC_SPINE_TELEMETRY_INT_PROFILE)
@pragma pa_no_overlay ingress ipv6.dstAddr
#endif
header ipv6_t ipv6;

header myFlow_t myFlow;

parser parse_myFlow {
    extract(myFlow);
    return ingress;
}

parser parse_udp_v6 {
    extract(udp);
    set_metadata(l3_metadata.lkp_outer_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_outer_l4_dport, latest.dstPort);
    return select(latest.dstPort) {
        UDP_PORT_BOOTPS : parse_set_prio_med;
        UDP_PORT_BOOTPC : parse_set_prio_med;
        UDP_PORT_DHCPV6_CLIENT : parse_set_prio_med;
        UDP_PORT_DHCPV6_SERVER : parse_set_prio_med;
        UDP_PORT_RIP : parse_set_prio_med;
        UDP_PORT_RIPNG : parse_set_prio_med;
        UDP_PORT_HSRP : parse_set_prio_med;
        default: ingress;
    }
}

parser parse_gre_v6 {
    extract(gre);
    return select(latest.C, latest.R, latest.K, latest.S, latest.s,
                  latest.recurse, latest.flags, latest.ver, latest.proto) {
#if !defined(TUNNEL_PARSING_DISABLE)
        ETHERTYPE_IPV4 : parse_gre_ipv4;
#endif /* !TUNNEL_PARSING_DISABLE */
        default: ingress;
    }
}

parser parse_ipv6 {
#ifndef IPV6_DISABLE
    extract(ipv6);
#if defined(TUNNEL_PARSING_DISABLE)
    set_metadata(l3_metadata.lkp_ip_proto, latest.nextHdr);
    set_metadata(l3_metadata.lkp_ip_ttl, latest.hopLimit);
    //    set_metadata(l3_metadata.lkp_dscp, latest.trafficClass);
#endif /* TUNNEL_PARSING_DISABLE */
    return select(latest.nextHdr) {
        IP_PROTOCOLS_ICMPV6 : parse_icmp;
        IP_PROTOCOLS_TCP : parse_tcp;
#if !defined(TUNNEL_PARSING_DISABLE)
        IP_PROTOCOLS_IPV4 : parse_ipv4_in_ip;
#ifdef SRV6_ENABLE
        IP_PROTOCOLS_SR : parse_ipv6_srh;
#endif
#ifndef IPV6_TUNNEL_DISABLE
        IP_PROTOCOLS_UDP : parse_udp;
        IP_PROTOCOLS_GRE : parse_gre;
        IP_PROTOCOLS_IPV6 : parse_ipv6_in_ip;
#else
        IP_PROTOCOLS_UDP : parse_udp_v6;
        IP_PROTOCOLS_GRE : parse_gre_v6;
#endif
#endif /* !TUNNEL_PARSING_DISABLE */
        IP_PROTOCOLS_EIGRP : parse_set_prio_med;
        IP_PROTOCOLS_OSPF : parse_set_prio_med;
        IP_PROTOCOLS_PIM : parse_set_prio_med;
        IP_PROTOCOLS_VRRP : parse_set_prio_med;

        default: ingress;
    }
#else
    return ingress;
#endif /* IPV6_DISABLE */
}

#ifdef SRV6_ENABLE
#define SRH_MAX_SEGMENTS 3
header ipv6_srh_t ipv6_srh;
header ipv6_srh_segment_t ipv6_srh_seg_list[SRH_MAX_SEGMENTS];

parser parse_ipv6_srh {
    extract(ipv6_srh);
    return select(latest.firstSeg, latest.segLeft) {
        0x0001 mask 0x00ff : parse_active_segment_0;  // SRH.SL = 1
        default : parse_segment_before_0;
    }
}

parser parse_segment_before_0 {
    extract(ipv6_srh_seg_list[0]);
    return select(ipv6_srh.firstSeg, ipv6_srh.segLeft) {
        0 : parse_srh_next_hdr;   // SRH.SL = 0
        0x0002 mask 0x00ff : parse_active_segment_1;  // SRH.SL = 2
        default : parse_segment_before_1;
    }
}

parser parse_segment_before_1 {
    extract(ipv6_srh_seg_list[1]);
    return select(ipv6_srh.firstSeg, ipv6_srh.segLeft) {
        0x0100 : parse_srh_next_hdr;  // SRH.SL = 0
        0x0100 mask 0xff00 : ingress;
        default : parse_segment_before_2;
    }
}

parser parse_segment_before_2 {
    extract(ipv6_srh_seg_list[2]);
    return select(ipv6_srh.firstSeg, ipv6_srh.segLeft) {
        0x0200 : parse_srh_next_hdr;  // SRH.SL = 0
        default : ingress;            // Invalid SRH
    }
}

parser parse_segment_after_1 {
    extract(ipv6_srh_seg_list[1]);
    return select(ipv6_srh.firstSeg) {
      0 : ingress;  // Invalid SRH
      1 : ingress;
      default : parse_segment_after_2;
    }
}

parser parse_segment_after_2 {
    extract(ipv6_srh_seg_list[2]);
    return ingress;
}

parser parse_active_segment_0 {
    extract(ipv6_srh_seg_list[0]);
    set_metadata(ipv6_metadata.lkp_ipv6_da, latest.sid);
    return select(ipv6_srh.firstSeg) {
        1 : ingress;
        default : parse_segment_after_1;
    }

}

parser parse_active_segment_1 {
    extract(ipv6_srh_seg_list[1]);
    set_metadata(ipv6_metadata.lkp_ipv6_da, latest.sid);
    return select(ipv6_srh.firstSeg) {
        0 : ingress;  // Invalid SRH
        1 : ingress;  // Invalid SRH
        default : parse_segment_after_2;
    }
}

parser parse_srh_next_hdr {
    return select(ipv6_srh.nextHdr) {
        IP_PROTOCOLS_IPV6 : parse_ipv6_in_srh;
        IP_PROTOCOLS_IPV4 : parse_ipv4_in_srh;
        default: ingress;
    }
}

parser parse_ipv6_in_srh {
    set_metadata(tunnel_metadata.ingress_tunnel_type,
                 INGRESS_TUNNEL_TYPE_SRV6);
    return parse_inner_ipv6;
}

parser parse_ipv4_in_srh {
    set_metadata(tunnel_metadata.ingress_tunnel_type,
                 INGRESS_TUNNEL_TYPE_SRV6);
    return parse_inner_ipv4;
}

#endif /* SRV6_ENABLE */

header icmp_t icmp;

#ifdef INT_L4_CHECKSUM_UPDATE
field_list icmp_checksum_list {
    icmp.typeCode;
    payload;
}

field_list_calculation icmp_checksum {
    input {
        icmp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field icmp.hdrChecksum {
    update icmp_checksum;
}
#endif /* INT_L4_CHECKSUM_UPDATE */

parser parse_icmp {
    extract(icmp);
#if defined(TUNNEL_PARSING_DISABLE)
    set_metadata(l3_metadata.lkp_l4_sport, latest.typeCode);
#else
    set_metadata(l3_metadata.lkp_outer_l4_sport, latest.typeCode);
#endif /* TUNNEL_PARSING_DISABLE */
    return select(latest.typeCode) {
        /* MLD and ND, 130-136 */
        0x8200 mask 0xfe00 : parse_set_prio_med;
        0x8400 mask 0xfc00 : parse_set_prio_med;
        0x8800 mask 0xff00 : parse_set_prio_med;
        default: ingress;
    }
}

header igmp_t igmp;

#ifdef INT_L4_CHECKSUM_UPDATE
field_list igmp_checksum_list {
    igmp.typeCode;
    payload;
}

field_list_calculation igmp_checksum {
    input {
        igmp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field igmp.hdrChecksum {
    update igmp_checksum;
}
#endif /* INT_L4_CHECKSUM_UPDATE */

parser parse_igmp {
    extract(igmp);
    set_metadata(l3_metadata.lkp_outer_l4_sport, latest.typeCode);
    return ingress;
}

#define TCP_PORT_BGP                   179
#define TCP_PORT_MSDP                  639
#define TCP_PORT_MYFLOW                 640

@pragma pa_fragment egress tcp.checksum
@pragma pa_fragment egress tcp.urgentPtr
header tcp_t tcp;

#ifdef INT_L4_CHECKSUM_UPDATE
field_list tcp_checksum_list {
    ipv4.srcAddr;
    ipv4.dstAddr;
    8'0;
    ipv4.protocol;
    int_metadata.l4_len;
    tcp.srcPort;
    tcp.dstPort;
    tcp.seqNo;
    tcp.ackNo;
    tcp.dataOffset;
    tcp.res;
    tcp.flags;
    tcp.window;
    tcp.urgentPtr;
    payload;
}

field_list_calculation tcp_checksum {
    input {
        tcp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum {
    update tcp_checksum;
}
#endif /* INT_L4_CHECKSUM_UPDATE */

#ifndef NAT_DISABLE
field_list tcp_checksum_list {
    ipv4.srcAddr;
    ipv4.dstAddr;
    8'0;
    ipv4.protocol;
    nat_metadata.l4_len;
    tcp.srcPort;
    tcp.dstPort;
    tcp.seqNo;
    tcp.ackNo;
    tcp.dataOffset;
    tcp.res;
    tcp.flags;
    tcp.window;
    tcp.urgentPtr;
    payload;
}

field_list_calculation tcp_checksum {
    input {
        tcp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum {
    update tcp_checksum if (nat_metadata.update_tcp_checksum == 1);
}
#endif

parser parse_tcp {
    extract(tcp);
#if defined(TUNNEL_PARSING_DISABLE)
    set_metadata(l3_metadata.lkp_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_l4_dport, latest.dstPort);
    set_metadata(l3_metadata.lkp_tcp_flags, latest.flags);
#else
    set_metadata(l3_metadata.lkp_outer_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_outer_l4_dport, latest.dstPort);
    set_metadata(l3_metadata.lkp_outer_tcp_flags, latest.flags);
#endif /* TUNNEL_PARSING_DISABLE */
    return select(latest.dstPort) {
        TCP_PORT_BGP : parse_set_prio_med;
        TCP_PORT_MSDP : parse_set_prio_med;
        //TCP_PORT_MYFLOW : parse_myFlow;
        default: ingress;
    }
}

header roce_v2_header_t roce_v2;

parser parse_roce_v2 {
    extract(roce_v2);
// don't parse entire header, if not required
//    set_metadata(l3_metadata.rocev2_opcode, current(0, 8));
//    set_metadata(l3_metadata.rocev2_nak, current(96, 8));
    return ingress;
}

#ifdef NAT_ENABLE
@pragma pa_fragment egress udp.checksum
#endif
header udp_t udp;

#ifndef NAT_DISABLE
field_list udp_checksum_list {
    ipv4.srcAddr;
    ipv4.dstAddr;
    8'0;
    ipv4.protocol;
#if !defined(__TARGET_TOFINO__) || defined(BMV2TOFINO)
    udp.length_;
#else
    nat_metadata.l4_len;
#endif
    udp.srcPort;
    udp.dstPort;
    udp.length_ ;
    payload;
}

field_list_calculation udp_checksum {
    input {
        udp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field udp.checksum {
    update udp_checksum if (nat_metadata.update_udp_checksum == 1);
}
#endif

parser parse_udp {
    extract(udp);
#if defined(TUNNEL_PARSING_DISABLE)
    set_metadata(l3_metadata.lkp_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_l4_dport, latest.dstPort);
#else
    set_metadata(l3_metadata.lkp_outer_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_outer_l4_dport, latest.dstPort);
#endif /* TUNNEL_PARSING_DISABLE */
    return select(latest.dstPort) {
#if !defined(TUNNEL_PARSING_DISABLE)
#if !defined(TUNNEL_DISABLE) || defined(TELEMETRY_WATCH_INNER_ENABLE)
        UDP_PORT_VXLAN : parse_vxlan;
#ifndef GENEVE_DISABLE
        UDP_PORT_GENV : parse_geneve;
#endif /* GENEVE DISABLE */
#ifdef MPLS_UDP_ENABLE
        UDP_PORT_MPLS : parse_mpls_udp;
#endif
#endif /* !TUNNEL_DISABLE || TELEMETRY_WATCH_INNER_ENABLE */
#if defined(INT_ENABLE) && !defined(INT_L45_ENABLE)
        // vxlan-gpe is only supported in the context of INT at this time
        UDP_PORT_VXLAN_GPE : parse_vxlan_gpe;
#endif
#ifdef ADV_FEATURES
        UDP_PORT_ROCE_V2: parse_roce_v2;
        UDP_PORT_LISP : parse_lisp;
#endif
#endif /* !TUNNEL_PARSING_DISABLE */
        UDP_PORT_BOOTPS : parse_set_prio_med;
        UDP_PORT_BOOTPC : parse_set_prio_med;
        UDP_PORT_DHCPV6_CLIENT : parse_set_prio_med;
        UDP_PORT_DHCPV6_SERVER : parse_set_prio_med;
        UDP_PORT_RIP : parse_set_prio_med;
        UDP_PORT_RIPNG : parse_set_prio_med;
        UDP_PORT_HSRP : parse_set_prio_med;
        UDP_PORT_SFLOW : parse_sflow;
#ifdef BFD_OFFLOAD_ENABLE
        UDP_PORT_BFD_1HOP : parse_bfd;
        UDP_PORT_BFD_MHOP : parse_bfd;
        UDP_PORT_BFD_ECHO : parse_bfd;
#endif
        default: ingress;
        // For deparser only
#ifdef TELEMETRY_REPORT_ENABLE
        0 : parse_telemetry_report;
#endif
    }
}

header sctp_t sctp;

parser parse_sctp {
    extract(sctp);
    return ingress;
}

#define GRE_PROTOCOLS_NVGRE            0x20006558
#define GRE_PROTOCOLS_ERSPAN_T3        0x22EB   /* Type III version 2 */

header gre_t gre;

parser parse_gre {
    extract(gre);
    return select(latest.C, latest.R, latest.K, latest.S, latest.s,
                  latest.recurse, latest.flags, latest.ver, latest.proto) {
#if !defined(TUNNEL_PARSING_DISABLE)
#ifndef NVGRE_DISABLE
        GRE_PROTOCOLS_NVGRE : parse_nvgre;
#endif
        ETHERTYPE_IPV4 : parse_gre_ipv4;
        ETHERTYPE_IPV6 : parse_gre_ipv6;
#endif /* !TUNNEL_PARSING_DISABLE */
        GRE_PROTOCOLS_ERSPAN_T3 : parse_erspan_t3;
#ifdef ADV_FEATURES
        ETHERTYPE_NSH : parse_nsh;
#endif
        default: ingress;
    }
}

parser parse_gre_ipv4 {
    set_metadata(tunnel_metadata.ingress_tunnel_type, INGRESS_TUNNEL_TYPE_GRE);
    return parse_inner_ipv4;
}

parser parse_gre_ipv6 {
    set_metadata(tunnel_metadata.ingress_tunnel_type, INGRESS_TUNNEL_TYPE_GRE);
    return parse_inner_ipv6;
}

header nvgre_t nvgre;
header ethernet_t inner_ethernet;

// See comment above pa_fragment for outer IPv4 header.
@pragma pa_fragment ingress inner_ipv4.hdrChecksum
@pragma pa_fragment egress inner_ipv4.hdrChecksum
header ipv4_t inner_ipv4;
header ipv6_t inner_ipv6;

field_list inner_ipv4_checksum_list {
        inner_ipv4.version;
        inner_ipv4.ihl;
        inner_ipv4.diffserv;
        inner_ipv4.totalLen;
        inner_ipv4.identification;
        inner_ipv4.flags;
        inner_ipv4.fragOffset;
        inner_ipv4.ttl;
        inner_ipv4.protocol;
        inner_ipv4.srcAddr;
        inner_ipv4.dstAddr;
}

field_list_calculation inner_ipv4_checksum {
    input {
        inner_ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field inner_ipv4.hdrChecksum {
#ifdef __TARGET_TOFINO__
    verify inner_ipv4_checksum;
    update inner_ipv4_checksum;
#else
    verify inner_ipv4_checksum if (inner_ipv4.ihl == 5);
    update inner_ipv4_checksum if (inner_ipv4.ihl == 5);
#endif
}

header udp_t outer_udp;

parser parse_nvgre {
    extract(nvgre);
    set_metadata(tunnel_metadata.ingress_tunnel_type,
                 INGRESS_TUNNEL_TYPE_NVGRE);
    set_metadata(tunnel_metadata.tunnel_vni, latest.tni);
    return parse_inner_ethernet;
}

header erspan_header_t3_t erspan_t3_header;

parser parse_erspan_t3 {
    extract(erspan_t3_header);
    return select(latest.ft_d_other) {
        0x000 mask 0x7c01:  parse_inner_ethernet;
#if !defined(TUNNEL_PARSING_DISABLE)
        0x800 mask 0x7c01:  parse_inner_ipv4;
#endif /* !TUNNEL_PARSING_DISABLE */
        default : ingress;
    }
}

parser parse_arp_rarp_req {
    set_metadata(l2_metadata.arp_opcode, ARP_OPCODE_REQ);
    return parse_set_prio_med;
}

parser parse_arp_rarp_res {
    set_metadata(l2_metadata.arp_opcode, ARP_OPCODE_RES);
    return parse_set_prio_med;
}

parser parse_arp_rarp {
    return select (current(48,16)) {
      0x1 : parse_arp_rarp_req;
      0x2 : parse_arp_rarp_res;
      default : ingress;
    }
}

header eompls_t eompls;

parser parse_eompls {
    //extract(eompls);
    set_metadata(tunnel_metadata.ingress_tunnel_type, INGRESS_TUNNEL_TYPE_MPLS);
    return parse_inner_ethernet;
}

header vxlan_t vxlan;

parser parse_vxlan {
    extract(vxlan);
    set_metadata(tunnel_metadata.ingress_tunnel_type,
                 INGRESS_TUNNEL_TYPE_VXLAN);
    set_metadata(tunnel_metadata.tunnel_vni, latest.vni);
    return parse_inner_ethernet;
}

#ifdef INT_ENABLE
header vxlan_gpe_t vxlan_gpe;

parser parse_vxlan_gpe {
    extract(vxlan_gpe);
    set_metadata(tunnel_metadata.ingress_tunnel_type,
                 INGRESS_TUNNEL_TYPE_VXLAN_GPE);
    set_metadata(tunnel_metadata.tunnel_vni, latest.vni);
#ifndef __TARGET_BMV2__
    return select(vxlan_gpe.flags, vxlan_gpe.next_proto)
#else
    return select(vxlan_gpe.next_proto)
#endif
    {
        default : parse_inner_ethernet;
    }
}
#endif

header genv_t genv;

parser parse_geneve {
    extract(genv);
    set_metadata(tunnel_metadata.tunnel_vni, latest.vni);
    set_metadata(tunnel_metadata.ingress_tunnel_type,
                 INGRESS_TUNNEL_TYPE_GENEVE);
    return select(genv.ver, genv.optLen, genv.protoType) {
        ETHERTYPE_ETHERNET : parse_inner_ethernet;
        ETHERTYPE_IPV4 : parse_inner_ipv4;
        ETHERTYPE_IPV6 : parse_inner_ipv6;
        default : ingress;
    }
}

header nsh_t nsh;
header nsh_context_t nsh_context;

parser parse_nsh {
    extract(nsh);
    extract(nsh_context);
    return select(nsh.protoType) {
        ETHERTYPE_IPV4 : parse_inner_ipv4;
        ETHERTYPE_IPV6 : parse_inner_ipv6;
        ETHERTYPE_ETHERNET : parse_inner_ethernet;
        default : ingress;
    }
}

header lisp_t lisp;

parser parse_lisp {
    extract(lisp);
    return select(current(0, 4)) {
        0x4 : parse_inner_ipv4;
        0x6 : parse_inner_ipv6;
        default : ingress;
    }
}

parser parse_inner_ipv4 {
    extract(inner_ipv4);
    set_metadata(ipv4_metadata.lkp_ipv4_sa, latest.srcAddr);
    set_metadata(ipv4_metadata.lkp_ipv4_da, latest.dstAddr);
    set_metadata(l3_metadata.lkp_ip_proto, latest.protocol);
    set_metadata(l3_metadata.lkp_ip_ttl, latest.ttl);
    return select(latest.fragOffset, latest.ihl, latest.protocol) {
        IP_PROTOCOLS_IPHL_ICMP : parse_inner_icmp;
        IP_PROTOCOLS_IPHL_TCP : parse_inner_tcp;
        IP_PROTOCOLS_IPHL_UDP : parse_inner_udp;
        default: ingress;
    }
}

header inner_l4_ports_t inner_l4_ports;

header icmp_t inner_icmp;

parser parse_inner_icmp {
    extract(inner_icmp);
    set_metadata(l3_metadata.lkp_l4_sport, latest.typeCode);
    return ingress;
}

#define copy_tcp_header(dst_tcp, src_tcp) copy_header(dst_tcp, src_tcp)
@pragma pa_fragment egress inner_tcp.checksum
@pragma pa_fragment egress inner_tcp.urgentPtr
header tcp_t inner_tcp;

header inner_tcp_info_t inner_tcp_info; // fot telemetry use only

parser parse_inner_tcp {
#if defined(TUNNEL_DISABLE) && defined(TELEMETRY_WATCH_INNER_ENABLE)
    extract(inner_l4_ports);
#else
    extract(inner_tcp);
#endif
    set_metadata(l3_metadata.lkp_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_l4_dport, latest.dstPort);
#if defined(TUNNEL_DISABLE) && defined(TELEMETRY_WATCH_INNER_ENABLE)
    extract(inner_tcp_info);
#endif
    set_metadata(l3_metadata.lkp_tcp_flags, latest.flags);
    return ingress;
}

#ifdef NAT_ENABLE
@pragma pa_fragment egress inner_udp.checksum
#endif
header udp_t inner_udp;

#ifndef NAT_DISABLE
field_list inner_udp_checksum_list {
    inner_ipv4.srcAddr;
    inner_ipv4.dstAddr;
    8'0;
    inner_ipv4.protocol;
#if !defined(__TARGET_TOFINO__) || defined(BMV2TOFINO)
    inner_udp.length_;
#else
    nat_metadata.l4_len;
#endif
    inner_udp.srcPort;
    inner_udp.dstPort;
    inner_udp.length_ ;
    payload;
}

field_list_calculation inner_udp_checksum {
    input {
        inner_udp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field inner_udp.checksum {
    update inner_udp_checksum if (nat_metadata.update_inner_udp_checksum == 1);
}
#endif

parser parse_inner_udp {
#if defined(TUNNEL_DISABLE) && defined(TELEMETRY_WATCH_INNER_ENABLE)
    extract(inner_l4_ports);
#else
    extract(inner_udp);
#endif
    set_metadata(l3_metadata.lkp_l4_sport, latest.srcPort);
    set_metadata(l3_metadata.lkp_l4_dport, latest.dstPort);
    return ingress;
}

header sctp_t inner_sctp;

parser parse_inner_sctp {
    extract(inner_sctp);
    return ingress;
}

parser parse_inner_ipv6 {
#ifndef IPV6_DISABLE
    extract(inner_ipv6);
    set_metadata(ipv6_metadata.lkp_ipv6_sa, latest.srcAddr);
    set_metadata(ipv6_metadata.lkp_ipv6_da, latest.dstAddr);
    set_metadata(l3_metadata.lkp_ip_proto, latest.nextHdr);
    set_metadata(l3_metadata.lkp_ip_ttl, latest.hopLimit);
    return select(latest.nextHdr) {
        IP_PROTOCOLS_ICMPV6 : parse_inner_icmp;
        IP_PROTOCOLS_TCP : parse_inner_tcp;
        IP_PROTOCOLS_UDP : parse_inner_udp;
        default: ingress;
    }
#else
    return ingress;
#endif /* IPV6_DISABLE */
}

parser parse_inner_ethernet {
    extract(inner_ethernet);
#ifndef TUNNEL_DISABLE
    set_metadata(l2_metadata.lkp_mac_sa, latest.srcAddr);
    set_metadata(l2_metadata.lkp_mac_da, latest.dstAddr);
#endif
    return select(latest.etherType) {
#if !defined(TUNNEL_PARSING_DISABLE)
        ETHERTYPE_IPV4 : parse_inner_ipv4;
#ifndef IPV6_TUNNEL_DISABLE
        ETHERTYPE_IPV6 : parse_inner_ipv6;
#endif
#endif /* !TUNNEL_PARSING_DISABLE */
        default: ingress;
    }
}

header trill_t trill;

parser parse_trill {
    extract(trill);
    return parse_inner_ethernet;
}

header vntag_t vntag;

parser parse_vntag {
    extract(vntag);
    return parse_inner_ethernet;
}

#ifdef BFD_OFFLOAD_ENABLE
header bfd_t bfd_header;

parser parse_bfd {
    extract(bfd_header);
    return parse_set_prio_max;
}
#endif

header sflow_hdr_t sflow;
header sflow_sample_t sflow_sample;
header sflow_raw_hdr_record_t sflow_raw_hdr_record;

parser parse_sflow {
#ifdef SFLOW_ENABLE
    extract(sflow);
#endif
    return ingress;
}

#if defined(ENT_DC_GENERAL_PROFILE)
@pragma pa_solitary ingress fabric_header_cpu.ingressBd
@pragma pa_solitary ingress fabric_header_cpu.ingressIfindex
@pragma pa_solitary ingress fabric_header_cpu.ingressPort
#endif /* ENT_DC_GENERAL_PROFILE */

header fabric_header_t                  fabric_header;
header fabric_header_unicast_t          fabric_header_unicast;
header fabric_header_multicast_t        fabric_header_multicast;
header fabric_header_mirror_t           fabric_header_mirror;
header fabric_header_cpu_t              fabric_header_cpu;
header fabric_header_sflow_t            fabric_header_sflow;
header fabric_header_bfd_event_t        fabric_header_bfd;
header fabric_payload_header_t          fabric_payload_header;
header fabric_header_timestamp_t        fabric_header_timestamp;

parser parse_fabric_header {
    extract(fabric_header);
#ifdef FABRIC_ENABLE
    return select(latest.packetType) {
        FABRIC_HEADER_TYPE_UNICAST : parse_fabric_header_unicast;
        FABRIC_HEADER_TYPE_MULTICAST : parse_fabric_header_multicast;
        FABRIC_HEADER_TYPE_MIRROR : parse_fabric_header_mirror;
        FABRIC_HEADER_TYPE_CPU : parse_fabric_header_cpu;
        default : ingress;
    }
#else
    return parse_fabric_header_cpu;
#endif /* FABRIC_ENABLE */
}

parser parse_fabric_header_unicast {
    extract(fabric_header_unicast);
    return parse_fabric_payload_header;
}

parser parse_fabric_header_multicast {
    extract(fabric_header_multicast);
    return parse_fabric_payload_header;
}

parser parse_fabric_header_mirror {
    extract(fabric_header_mirror);
    return parse_fabric_payload_header;
}

parser parse_fabric_header_cpu {
    extract(fabric_header_cpu);
    set_metadata(ingress_metadata.bypass_lookups, latest.reasonCode);
    return select(latest.reasonCode) {
#ifdef SFLOW_ENABLE
        CPU_REASON_CODE_SFLOW: parse_fabric_sflow_header;
#endif
#ifdef BFD_OFFLOAD_ENABLE
        CPU_REASON_CODE_BFD_EVENT: parse_fabric_bfd_header;
#endif
#ifdef PTP_ENABLE
        CPU_REASON_CODE_PTP: parse_fabric_timestamp_header;
#endif

        default : parse_fabric_payload_header;
    }
}

#ifdef SFLOW_ENABLE
parser parse_fabric_sflow_header {
    extract(fabric_header_sflow);
    return parse_fabric_payload_header;
}
#endif

#ifdef BFD_OFFLOAD_ENABLE
parser parse_fabric_bfd_header {
    extract(fabric_header_bfd);
    return parse_fabric_payload_header;
}
#endif /* BFD_OFFLOAD_ENABLE */

#ifdef PTP_ENABLE
parser parse_fabric_timestamp_header {
    extract(fabric_header_timestamp);
    return parse_fabric_payload_header;
}
#endif

parser parse_fabric_payload_header {
    extract(fabric_payload_header);
    return select(latest.etherType) {
        0 mask 0xfe00: parse_llc_header;
        0 mask 0xfa00: parse_llc_header;
        PARSE_ETHERTYPE;
    }
}

#define CONTROL_TRAFFIC_PRIO_0         0
#define CONTROL_TRAFFIC_PRIO_1         1
#define CONTROL_TRAFFIC_PRIO_2         2
#define CONTROL_TRAFFIC_PRIO_3         3
#define CONTROL_TRAFFIC_PRIO_4         4
#define CONTROL_TRAFFIC_PRIO_5         5
#define CONTROL_TRAFFIC_PRIO_6         6
#define CONTROL_TRAFFIC_PRIO_7         7

parser parse_set_prio_med {
    set_metadata(ig_prsr_ctrl.priority, CONTROL_TRAFFIC_PRIO_3);
    return ingress;
}

parser parse_set_prio_high {
    set_metadata(ig_prsr_ctrl.priority, CONTROL_TRAFFIC_PRIO_5);
    return ingress;
}

parser parse_set_prio_max {
    set_metadata(ig_prsr_ctrl.priority, CONTROL_TRAFFIC_PRIO_7);
    return ingress;
}

#ifdef COALESCED_MIRROR_ENABLE
header coal_pkt_hdr_t coal_pkt_hdr;

@pragma packet_entry
parser start_coalesced {
    extract(coal_pkt_hdr);
    set_metadata(i2e_metadata.mirror_session_id, coal_pkt_hdr.session_id);
    return ingress;
}
#endif

#include "telemetry_parser.p4"
