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
 * ACL processing : MAC, IPv4, IPv6, RACL/PBR
 */

/*
 * ACL metadata
 */
header_type acl_metadata_t {
    fields {
        acl_deny : 1;                          /* ifacl/vacl deny action */
        racl_deny : 1;                         /* racl deny action */
        egress_acl_deny : 1;                   /* egress acl deny action */
        acl_nexthop : NEXTHOP_BIT_WIDTH;       /* next hop from ifacl/vacl */
        racl_nexthop : NEXTHOP_BIT_WIDTH;      /* next hop from racl */
        acl_nexthop_type : 1;                  /* ecmp or nexthop */
        racl_nexthop_type : 1;                 /* ecmp or nexthop */
        acl_redirect :   1;                    /* ifacl/vacl redirect action */
        racl_redirect : 1;                     /* racl redirect action */
        port_lag_label : 16;		       /* port/lag label for acls */
        //if_label : 16;                         /* if label for acls */
        bd_label : 16;                         /* bd label for acls */
        acl_stats_index : 14;                  /* acl stats index */
        mirror_acl_stats_index : 14;           /* mirror acl stats index */
        racl_stats_index : 14;                 /* ingress racl stats index */
        egress_acl_stats_index : 14;           /* egress acl stats index */
        acl_partition_index : 16;              /* acl atcam partition index */
        egress_port_lag_label : 16;	       /* port/lag label for acls */
        //egress_if_label : 16;                  /* if label for egress acls */
        egress_bd_label : 16;                  /* bd label for egress acls */
        ingress_src_port_range_id : 8;         /* ingress src port range id */
        ingress_dst_port_range_id : 8;         /* ingress dst port range id */
        egress_src_port_range_id : 8;          /* egress src port range id */
        egress_dst_port_range_id : 8;          /* egress dst port range id */
    }
}

#define INGRESS_ACL_KEY_PORT_LABEL       acl_metadata.port_lag_label 
#define INGRESS_ACL_KEY_BD_LABEL         acl_metadata.bd_label
#define INGRESS_ACL_KEY_MAC_SA           l2_metadata.lkp_mac_sa
#define INGRESS_ACL_KEY_MAC_DA           l2_metadata.lkp_mac_da
#define INGRESS_ACL_KEY_PCP              l2_metadata.lkp_pcp
//#define INGRESS_ACL_KEY_CFI              l2_metadata.lkp_cfi
#define INGRESS_ACL_KEY_ETYPE            l2_metadata.lkp_mac_type
#define INGRESS_ACL_KEY_IPV4_SA          ipv4_metadata.lkp_ipv4_sa
#define INGRESS_ACL_KEY_IPV4_DA          ipv4_metadata.lkp_ipv4_da
#define INGRESS_ACL_KEY_IPV6_SA          ipv6_metadata.lkp_ipv6_sa
#define INGRESS_ACL_KEY_IPV6_DA          ipv6_metadata.lkp_ipv6_da
#define INGRESS_ACL_KEY_IP_PROTO         l3_metadata.lkp_ip_proto
#define INGRESS_ACL_KEY_IP_DSCP          l3_metadata.lkp_dscp
#define INGRESS_ACL_KEY_IP_TTL           l3_metadata.lkp_ip_ttl
#ifdef TUNNEL_DISABLE
#define INGRESS_ACL_KEY_TCP_FLAGS        tcp.flags
#else
#define INGRESS_ACL_KEY_TCP_FLAGS        l3_metadata.lkp_tcp_flags
#endif
#define INGRESS_ACL_KEY_SRC_PORT_RANGE   acl_metadata.ingress_src_port_range_id
#define INGRESS_ACL_KEY_DST_PORT_RANGE   acl_metadata.ingress_dst_port_range_id
#define INGRESS_ACL_KEY_FC_SID           fcoe_fc.s_id
#define INGRESS_ACL_KEY_FC_DID           fcoe_fc.d_id
#define INGRESS_ACL_KEY_FIP_OPER_CODE    fip.oper_code

#define INGRESS_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_MAC_SA           : ternary; \
        INGRESS_ACL_KEY_MAC_DA           : ternary; \
        INGRESS_ACL_KEY_ETYPE            : ternary; \
        INGRESS_ACL_KEY_IPV4_SA          : ternary; \
        INGRESS_ACL_KEY_IPV4_DA          : ternary; \
        INGRESS_ACL_KEY_IPV6_SA          : ternary; \
        INGRESS_ACL_KEY_IPV6_DA          : ternary; \
        INGRESS_ACL_KEY_IP_PROTO         : ternary; \
        INGRESS_ACL_KEY_IP_DSCP          : ternary; \
        INGRESS_ACL_KEY_TCP_FLAGS        : ternary; \
        INGRESS_ACL_KEY_SRC_PORT_RANGE   : ternary; \
        INGRESS_ACL_KEY_DST_PORT_RANGE   : ternary;

#define INGRESS_MAC_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_MAC_SA           : ternary; \
        INGRESS_ACL_KEY_MAC_DA           : ternary; \
        INGRESS_ACL_KEY_ETYPE            : ternary; 

#define INGRESS_FCOE_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_MAC_SA           : ternary; \
        INGRESS_ACL_KEY_MAC_DA           : ternary; \
        INGRESS_ACL_KEY_ETYPE            : ternary; \
        INGRESS_ACL_KEY_FC_SID           : ternary; \
        INGRESS_ACL_KEY_FC_DID           : ternary; \
        INGRESS_ACL_KEY_FIP_OPER_CODE    : ternary;

#define INGRESS_IPV4_ACL_KEY			    \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_IPV4_SA          : ternary; \
        INGRESS_ACL_KEY_IPV4_DA          : ternary; \
        INGRESS_ACL_KEY_IP_PROTO         : ternary; \
        INGRESS_ACL_KEY_IP_TTL           : ternary; \
        INGRESS_ACL_KEY_TCP_FLAGS        : ternary; \
        INGRESS_ACL_KEY_SRC_PORT_RANGE   : ternary; \
        INGRESS_ACL_KEY_DST_PORT_RANGE   : ternary;

#define INGRESS_IPV6_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_BD_LABEL         : ternary; \
        INGRESS_ACL_KEY_IPV6_SA          : ternary; \
        INGRESS_ACL_KEY_IPV6_DA          : ternary; \
        INGRESS_ACL_KEY_IP_PROTO         : ternary; \
        INGRESS_ACL_KEY_IP_TTL           : ternary; \
        INGRESS_ACL_KEY_TCP_FLAGS        : ternary; \
        INGRESS_ACL_KEY_SRC_PORT_RANGE   : ternary; \
        INGRESS_ACL_KEY_DST_PORT_RANGE   : ternary;

#define INGRESS_MAC_MIRROR_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_MAC_SA           : ternary; \
        INGRESS_ACL_KEY_MAC_DA           : ternary; \
        INGRESS_ACL_KEY_ETYPE            : ternary; \
        INGRESS_ACL_KEY_PCP              : ternary; \

#define INGRESS_IPV4_MIRROR_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_IPV4_SA          : ternary; \
        INGRESS_ACL_KEY_IPV4_DA          : ternary; \
        INGRESS_ACL_KEY_IP_PROTO         : ternary; \
      	INGRESS_ACL_KEY_IP_DSCP          : ternary; \
        INGRESS_ACL_KEY_TCP_FLAGS        : ternary; \
        INGRESS_ACL_KEY_SRC_PORT_RANGE   : ternary;   \
        INGRESS_ACL_KEY_DST_PORT_RANGE   : ternary;

#define INGRESS_IPV6_MIRROR_ACL_KEY \
        INGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        INGRESS_ACL_KEY_IPV6_SA          : ternary; \
        INGRESS_ACL_KEY_IPV6_DA          : ternary; \
        INGRESS_ACL_KEY_IP_PROTO         : ternary; \
        INGRESS_ACL_KEY_IP_DSCP          : ternary; \
        INGRESS_ACL_KEY_TCP_FLAGS        : ternary; \
        INGRESS_ACL_KEY_SRC_PORT_RANGE   : ternary; \
        INGRESS_ACL_KEY_DST_PORT_RANGE   : ternary;

#define EGRESS_ACL_KEY_PORT_LABEL            acl_metadata.egress_port_lag_label
#define EGRESS_ACL_KEY_BD_LABEL              acl_metadata.egress_bd_label
#define EGRESS_ACL_KEY_MAC_SA                ethernet.srcAddr
#define EGRESS_ACL_KEY_MAC_DA                ethernet.dstAddr
#define EGRESS_ACL_KEY_ETYPE                 ethernet.etherType
#define EGRESS_ACL_KEY_IPV4_SA               ipv4.srcAddr
#define EGRESS_ACL_KEY_IPV4_DA               ipv4.dstAddr
#define EGRESS_ACL_KEY_IPV4_PROTO            ipv4.protocol
#define EGRESS_ACL_KEY_IPV6_SA               ipv6.srcAddr
#define EGRESS_ACL_KEY_IPV6_DA               ipv6.dstAddr
#define EGRESS_ACL_KEY_IPV6_PROTO            ipv6.nextHdr
#ifdef EGRESS_ACL_RANGE_DISABLE
#define EGRESS_ACL_KEY_L4_SPORT_OR_RANGE        l3_metadata.egress_l4_sport
#define EGRESS_ACL_KEY_L4_DPORT_OR_RANGE        l3_metadata.egress_l4_dport
#else
#define EGRESS_ACL_KEY_L4_SPORT_OR_RANGE        acl_metadata.egress_src_port_range_id
#define EGRESS_ACL_KEY_L4_DPORT_OR_RANGE        acl_metadata.egress_dst_port_range_id
#endif /* EGRESS_ACL_RANGE_DISABLE */

#define EGRESS_MAC_ACL_KEY \
        EGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        EGRESS_ACL_KEY_BD_LABEL         : ternary; \
        EGRESS_ACL_KEY_MAC_SA           : ternary; \
        EGRESS_ACL_KEY_MAC_DA           : ternary; \
        EGRESS_ACL_KEY_ETYPE            : ternary; 

#define EGRESS_IPV4_ACL_KEY \
        EGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        EGRESS_ACL_KEY_BD_LABEL         : ternary; \
        EGRESS_ACL_KEY_IPV4_SA          : ternary; \
        EGRESS_ACL_KEY_IPV4_DA          : ternary; \
        EGRESS_ACL_KEY_IPV4_PROTO       : ternary; \
        EGRESS_ACL_KEY_L4_SPORT_OR_RANGE   : ternary; \
        EGRESS_ACL_KEY_L4_DPORT_OR_RANGE   : ternary;
//        EGRESS_ACL_KEY_TCP_FLAGS        : ternary;	\

#define EGRESS_IPV6_ACL_KEY \
        EGRESS_ACL_KEY_PORT_LABEL       : ternary; \
        EGRESS_ACL_KEY_BD_LABEL         : ternary; \
        EGRESS_ACL_KEY_IPV6_SA          : ternary; \
        EGRESS_ACL_KEY_IPV6_DA          : ternary; \
        EGRESS_ACL_KEY_IPV6_PROTO       : ternary; \
        EGRESS_ACL_KEY_L4_SPORT_OR_RANGE   : ternary; \
        EGRESS_ACL_KEY_L4_DPORT_OR_RANGE   : ternary;
//        EGRESS_ACL_KEY_TCP_FLAGS        : ternary;	\


header_type i2e_metadata_t {
    fields {
        ingress_tstamp    : 32;
        mirror_session_id : 10;
    }
}

#ifdef COALESCED_MIRROR_ENABLE
header_type coal_sample_hdr_t {
    // Small header (as an example) added to each coalesced sample
    fields {
        id: 32;
    }
}
header coal_sample_hdr_t coal_sample_hdr;
#endif

@pragma pa_solitary ingress INGRESS_ACL_KEY_PORT_LABEL
@pragma pa_atomic   ingress INGRESS_ACL_KEY_PORT_LABEL

#if defined(MSDC_TELEMETRY_POSTCARD_PROFILE) || defined(TEST_ENT_DC_POSTCARD_PROFILE)
@pragma pa_no_overlay ingress acl_metadata.racl_nexthop
#endif
#ifdef ENT_DC_AGGR_PROFILE
// Temporary Workaround
@pragma pa_container_size egress i2e_metadata.mirror_session_id 16
#endif
metadata acl_metadata_t acl_metadata;
metadata i2e_metadata_t i2e_metadata;

/*****************************************************************************/
/* Egress ACL l4 port range                                                  */
/*****************************************************************************/
#ifdef EGRESS_ACL_ENABLE
action set_egress_tcp_port_fields() {
    modify_field(l3_metadata.egress_l4_sport, tcp.srcPort);
    modify_field(l3_metadata.egress_l4_dport, tcp.dstPort);
}

action set_egress_udp_port_fields() {
    modify_field(l3_metadata.egress_l4_sport, udp.srcPort);
    modify_field(l3_metadata.egress_l4_dport, udp.dstPort);
}

action set_egress_icmp_port_fields() {
    modify_field(l3_metadata.egress_l4_sport, icmp.typeCode);
}

table egress_l4port_fields {
    reads {
        tcp : valid;
        udp : valid;
        icmp : valid;
    }
    actions {
        nop;
        set_egress_tcp_port_fields;
        set_egress_udp_port_fields;
        set_egress_icmp_port_fields;
    }
    size: EGRESS_PORT_LKP_FIELD_SIZE;
}

#if !defined(ACL_RANGE_DISABLE) && !defined(EGRESS_ACL_RANGE_DISABLE)
action set_egress_src_port_range_id(range_id) {
    modify_field(acl_metadata.egress_src_port_range_id, range_id);
}

table egress_l4_src_port {
    reads {
        l3_metadata.egress_l4_sport : range;
    }
    actions {
        nop;
        set_egress_src_port_range_id;
    }
    size: EGRESS_ACL_RANGE_TABLE_SIZE;
}

action set_egress_dst_port_range_id(range_id) {
    modify_field(acl_metadata.egress_dst_port_range_id, range_id);
}

table egress_l4_dst_port {
    reads {
        l3_metadata.egress_l4_dport : range;
    }
    actions {
        nop;
        set_egress_dst_port_range_id;
    }
    size: EGRESS_ACL_RANGE_TABLE_SIZE;
}

#endif /* !ACL_RANGE_DISABLE && !EGRESS_ACL_RANGE_DISABLE */
#endif /* EGRESS_ACL_ENABLE */

control process_egress_l4port {
#ifdef EGRESS_ACL_ENABLE
    apply(egress_l4port_fields);
#ifndef EGRESS_ACL_RANGE_DISABLE
    apply(egress_l4_src_port);
    apply(egress_l4_dst_port);
#endif /* ACL_RANGE_DISABLE */
#endif /* EGRESS_ACL_ENABLE */
}

/*****************************************************************************/
/* Ingress ACL l4 port range                                                 */
/*****************************************************************************/
#ifndef ACL_RANGE_DISABLE
action set_ingress_src_port_range_id(range_id) {
    modify_field(acl_metadata.ingress_src_port_range_id, range_id);
}

table ingress_l4_src_port {
    reads {
        l3_metadata.lkp_l4_sport : range;
    }
    actions {
        nop;
        set_ingress_src_port_range_id;
    }
    size: INGRESS_ACL_RANGE_TABLE_SIZE;
}

action set_ingress_dst_port_range_id(range_id) {
    modify_field(acl_metadata.ingress_dst_port_range_id, range_id);
}

table ingress_l4_dst_port {
    reads {
        l3_metadata.lkp_l4_dport : range;
    }
    actions {
        nop;
        set_ingress_dst_port_range_id;
    }
    size: INGRESS_ACL_RANGE_TABLE_SIZE;
}
#endif /* ACL_RANGE_DISABLE */

control process_ingress_l4port {
#ifndef ACL_RANGE_DISABLE
    apply(ingress_l4_src_port);
    apply(ingress_l4_dst_port);
#endif /* ACL_RANGE_DISABLE */
}

/*****************************************************************************/
/* ACL Actions                                                               */
/*****************************************************************************/
action acl_deny(acl_stats_index, acl_meter_index, acl_copy_reason,
                nat_mode, ingress_cos, tc, color) {
    modify_field(acl_metadata.acl_deny, TRUE);
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
    modify_field(nat_metadata.ingress_nat_mode, nat_mode);
#ifdef ACL_QOS_ENABLE
    modify_field(meter_metadata.meter_index, acl_meter_index);
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* ACL_QOS_ENABLE */

}

action acl_permit(acl_stats_index, acl_meter_index, acl_copy_reason,
                  nat_mode, ingress_cos, tc, color) {
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
    modify_field(nat_metadata.ingress_nat_mode, nat_mode);
#ifdef ACL_QOS_ENABLE
    modify_field(meter_metadata.meter_index, acl_meter_index);
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* ACL_QOS_ENABLE */
}

field_list i2e_mirror_info {
    i2e_metadata.ingress_tstamp;
    i2e_metadata.mirror_session_id;
}

field_list e2e_mirror_info {
    i2e_metadata.ingress_tstamp;
    i2e_metadata.mirror_session_id;
}

action acl_mirror(session_id, acl_stats_index, acl_meter_index, nat_mode,
                  ingress_cos, tc, color) {
    modify_field(i2e_metadata.mirror_session_id, session_id);
    clone_ingress_pkt_to_egress(session_id, i2e_mirror_info);
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
    modify_field(nat_metadata.ingress_nat_mode, nat_mode);
#ifdef ACL_QOS_ENABLE
    modify_field(meter_metadata.meter_index, acl_meter_index);
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* ACL_QOS_ENABLE */
}

action acl_redirect_nexthop(nexthop_index, acl_stats_index, acl_meter_index,
                            acl_copy_reason, nat_mode,
                            ingress_cos, tc, color) {
    modify_field(acl_metadata.acl_redirect, TRUE);
    modify_field(acl_metadata.acl_nexthop, nexthop_index);
    modify_field(acl_metadata.acl_nexthop_type, NEXTHOP_TYPE_SIMPLE);
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
    modify_field(nat_metadata.ingress_nat_mode, nat_mode);
#ifdef ACL_QOS_ENABLE
    modify_field(meter_metadata.meter_index, acl_meter_index);
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* ACL_QOS_ENABLE */
}

action acl_redirect_ecmp(ecmp_index, acl_stats_index, acl_meter_index,
                         acl_copy_reason, nat_mode,
                         ingress_cos, tc, color) {
    modify_field(acl_metadata.acl_redirect, TRUE);
    modify_field(acl_metadata.acl_nexthop, ecmp_index);
    modify_field(acl_metadata.acl_nexthop_type, NEXTHOP_TYPE_ECMP);
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
    modify_field(nat_metadata.ingress_nat_mode, nat_mode);
#ifdef ACL_QOS_ENABLE
    modify_field(meter_metadata.meter_index, acl_meter_index);
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* ACL_QOS_ENABLE */
}

action acl_set_qos_fields(tc, color, acl_meter_index) {
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#if defined(QOS_METERING_ENABLE)
    modify_field(meter_metadata.meter_index, acl_meter_index);
#endif /* QOS_METERING_ENABLE */
}

/*****************************************************************************/
/* MAC ACL                                                                   */
/*****************************************************************************/
#ifndef L2_DISABLE
table mac_acl {
    reads {
        INGRESS_MAC_ACL_KEY
    }
    actions {
        nop;
        acl_deny;
        acl_permit;
        acl_redirect_nexthop;
        acl_redirect_ecmp;
#ifndef MIRROR_DISABLE
        acl_mirror;
#endif /* MIRROR_DISABLE */
    }
    size : INGRESS_MAC_ACL_TABLE_SIZE;
}
#endif /* L2_DISABLE */

control process_mac_acl {
#if !defined(L2_DISABLE) && !defined(INGRESS_MAC_ACL_DISABLE)
    if (DO_LOOKUP(ACL)) {
        apply(mac_acl);
    }
#endif /* L2_DISABLE */
}

/*****************************************************************************/
/* FCOE ACL                                                                  */
/*****************************************************************************/
#ifdef FCOE_ACL_ENABLE
table fcoe_acl {
    reads {
        INGRESS_FCOE_ACL_KEY
    }
    actions {
        nop;
        acl_deny;
        acl_permit;
        acl_redirect_nexthop;
        acl_redirect_ecmp;
    }
    size : INGRESS_FCOE_ACL_TABLE_SIZE;
}

control process_fcoe_acl {
    if (DO_LOOKUP(ACL)) {
        apply(fcoe_acl);
    }
}
#endif

/*****************************************************************************/
/* IPv4 ACL                                                                  */
/*****************************************************************************/
#ifndef IPV4_DISABLE

#ifdef ATCAM
action set_ipv4_acl_partition_index(partition_index) {
    modify_field(acl_metadata.acl_partition_index, partition_index);
}

table ip_acl_partition {
    reads {
        INGRESS_IPV4_ACL_KEY
#ifdef FIB_ACL_LABEL_ENABLE
	  l3_metadata.fib_label : ternary;
#endif /* FIB_ACL_LABEL_ENABLE */
#ifdef ETYPE_IN_IP_ACL_KEY_ENABLE
        l2_metadata.lkp_mac_type : ternary;
#endif
    }
    actions {
        set_ipv4_acl_partition_index;
    }
    size : IPV4_ACL_PARTITION_TABLE_SIZE;
}
#endif /* ATCAM */

#ifdef ATCAM
@pragma atcam_number_partitions IPV4_ACL_PARTITION_TABLE_SIZE
@pragma atcam_partition_index acl_metadata.acl_partition_index
@pragma ways 5
#endif /* ATCAM */

table ip_acl {
    reads {
#ifdef ATCAM
        acl_metadata.acl_partition_index : exact;
#endif /* ATCAM */
        INGRESS_IPV4_ACL_KEY
#ifdef FIB_ACL_LABEL_ENABLE
	  l3_metadata.fib_label : ternary;
#endif /* FIB_ACL_LABEL_ENABLE */
#ifdef ETYPE_IN_IP_ACL_KEY_ENABLE
        l2_metadata.lkp_mac_type : ternary;
#endif
    }
    actions {
        nop;
        acl_deny;
        acl_permit;
        acl_redirect_nexthop;
        acl_redirect_ecmp;
#ifndef MIRROR_DISABLE
        acl_mirror;
#endif /* MIRROR_DISABLE */
    }
    size : INGRESS_IP_ACL_TABLE_SIZE;
}
#endif /* IPV4_DISABLE */


/*****************************************************************************/
/* IPv6 ACL                                                                  */
/*****************************************************************************/
#ifndef IPV6_DISABLE

#ifdef ATCAM
action set_ipv6_acl_partition_index(partition_index) {
    modify_field(acl_metadata.acl_partition_index, partition_index);
}

table ipv6_acl_partition {
    reads {
        INGRESS_IPV6_ACL_KEY
#ifdef FIB_ACL_LABEL_ENABLE
	  l3_metadata.fib_label : ternary;
#endif /* FIB_ACL_LABEL_ENABLE */
#ifdef ETYPE_IN_IP_ACL_KEY_ENABLE
        l2_metadata.lkp_mac_type : ternary;
#endif
    }
    actions {
        set_ipv6_acl_partition_index;
    }
    size : IPV6_ACL_PARTITION_TABLE_SIZE;
}

#endif /* ATCAM */

#ifdef ATCAM
@pragma atcam_number_partitions IPV6_ACL_PARTITION_TABLE_SIZE
@pragma atcam_partition_index acl_metadata.acl_partition_index
@pragma ways 5
#endif /* ATCAM */

table ipv6_acl {
    reads {
#ifdef ATCAM
        acl_metadata.acl_partition_index : exact;
#endif /* ATCAM */
        INGRESS_IPV6_ACL_KEY
#ifdef FIB_ACL_LABEL_ENABLE
	  l3_metadata.fib_label : ternary;
#endif /* FIB_ACL_LABEL_ENABLE */
#ifdef ETYPE_IN_IP_ACL_KEY_ENABLE
        l2_metadata.lkp_mac_type : ternary;
#endif
    }
    actions {
        nop;
        acl_deny;
        acl_permit;
        acl_redirect_nexthop;
        acl_redirect_ecmp;
#ifndef MIRROR_DISABLE
        acl_mirror;
#endif /* MIRROR_DISABLE */
    }
    size : INGRESS_IPV6_ACL_TABLE_SIZE;
}
#endif /* IPV6_DISABLE */

/*****************************************************************************/
/* QoS ACLs                                                                  */
/*****************************************************************************/
#if defined(MAC_QOS_ACL_ENABLE)
table mac_qos_acl {
    reads {
        INGRESS_MAC_MIRROR_ACL_KEY
    }
    actions {
        nop;
	acl_set_qos_fields;
    }
    size : INGRESS_MAC_QOS_ACL_TABLE_SIZE;
}
#endif /* MAC_QOS_ACL_ENABLE */

#if defined(IPV4_QOS_ACL_ENABLE)
table ipv4_qos_acl {
    reads {
        INGRESS_IPV4_MIRROR_ACL_KEY
    }
    actions {
        nop;
	acl_set_qos_fields;
    }
    size : INGRESS_IPV4_QOS_ACL_TABLE_SIZE;
}
#endif /* IPV4_QOS_ACL_ENABLE */

#if defined(IPV6_QOS_ACL_ENABLE)
table ipv6_qos_acl {
    reads {
        INGRESS_IPV6_MIRROR_ACL_KEY
    }
    actions {
        nop;
	acl_set_qos_fields;
    }
    size : INGRESS_IPV6_QOS_ACL_TABLE_SIZE;
}
#endif /* IPV6_QOS_ACL_ENABLE */

/*****************************************************************************/
/* ACL Control flow                                                          */
/*****************************************************************************/
control process_ip_acl {
    if (DO_LOOKUP(ACL)) {
        if (l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
#ifndef IPV4_DISABLE
#ifdef ATCAM
            apply(ip_acl_partition);
#endif /* ATCAM */
            apply(ip_acl);
#endif /* IPV4_DISABLE */
        } else {
            if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
#if !defined(IPV6_DISABLE) && !defined(IPV6_ACL_DISABLE)
#ifdef ATCAM
                apply(ipv6_acl_partition);
#endif /* ATCAM */
                apply(ipv6_acl);
#endif /* IPV6_DISABLE */
            }
        }
    }
}

/*****************************************************************************/
/* RACL actions                                                              */
/*****************************************************************************/
action racl_deny(acl_stats_index, acl_copy_reason,
                 ingress_cos, tc, color) {
    modify_field(acl_metadata.racl_deny, TRUE);
#ifndef RACL_STATS_ENABLE
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
#else
    modify_field(acl_metadata.racl_stats_index, acl_stats_index);
#endif /* RACL_STATS_ENABLE */
    
#ifndef RACL_REASON_CODE_DISABLE
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#endif /* RACL_REASON_CODE_DISABLE */
#ifdef ACL_QOS_ENABLE
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* ACL_QOS_ENABLE */
}

action racl_permit(acl_stats_index, acl_copy_reason,
                   ingress_cos, tc, color) {
#ifndef RACL_STATS_ENABLE
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
#else
    modify_field(acl_metadata.racl_stats_index, acl_stats_index);
#endif /* RACL_STATS_ENABLE */
#ifndef RACL_REASON_CODE_DISABLE
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#endif /* RACL_REASON_CODE_DISABLE */
#ifdef ACL_QOS_ENABLE
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* ACL_QOS_ENABLE */
}

action racl_redirect_nexthop(nexthop_index, acl_stats_index,
                             acl_copy_reason,
                             ingress_cos, tc, color) {
    modify_field(acl_metadata.racl_redirect, TRUE);
    modify_field(acl_metadata.racl_nexthop, nexthop_index);
    modify_field(acl_metadata.racl_nexthop_type, NEXTHOP_TYPE_SIMPLE);
#ifndef RACL_STATS_ENABLE
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
#else
    modify_field(acl_metadata.racl_stats_index, acl_stats_index);
#endif /* RACL_STATS_ENABLE */
#ifndef RACL_REASON_CODE_DISABLE
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#endif /* RACL_REASON_CODE_DISABLE */
#ifdef ACL_QOS_ENABLE
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* ACL_QOS_ENABLE */
}

action racl_redirect_ecmp(ecmp_index, acl_stats_index,
                          acl_copy_reason,
                          ingress_cos, tc, color) {
    modify_field(acl_metadata.racl_redirect, TRUE);
    modify_field(acl_metadata.racl_nexthop, ecmp_index);
    modify_field(acl_metadata.racl_nexthop_type, NEXTHOP_TYPE_ECMP);
#ifndef RACL_STATS_ENABLE
    modify_field(acl_metadata.acl_stats_index, acl_stats_index);
#else
    modify_field(acl_metadata.racl_stats_index, acl_stats_index);
#endif /* RACL_STATS_ENABLE */
#ifndef RACL_REASON_CODE_DISABLE
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#endif /* RACL_REASON_CODE_DISABLE */
#ifdef ACL_QOS_ENABLE
    modify_field(ig_intr_md_for_tm.ingress_cos, ingress_cos);
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
#endif /* ACL_QOS_ENABLE */
}


/*****************************************************************************/
/* IPv4 RACL                                                                 */
/*****************************************************************************/
#if !defined(IPV4_DISABLE) && !defined(RACL_DISABLE)
table ipv4_racl {
    reads {
      INGRESS_IPV4_ACL_KEY
    }
    actions {
        nop;
        racl_deny;
        racl_permit;
        racl_redirect_nexthop;
        racl_redirect_ecmp;
    }
    size : INGRESS_IP_RACL_TABLE_SIZE;
}
#endif /* !IPV4_DISABLE && !RACL_DISABLE */

control process_ipv4_racl {
#if !defined(IPV4_DISABLE) && !defined(RACL_DISABLE)
    apply(ipv4_racl);
#endif /* !IPV4_DISABLE && !RACL_DISABLE */
}

/*****************************************************************************/
/* IPv6 RACL                                                                 */
/*****************************************************************************/
#if !defined(IPV6_DISABLE) && !defined(RACL_DISABLE)
table ipv6_racl {
    reads {
        INGRESS_IPV6_ACL_KEY
    }
    actions {
        nop;
        racl_deny;
        racl_permit;
        racl_redirect_nexthop;
        racl_redirect_ecmp;
    }
    size : INGRESS_IPV6_RACL_TABLE_SIZE;
}
#endif /* !IPV6_DISABLE && !RACL_DISABLE */

control process_ipv6_racl {
#if !defined(IPV6_DISABLE) && !defined(RACL_DISABLE)
    apply(ipv6_racl);
#endif /* !IPV6_DISABLE && !RACL_DISABLE */
}

/*****************************************************************************/
/* Mirror ACL actions                                                        */
/*****************************************************************************/
action mirror_acl_mirror(session_id, acl_stats_index) {
    modify_field(i2e_metadata.mirror_session_id, session_id);
    clone_ingress_pkt_to_egress(session_id, i2e_mirror_info);
#ifdef MIRROR_ACL_STATS_ENABLE
    modify_field(acl_metadata.mirror_acl_stats_index, acl_stats_index);
#endif /* MIRROR_ACL_STATS_ENABLE */
}

/*****************************************************************************/
/* IPv4 Mirror ACL                                                           */
/*****************************************************************************/
#if !defined(IPV4_DISABLE) && defined(MIRROR_ACL_ENABLE)
table ipv4_mirror_acl {
    reads {
        INGRESS_IPV4_MIRROR_ACL_KEY
    }
    actions {
        nop;
        mirror_acl_mirror;
    }
    size : INGRESS_MIRROR_ACL_TABLE_SIZE;
}
#endif /* !IPV4_DISABLE && MIRROR_ACL_ENABLE */

control process_ipv4_mirror_acl {
#if !defined(IPV4_DISABLE) && defined(MIRROR_ACL_ENABLE)
    apply(ipv4_mirror_acl);
#endif /* !IPV4_DISABLE && MIRROR_ACL_ENABLE */
}

/*****************************************************************************/
/* IPv6 Mirror ACL                                                           */
/*****************************************************************************/
#if !defined(IPV6_DISABLE) && defined(MIRROR_ACL_ENABLE)
table ipv6_mirror_acl {
    reads {
        INGRESS_IPV6_MIRROR_ACL_KEY
    }
    actions {
        nop;
        mirror_acl_mirror;
    }
    size : INGRESS_MIRROR_ACL_TABLE_SIZE;
}
#endif /* !IPV6_DISABLE && MIRROR_ACL_ENABLE */

control process_ipv6_mirror_acl {
#if !defined(IPV6_DISABLE) && defined(MIRROR_ACL_ENABLE)
    apply(ipv6_mirror_acl);
#endif /* !IPV6_DISABLE && MIRROR_ACL_ENABLE */
}

/*****************************************************************************/
/* ACL stats                                                                 */
/*****************************************************************************/
#ifndef STATS_DISABLE
counter acl_stats {
    type : packets_and_bytes;
    instance_count : ACL_STATS_TABLE_SIZE;
    min_width : 16;
}

action acl_stats_update() {
    count(acl_stats, acl_metadata.acl_stats_index);
}

table acl_stats {
    actions {
        acl_stats_update;
    }
    size : ACL_STATS_TABLE_SIZE;
}
#endif /* STATS_DISABLE */

#ifdef MIRROR_ACL_STATS_ENABLE
counter mirror_acl_stats {
 type : packets_and_bytes;
 instance_count : MIRROR_ACL_STATS_TABLE_SIZE;
 min_width : 16;
}

action mirror_acl_stats_update() {
  count(mirror_acl_stats, acl_metadata.mirror_acl_stats_index);
}

table mirror_acl_stats {
  actions {
    mirror_acl_stats_update;
  }
 size : MIRROR_ACL_STATS_TABLE_SIZE;
}
#endif /* MIRROR_ACL_STATS_ENABLE */

#ifdef RACL_STATS_ENABLE
counter racl_stats {
    type : packets_and_bytes;
    instance_count : RACL_STATS_TABLE_SIZE;
    min_width : 16;
}

action racl_stats_update() {
    count(racl_stats, acl_metadata.racl_stats_index);
}

table racl_stats {
    actions {
        racl_stats_update;
    }
    size : RACL_STATS_TABLE_SIZE;
}
#endif /* RACL_STATS_ENABLE */

control process_ingress_acl_stats {
#ifndef STATS_DISABLE
    apply(acl_stats);
#endif /* STATS_DISABLE */
}

control process_ingress_mirror_acl_stats {
#ifdef MIRROR_ACL_STATS_ENABLE
  apply(mirror_acl_stats);
#endif /* MIRROR_ACL_STATS_ENABLE */
}

control process_ingress_racl_stats {
#ifdef RACL_STATS_ENABLE
    apply(racl_stats);
#endif /* RACL_STATS_ENABLE */
}

/*****************************************************************************/
/* CoPP                                                                      */
/*****************************************************************************/
#ifndef COPP_METER_DISABLE
meter copp {
    type: bytes;
    static: system_acl;
    result: ig_intr_md_for_tm.packet_color;
    instance_count: COPP_TABLE_SIZE;
}
#endif /* !COPP_METER_DISABLE */

/*****************************************************************************/
/* System ACL                                                                */
/*****************************************************************************/
counter drop_stats {
    type : packets;
    instance_count : DROP_STATS_TABLE_SIZE;
}

counter drop_stats_2 {
    type : packets;
    instance_count : DROP_STATS_TABLE_SIZE;
}

#ifdef MIRROR_ON_DROP_ENABLE
field_list i2e_mirror_and_drop_info {
    ingress_metadata.drop_reason;
    i2e_metadata.mirror_session_id;
    i2e_metadata.ingress_tstamp;
    ingress_metadata.ingress_port;
    telemetry_md.mod_watchlist_hit;
    egress_metadata.egress_port;
#ifdef INT_EP_ENABLE
    int_metadata.source;
    int_metadata.sink;
#endif // INT_EP_ENABLE
#ifdef INT_TRANSIT_ENABLE
    int_metadata.path_tracking_flow;
#endif // INT_TRANSIT_ENABLE
#ifdef POSTCARD_ENABLE
    postcard_md.report;
#endif // POSTCARD_ENABLE;
//    hash_metadata.entropy_hash;
}

action mirror_and_drop() {
    modify_field(i2e_metadata.mirror_session_id,
                 telemetry_md.mirror_session_id);
    modify_field(egress_metadata.egress_port, INVALID_PORT_ID);
    clone_ingress_pkt_to_egress(telemetry_md.mirror_session_id,
                                i2e_mirror_and_drop_info);
    drop();
}

action mirror_and_drop_with_reason(drop_reason) {
    count(drop_stats, drop_reason);
    modify_field(ingress_metadata.drop_reason, drop_reason);
    modify_field(acl_metadata.acl_deny, FALSE);
    mirror_and_drop();
}
#endif /* MIRROR_ON_DROP_ENABLE */

action redirect_to_cpu_with_reason(reason_code, qid, meter_id, icos) {
    copy_to_cpu_with_reason(reason_code, qid, meter_id, icos);
    drop();
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
}

action redirect_to_cpu(qid, meter_id, icos) {
    copy_to_cpu(qid, meter_id, icos);
    drop();
#ifdef FABRIC_ENABLE
    modify_field(fabric_metadata.dst_device, 0);
#endif /* FABRIC_ENABLE */
}

field_list cpu_info {
    ingress_metadata.bd;
    ingress_metadata.ifindex;
    fabric_metadata.reason_code;
    ingress_metadata.ingress_port;
}

action copy_to_cpu(qid, meter_id, icos) {
    modify_field(ig_intr_md_for_tm.qid, qid);
    modify_field(ig_intr_md_for_tm.ingress_cos, icos);
#ifdef __TARGET_TOFINO__
    modify_field(ig_intr_md_for_tm.copy_to_cpu, TRUE);
#else
    clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, cpu_info);
#endif
#ifndef COPP_METER_DISABLE
    execute_meter(copp, meter_id, ig_intr_md_for_tm.packet_color);
#endif /* COPP_METER_DISABLE */
}

action copy_to_cpu_with_reason(reason_code, qid, meter_id, icos) {
    modify_field(fabric_metadata.reason_code, reason_code);
    copy_to_cpu(qid, meter_id, icos);
}

action drop_packet() {
    drop();
}

action drop_packet_with_reason(drop_reason) {
    count(drop_stats, drop_reason);
    drop();
}

table system_acl {
    reads {
        INGRESS_ACL_KEY_PORT_LABEL : ternary;

        INGRESS_ACL_KEY_BD_LABEL : ternary;

        ingress_metadata.ifindex : ternary;
        // should we add port_lag_index here?

        /* drop reasons */
        l2_metadata.lkp_mac_type : ternary;
        l2_metadata.port_vlan_mapping_miss : ternary;
#ifndef IPSG_DISABLE
        security_metadata.ipsg_check_fail : ternary;
#endif /* !IPSG_DISABLE */
        acl_metadata.acl_deny : ternary;
#ifndef RACL_DISABLE
        acl_metadata.racl_deny: ternary;
#endif /* RACL_DISABLE */
#if !defined(URPF_DISABLE)
        l3_metadata.urpf_check_fail : ternary;
#endif /* !URPF_DISABLE */
#if !defined(STORM_CONTROL_DISABLE)
        meter_metadata.storm_control_color : ternary;
#endif /* !STORM_CONTROL_DISABLE */
        meter_metadata.meter_drop : ternary;
        ingress_metadata.drop_flag : ternary;

        l3_metadata.l3_copy : ternary;

        l3_metadata.rmac_hit : ternary;
        nexthop_metadata.nexthop_glean : ternary;

        /*
         * other checks, routed link_local packet, l3 same if check,
         * expired ttl
         */
#if !defined(L3_MULTICAST_DISABLE)
        multicast_metadata.mcast_route_hit : ternary;
        multicast_metadata.mcast_route_s_g_hit : ternary;
        multicast_metadata.mcast_copy_to_cpu : ternary;
        multicast_metadata.mcast_rpf_fail : ternary;
#endif /* L3_MULTICAST_DISABLE */
        l3_metadata.routed : ternary;
        ipv6_metadata.ipv6_src_is_link_local : ternary;
        l2_metadata.same_if_check : ternary;
        tunnel_metadata.tunnel_if_check : ternary;
        l3_metadata.same_bd_check : ternary;
        l3_metadata.lkp_ip_ttl : ternary;
        l2_metadata.stp_state : ternary;
        ingress_metadata.control_frame: ternary;
        ipv4_metadata.ipv4_unicast_enabled : ternary;
        ipv6_metadata.ipv6_unicast_enabled : ternary;
        l2_metadata.l2_dst_miss : ternary;
        l2_metadata.lkp_pkt_type : ternary;
        l2_metadata.arp_opcode : ternary;
        /* egress information */
        ingress_metadata.egress_ifindex : ternary;

        fabric_metadata.reason_code : ternary;
#ifdef MIRROR_ON_DROP_ENABLE
        ig_intr_md_for_tm.drop_ctl : ternary;
        telemetry_md.mod_watchlist_hit: ternary;
#endif
    }
    actions {
        nop;
        redirect_to_cpu;
        redirect_to_cpu_with_reason;
        copy_to_cpu;
        copy_to_cpu_with_reason;
        drop_packet;
        drop_packet_with_reason;
#ifdef MIRROR_ON_DROP_ENABLE
        mirror_and_drop;
        mirror_and_drop_with_reason;
#endif /* MIRROR_ON_DROP_ENABLE */
    }
    size : SYSTEM_ACL_SIZE;
}

action drop_stats_update() {
    count(drop_stats_2, ingress_metadata.drop_reason);
}

table drop_stats {
    actions {
        drop_stats_update;
    }
    size : DROP_STATS_TABLE_SIZE;
}

action invalidate_dod() {
    deflect_on_drop(FALSE);
}

table dod_control {
    reads {
        ig_intr_md_for_tm.mcast_grp_a  : exact;
        ig_intr_md_for_tm.mcast_grp_b  : exact;
        ig_intr_md_for_tm.copy_to_cpu  : exact;
    }

    actions {
        invalidate_dod;
        nop;
    }
    size: 2;
}

control process_system_acl {

    if (DO_LOOKUP(SYSTEM_ACL)) {
        apply(system_acl);
        if (ingress_metadata.drop_flag == TRUE) {
            apply(drop_stats);
        }
#if defined(MIRROR_ON_DROP_ENABLE) || \
    defined(TELEMETRY_STATELESS_SUP_ENABLE)
        apply(dod_control);
#endif
    }
}

/*****************************************************************************/
/* Egress ACL                                                                */
/*****************************************************************************/

#ifdef EGRESS_ACL_ENABLE

/*****************************************************************************/
/* Egress ACL Actions                                                        */
/*****************************************************************************/
action egress_acl_deny(acl_copy_reason, acl_stats_index) {
    modify_field(acl_metadata.egress_acl_deny, TRUE);
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#ifdef EGRESS_ACL_STATS_ENABLE
    modify_field(acl_metadata.egress_acl_stats_index, acl_stats_index);
#endif /* EGRESS_ACL_STATS_ENABLE */
}

action egress_acl_permit(acl_copy_reason, acl_stats_index) {
    modify_field(fabric_metadata.reason_code, acl_copy_reason);
#ifdef EGRESS_ACL_STATS_ENABLE
    modify_field(acl_metadata.egress_acl_stats_index, acl_stats_index);
#endif /* EGRESS_ACL_STATS_ENABLE */
}

/*****************************************************************************/
/* Egress Mac ACL                                                            */
/*****************************************************************************/

#if !defined(L2_DISABLE) && !defined(EGRESS_MAC_ACL_DISABLE)
table egress_mac_acl {
    reads {
        EGRESS_MAC_ACL_KEY
    }
    actions {
        nop;
        egress_acl_deny;
        egress_acl_permit;
    }
    size : EGRESS_MAC_ACL_TABLE_SIZE;
}
#endif /* !L2_DISABLE && !EGRESS_MAC_ACL_DISABLE */

/*****************************************************************************/
/* Egress IPv4 ACL                                                           */
/*****************************************************************************/
#ifndef IPV4_DISABLE
#ifdef ENT_DC_GENERAL_PROFILE
@pragma stage 5
#endif /* ENT_DC_GENERAL_PROFILE */
table egress_ip_acl {
    reads {
        EGRESS_IPV4_ACL_KEY
    }
    actions {
        nop;
        egress_acl_deny;
        egress_acl_permit;
    }
    size : EGRESS_IP_ACL_TABLE_SIZE;
}
#endif /* IPV4_DISABLE */

/*****************************************************************************/
/* Egress IPv6 ACL                                                           */
/*****************************************************************************/
#ifndef IPV6_DISABLE
table egress_ipv6_acl {
    reads {
        EGRESS_IPV6_ACL_KEY
    }
    actions {
        nop;
        egress_acl_deny;
        egress_acl_permit;
    }
    size : EGRESS_IPV6_ACL_TABLE_SIZE;
}

#endif /* IPV6_DISABLE */
#endif /* EGRESS_ACL_ENABLE */

/*****************************************************************************/
/* Egress ACL Control flow                                                   */
/*****************************************************************************/
control process_egress_acl {
#ifdef EGRESS_ACL_ENABLE
    if (valid(ipv4)) {
#ifndef IPV4_DISABLE
        apply(egress_ip_acl);
#endif /* IPV4_DISABLE */
    } else {
        if (valid(ipv6)) {
#ifndef IPV6_DISABLE
            apply(egress_ipv6_acl);
#endif /* IPV6_DISABLE */
#if !defined(L2_DISABLE) && !defined(EGRESS_MAC_ACL_DISABLE)
        } else {
            apply(egress_mac_acl);
#endif /* !L2_DISABLE && !EGRESS_MAC_ACL_DISABLE */
        }
    }
#endif /* EGRESS_ACL_ENABLE */
}

/*****************************************************************************/
/* Egress ACL stats                                                          */
/*****************************************************************************/
#ifdef EGRESS_ACL_STATS_ENABLE
counter egress_acl_stats {
    type : packets_and_bytes;
    instance_count : EGRESS_ACL_STATS_TABLE_SIZE;
    min_width : 16;
}

action egress_acl_stats_update() {
    count(egress_acl_stats, acl_metadata.egress_acl_stats_index);
}

table egress_acl_stats {
    actions {
        egress_acl_stats_update;
    }
    size : EGRESS_ACL_STATS_TABLE_SIZE;
}
#endif /* EGRESS_ACL_STATS_ENABLE */

control process_egress_acl_stats {
#ifdef EGRESS_ACL_STATS_ENABLE
    apply(egress_acl_stats);
#endif /* EGRESS_ACL_STATS_ENABLE */
}

/*****************************************************************************/
/* Egress System ACL                                                         */
/*****************************************************************************/

#if defined(TELEMETRY_STATELESS_SUP_ENABLE) || \
    defined(MIRROR_ON_DROP_ENABLE)
field_list e2e_mirror_and_drop_info {
    i2e_metadata.ingress_tstamp;
    i2e_metadata.mirror_session_id;
    ingress_metadata.drop_reason;
    ingress_metadata.ingress_port;
    egress_metadata.egress_port;
    ig_intr_md_for_tm.qid;
#ifdef INT_EP_ENABLE
    int_metadata.source;
    int_metadata.sink;
#endif // INT_EP_ENABLE;
#ifdef INT_TRANSIT_ENABLE
    int_metadata.path_tracking_flow;
#endif // INT_TRANSIT_ENABLE
#ifdef POSTCARD_ENABLE
    postcard_md.report;
#endif // POSTCARD_ENABLE;
#ifdef TELEMETRY_STATELESS_SUP_ENABLE
    telemetry_md.queue_alert;
#endif // TELEMETRY_STATELESS_SUP_ENABLE
    telemetry_md.mod_watchlist_hit;
//    hash_metadata.entropy_hash;
}
#endif /* MIRROR_ON_DROP_ENABLE || TELEMETRY_STATELESS_SUP_ENABLE*/

action egress_mirror(session_id) {
    modify_field(i2e_metadata.mirror_session_id, session_id);
    clone_egress_pkt_to_egress(session_id, e2e_mirror_info);
}

action egress_mirror_and_drop(reason_code) {
    // This is used for cases like mirror on drop where
    // original frame needs to be dropped after mirror copy is made
#if defined(MIRROR_ON_DROP_ENABLE) || defined(TELEMETRY_STATELESS_SUP_ENABLE)
    modify_field(ingress_metadata.drop_reason, reason_code);
    modify_field(i2e_metadata.mirror_session_id,
                 telemetry_md.mirror_session_id);
    clone_egress_pkt_to_egress(telemetry_md.mirror_session_id,
                               e2e_mirror_and_drop_info);
#endif /* MIRROR_ON_DROP_ENABLE || TELEMETRY_STATELESS_SUP_ENABLE */
    drop();
}

#ifdef TELEMETRY_STATELESS_SUP_ENABLE
// if eg_intr_md.deflection_flag and telemetry_md.queue_dod_enable are both set
action egress_mirror_and_drop_set_queue_alert(reason_code) {
    modify_field(telemetry_md.queue_alert, 1);
    egress_mirror_and_drop(reason_code);
}
#endif // TELEMETRY_STATELESS_SUP_ENABLE

action egress_copy_to_cpu() {
    clone_egress_pkt_to_egress(CPU_MIRROR_SESSION_ID, cpu_info);
}

action egress_redirect_to_cpu() {
    egress_copy_to_cpu();
    drop();
}

action egress_copy_to_cpu_with_reason(reason_code) {
    modify_field(fabric_metadata.reason_code, reason_code);
    egress_copy_to_cpu();
}

action egress_redirect_to_cpu_with_reason(reason_code) {
    egress_copy_to_cpu_with_reason(reason_code);
    drop();
}

// Example of coal_mirroring with small sample header
action egress_mirror_coal_hdr(session_id, id) {
#ifdef COALESCED_MIRROR_ENABLE
    add_header(coal_sample_hdr);
    modify_field(coal_sample_hdr.id, id);
    // Just make sure extract len (64) will not be > pkt_len
    sample_e2e(session_id, 64, coal_sample_hdr);
#endif
}

action egress_insert_cpu_timestamp() {
#ifdef PTP_ENABLE
  add_header(fabric_header_timestamp);
  modify_field(fabric_header_timestamp.arrival_time, i2e_metadata.ingress_tstamp);
#endif /* PTP_ENABLE */
}

table egress_system_acl {
    reads {
        fabric_metadata.reason_code : ternary;
#ifdef COPP_COLOR_DROP_ENABLE
        ig_intr_md_for_tm.packet_color : ternary;
#endif
        eg_intr_md.egress_port : ternary;
        eg_intr_md.deflection_flag : ternary;
        l3_metadata.l3_mtu_check : ternary;
#ifdef WRED_DROP_ENABLE
        wred_metadata.drop_flag : ternary;
#endif
        acl_metadata.egress_acl_deny : ternary;
#ifdef MIRROR_ON_DROP_ENABLE
        eg_intr_md_for_oport.drop_ctl : ternary;
        telemetry_md.mod_watchlist_hit : ternary;
#endif
#ifdef TELEMETRY_STATELESS_SUP_ENABLE
        telemetry_md.queue_dod_enable : ternary;
#endif
#ifdef INGRESS_PORT_IN_EGRESS_SYSTEM_ACL_ENABLE
        ingress_metadata.ingress_port : ternary;
#endif
    }
    actions {
        nop;
        drop_packet;
        egress_copy_to_cpu;
        egress_redirect_to_cpu;
        egress_copy_to_cpu_with_reason;
        egress_redirect_to_cpu_with_reason;
        egress_mirror_coal_hdr;
#ifdef PTP_ENABLE
	egress_insert_cpu_timestamp;
#endif /* PTP_ENABLE */
#ifndef MIRROR_DISABLE
        egress_mirror;
        egress_mirror_and_drop;
#ifdef TELEMETRY_STATELESS_SUP_ENABLE
        egress_mirror_and_drop_set_queue_alert;
#endif // TELEMETRY_STATELESS_SUP_ENABLE
#endif /* MIRROR_DISABLE */
    }
    size : EGRESS_ACL_TABLE_SIZE;
}

control process_egress_system_acl {
    if (egress_metadata.bypass == FALSE) {
        apply(egress_system_acl);
    }
}
