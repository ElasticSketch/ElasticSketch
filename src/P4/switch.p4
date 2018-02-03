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
#ifdef __TARGET_BMV2__
#define BMV2
#endif

#ifdef __TARGET_TOFINO__
#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>
#include <tofino/pktgen_headers.p4>
#include <tofino/stateful_alu_blackbox.p4>
#include <tofino/wred_blackbox.p4>
#else
#include "includes/tofino.p4"
#endif

#include "includes/p4features.h"
#include "includes/drop_reason_codes.h"
#include "includes/cpu_reason_codes.h"
#include "includes/p4_pktgen.h"
#include "includes/defines.p4"
#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/p4_table_sizes.h"

/* METADATA */
header_type ingress_metadata_t {
    fields {
        ingress_port : 9;                         /* input physical port */
        port_lag_index : PORT_LAG_INDEX_BIT_WIDTH;      /* ingress port index */
        egress_port_lag_index : PORT_LAG_INDEX_BIT_WIDTH;/* egress port index */
        ifindex : IFINDEX_BIT_WIDTH;              /* ingress interface index */
        egress_ifindex : IFINDEX_BIT_WIDTH;       /* egress interface index */
        port_type : 2;                         /* ingress port type */

        outer_bd : BD_BIT_WIDTH;               /* outer BD */
        bd : BD_BIT_WIDTH;                     /* BD */

        drop_flag : 1;                         /* if set, drop the packet */
        drop_reason : 8;                       /* drop reason */

        control_frame: 1;                      /* control frame */
        bypass_lookups : 16;                   /* list of lookups to skip */
    }
}

header_type egress_metadata_t {
    fields {
#ifdef PTP_ENABLE
        capture_tstamp_on_tx : 1;              /* request for packet departure time capture */
#endif
        bypass : 1;                            /* bypass egress pipeline */
        port_type : 2;                         /* egress port type */
        payload_length : 16;                   /* payload length for tunnels */
        smac_idx : 9;                          /* index into source mac table */
        bd : BD_BIT_WIDTH;                     /* egress inner bd */
        outer_bd : BD_BIT_WIDTH;               /* egress inner bd */
        mac_da : 48;                           /* final mac da */
        routed : 1;                            /* is this replica routed */
        same_bd_check : BD_BIT_WIDTH;          /* ingress bd xor egress bd */
        drop_reason : 8;                       /* drop reason */
        ifindex : IFINDEX_BIT_WIDTH;           /* egress interface index */
        egress_port :  9;                      /* original egress port */
    }
}

header_type intrinsic_metadata_t {
    fields {
        mcast_grp : 16;                           /* multicast group */
        lf_field_list : 32;                       /* Learn filter field list */
        egress_rid : 16;                          /* replication index */
        ingress_global_timestamp : 32;
    }
}


header_type my_metadata_t {
    fields {
        sentry: 32;
        //sentry_div: 32;
        register_id: 32;
        //branch: 8;
        //newfreq: 32;
    }
}


/* Global config information */
header_type global_config_metadata_t {
    fields {
        enable_dod : 1;                        /* Enable Deflection-on-Drop */
        switch_id  : 32;                       /* Switch Id */
    }
}
#ifdef SFLOW_ENABLE
@pragma pa_atomic ingress ingress_metadata.sflow_take_sample
@pragma pa_solitary ingress ingress_metadata.sflow_take_sample
#endif
@pragma pa_atomic ingress ingress_metadata.port_type
@pragma pa_solitary ingress ingress_metadata.port_type
#ifndef INT_ENABLE
@pragma pa_atomic ingress ingress_metadata.port_lag_index
@pragma pa_solitary ingress ingress_metadata.port_lag_index
@pragma pa_atomic ingress ingress_metadata.ifindex
@pragma pa_solitary ingress ingress_metadata.ifindex
@pragma pa_atomic egress ingress_metadata.bd
@pragma pa_solitary egress ingress_metadata.bd
#endif
#if defined(FABRIC_PROFILE)
/* This field is part of bridged metadata.  The fabric
   profile puts a lot of pressure on 16-bit containers.
   Even though the natural container size of this field is 16,
   it can safely be allocated in a 32-bit container since its
   MAU cluster size is 1. */
@pragma pa_container_size ingress ingress_metadata.ifindex 32
#endif

// COMPILER workaround suggested by Mike
#ifdef ENT_DC_AGGR_PROFILE
@pragma pa_solitary ingress l3_metadata.lkp_dscp
@pragma pa_no_overlay ingress ig_intr_md_from_parser_aux.ingress_global_tstamp
#endif

metadata ingress_metadata_t ingress_metadata;
#ifdef TELEMETRY_MIRROR_LB_ENABLE
@pragma pa_no_overlay egress egress_metadata.routed
#endif
#ifdef MSDC_LEAF_TELEMETRY_INT_PROFILE
@pragma pa_solitary egress egress_metadata.routed
#endif
metadata egress_metadata_t egress_metadata;
metadata intrinsic_metadata_t intrinsic_metadata;
metadata global_config_metadata_t global_config_metadata;
metadata my_metadata_t meta;

#include "switch_config.p4"
#ifdef OPENFLOW_ENABLE
#include "openflow.p4"
#endif /* OPENFLOW_ENABLE */
#include "port.p4"
#include "l2.p4"
#include "l3.p4"
#include "ipv4.p4"
#include "ipv6.p4"
#include "tunnel.p4"
#include "acl.p4"
#include "nat.p4"
#include "multicast.p4"
#include "nexthop.p4"
#include "rewrite.p4"
#include "security.p4"
#include "fabric.p4"
#include "egress_filter.p4"
#include "mirror.p4"
#include "hashes.p4"
#include "meter.p4"
#include "sflow.p4"
#include "bfd.p4"
#include "qos.p4"
#include "sr.p4"
#include "flowlet.p4"
#include "pktgen.p4"
#include "failover.p4"
#include "ila.p4"
#include "wred.p4"
#include "telemetry.p4"
#include "telemetry_int.p4"
#include "telemetry_postcard.p4"

action nop() {
}

action on_miss() {
}
action real_drop() {
    drop();
}





/*--*--* REGISTERS *--*--*/
register sentry1 {
    width: 32;
    instance_count: BUCKETS;
}
register freq_id_1_first {
    width: 64;
    instance_count: BUCKETS;
}

register freq_id_1_second {
    width: 64;
    instance_count: BUCKETS;
}
register freq_id_1_third {
    width: 64;
    instance_count: BUCKETS;
}

register sentry2 {
    width: 32;
    instance_count: BUCKETS;
}
register freq_id_2_first {
    width: 64;
    instance_count: BUCKETS;
}
register freq_id_2_second {
    width: 64;
    instance_count: BUCKETS;
}
register freq_id_2_third {
    width: 64;
    instance_count: BUCKETS;
}

register sentry3 {
    width: 32;
    instance_count: BUCKETS;
}

register freq_id_3_first {
    width: 64;
    instance_count: BUCKETS;
}
register freq_id_3_second {
    width: 64;
    instance_count: BUCKETS;
}
register freq_id_3_third {
    width: 64;
    instance_count: BUCKETS;
}

register sentry4 {
    width: 32;
    instance_count: BUCKETS;
}
register freq_id_4_first {
    width: 64;
    instance_count: BUCKETS;
}
register freq_id_4_second {
    width: 64;
    instance_count: BUCKETS;
}
register freq_id_4_third {
    width: 64;
    instance_count: BUCKETS;
}


register lights {
    // width: 8;
    width: 32;
    instance_count: LIGHT_LEN;
}

/*--*--* Hash *--*--*/
field_list hash_list {
    myFlow.id;
}

field_list_calculation hash_heavy_1 {
    input { hash_list; }
    algorithm : identity;
    output_width : 10;
}

field_list_calculation hash_heavy_2 {
    input { hash_list; }
    algorithm : crc16;
    output_width : 10;
}

field_list_calculation hash_heavy_3 {
    input { hash_list; }
    algorithm : crc_16_dds_110;
    output_width : 10;
}

field_list_calculation hash_heavy_4 {
    input { hash_list; }
    algorithm : crc_16_dect;
    output_width : 10;
}

field_list_calculation hash_light {
    input { hash_list; }
    algorithm : identity;
    output_width : 32;
}


/*--*--* actions and blackboxes of sentrys *--*--*/
blackbox stateful_alu sentry_incre_1 {
    reg: sentry1;
    update_lo_1_value: register_lo + myFlow.freq;
    output_value: alu_lo;
    output_dst: meta.sentry;
}
action sentry_1_action() {
    sentry_incre_1.execute_stateful_alu_from_hash(hash_heavy_1);
    //shift_left(meta.sentry_div, meta.sentry, 3);
}
table sentry_1_table {
    // reads {
    //     meta.branch: exact;
    // }
    actions {
        //real_drop;
        sentry_1_action;
    }
    //default_action: sentry_1_action();
    //default_action: real_drop;
}

blackbox stateful_alu sentry_incre_2 {
    reg: sentry2;
    update_lo_1_value: register_lo + myFlow.freq;
    output_value: alu_lo;
    output_dst: meta.sentry;
}
action sentry_2_action() {
    sentry_incre_2.execute_stateful_alu_from_hash(hash_heavy_2);
    //shift_left(meta.sentry_div, meta.sentry, 3);
}

table sentry_2_table {
    // reads {
    //     meta.branch: exact;
    // }
    actions {
        // real_drop;
        sentry_2_action;
    }
    // default_action: real_drop;
}

blackbox stateful_alu sentry_incre_3 {
    reg: sentry3;
    update_lo_1_value: register_lo + myFlow.freq;
    output_value: alu_lo;
    output_dst: meta.sentry;
}
action sentry_3_action() {
    sentry_incre_3.execute_stateful_alu_from_hash(hash_heavy_3);
    //shift_left(meta.sentry_div, meta.sentry, 3);
}
table sentry_3_table {
    // reads {
    //     meta.branch: exact;
    // }
    actions {
        // real_drop;
        sentry_3_action;
    }
    // default_action: real_drop;
}

blackbox stateful_alu sentry_incre_4 {
    reg: sentry4;
    update_lo_1_value: register_lo + myFlow.freq;
    output_value: alu_lo;
    output_dst: meta.sentry;
}
action sentry_4_action() {
    sentry_incre_4.execute_stateful_alu_from_hash(hash_heavy_4);
    //shift_left(meta.sentry_div, meta.sentry, 3);
}
table sentry_4_table {
    // reads {
    //     meta.branch: exact;
    // }
    actions {
        // real_drop;
        sentry_4_action;
    }
    // default_action: real_drop;
}


/*--*--* actions and blackboxes of freq_id_1 *--*--*/
blackbox stateful_alu freq_id_insert_1_first {
    reg: freq_id_1_first;

    condition_hi: meta.sentry >= register_hi;
    condition_lo: register_lo == myFlow.id;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: myFlow.id;

    update_hi_1_predicate: condition_lo or condition_hi;
    //update_hi_1_value: register_hi + myFlow.freq;
    update_hi_1_value: register_hi;

    output_predicate: condition_lo or condition_hi;
    output_value: register_lo;
    output_dst: meta.register_id;
}

blackbox stateful_alu freq_id_insert_1_second {
    reg: freq_id_1_second;

    condition_hi: meta.sentry >= register_hi;
    condition_lo: register_lo == myFlow.id;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: myFlow.id;

    update_hi_1_predicate: condition_lo or condition_hi;
    update_hi_1_value: register_hi + myFlow.freq;

    output_predicate: condition_lo or condition_hi;
    output_value: register_hi;
    output_dst: meta.newfreq;
}

blackbox stateful_alu freq_id_insert_1_third {
    reg: freq_id_1_third;

    condition_hi: meta.sentry >= register_hi;
    condition_lo: register_lo == myFlow.id;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: myFlow.id;

    update_hi_1_predicate: condition_lo or condition_hi;
    //update_hi_1_value: register_hi + myFlow.freq;

    output_predicate: not condition_lo;
    output_value: 1;
    output_dst: meta.branch;
// }

action freq_id_1_action() {
    freq_id_insert_1_first.execute_stateful_alu_from_hash(hash_heavy_1);
    //freq_id_insert_1_second.execute_stateful_alu_from_hash(hash_heavy_1);
    //freq_id_insert_1_third.execute_stateful_alu_from_hash(hash_heavy_1);
    //modify_field(myFlow.id, meta.register_id);
}

table freq_id_1_table {
    actions {
        freq_id_1_action;
    }
    //default_action: freq_id_1_action();
}

/*--*--* actions and blackboxes of freq_id_2 *--*--*/
blackbox stateful_alu freq_id_insert_2_first {
    reg: freq_id_2_first;

    condition_hi: meta.sentry >= register_hi;
    condition_lo: register_lo == myFlow.id;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: myFlow.id;

    update_hi_1_predicate: condition_lo or condition_hi;
    //update_hi_1_value: register_hi + myFlow.freq;
    update_hi_1_value: register_hi;

    output_predicate: condition_lo or condition_hi;
    output_value: register_lo;
    output_dst: meta.register_id;
}

blackbox stateful_alu freq_id_insert_2_second {
    reg: freq_id_2_second;

    condition_hi: meta.sentry >= register_hi;
    condition_lo: register_lo == myFlow.id;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: myFlow.id;

    update_hi_1_predicate: condition_lo or condition_hi;
    update_hi_1_value: register_hi + myFlow.freq;

    output_predicate: condition_lo or condition_hi;
    output_value: register_hi;
    output_dst: myFlow.freq;
}

blackbox stateful_alu freq_id_insert_2_third {
    reg: freq_id_2_third;

    condition_hi: meta.sentry >= register_hi;
    condition_lo: register_lo == myFlow.id;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: myFlow.id;

    update_hi_1_predicate: condition_lo or condition_hi;
    update_hi_1_value: register_hi + myFlow.freq;

    output_predicate: not condition_lo;
    output_value: 1;
    output_dst: meta.branch;
}

action freq_id_2_action() {
    freq_id_insert_2_first.execute_stateful_alu_from_hash(hash_heavy_2);
    //freq_id_insert_2_second.execute_stateful_alu_from_hash(hash_heavy_2);
    //freq_id_insert_2_third.execute_stateful_alu_from_hash(hash_heavy_2);
    //modify_field(myFlow.id, meta.register_id);
}

table freq_id_2_table {
    actions {
        freq_id_2_action;
    }
    default_action: freq_id_2_action();
}
//
/*--*--* actions and blackboxes of freq_id_3 *--*--*/
blackbox stateful_alu freq_id_insert_3_first {
    reg: freq_id_3_first;

    condition_hi: meta.sentry >= register_hi;
    condition_lo: register_lo == myFlow.id;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: myFlow.id;

    update_hi_1_predicate: condition_lo or condition_hi;
    // update_hi_1_value: register_hi + myFlow.freq;
    update_hi_1_value: register_hi;

    output_predicate: condition_lo or condition_hi;
    output_value: register_lo;
    output_dst: meta.register_id;
}

blackbox stateful_alu freq_id_insert_3_second {
    reg: freq_id_3_second;

    condition_hi: meta.sentry >= register_hi;
    condition_lo: register_lo == myFlow.id;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: myFlow.id;

    update_hi_1_predicate: condition_lo or condition_hi;
    update_hi_1_value: register_hi + myFlow.freq;

    output_predicate: condition_lo or condition_hi;
    output_value: register_hi;
    output_dst: myFlow.freq;
}

blackbox stateful_alu freq_id_insert_3_third {
    reg: freq_id_3_third;

    condition_hi: meta.sentry >= register_hi;
    condition_lo: register_lo == myFlow.id;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: myFlow.id;

    update_hi_1_predicate: condition_lo or condition_hi;
    update_hi_1_value: register_hi + myFlow.freq;

    output_predicate: not condition_lo;
    output_value: 1;
    output_dst: meta.branch;
}

action freq_id_3_action() {
    freq_id_insert_3_first.execute_stateful_alu_from_hash(hash_heavy_3);
    //freq_id_insert_3_second.execute_stateful_alu_from_hash(hash_heavy_3);
    //freq_id_insert_3_third.execute_stateful_alu_from_hash(hash_heavy_3);
    //modify_field(myFlow.id, meta.register_id);
}

table freq_id_3_table {
    actions {
        freq_id_3_action;
    }
    default_action: freq_id_3_action();
}
//
/*--*--* actions and blackboxes of freq_id_4 *--*--*/
blackbox stateful_alu freq_id_insert_4_first {
    reg: freq_id_4_first;

    condition_hi: meta.sentry >= register_hi;
    condition_lo: register_lo == myFlow.id;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: myFlow.id;

    update_hi_1_predicate: condition_lo or condition_hi;
    //update_hi_1_value: register_hi + myFlow.freq;
    update_hi_1_value: register_hi;

    output_predicate: condition_lo or condition_hi;
    output_value: register_lo;
    output_dst: meta.register_id;
}

blackbox stateful_alu freq_id_insert_4_second {
    reg: freq_id_4_second;

    condition_hi: meta.sentry >= register_hi;
    condition_lo: register_lo == myFlow.id;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: myFlow.id;

    update_hi_1_predicate: condition_lo or condition_hi;
    update_hi_1_value: register_hi + myFlow.freq;

    output_predicate: condition_lo or condition_hi;
    output_value: register_hi;
    output_dst: meta.newfreq;
}

blackbox stateful_alu freq_id_insert_4_third {
    reg: freq_id_4_third;

    condition_hi: meta.sentry >= register_hi;
    condition_lo: register_lo == myFlow.id;

    update_lo_1_predicate: condition_lo or condition_hi;
    update_lo_1_value: myFlow.id;

    update_hi_1_predicate: condition_lo or condition_hi;
    update_hi_1_value: register_hi + myFlow.freq;

    output_predicate: not condition_lo;
    output_value: 1;
    output_dst: meta.branch;
}

action freq_id_4_action() {
    freq_id_insert_4_first.execute_stateful_alu_from_hash(hash_heavy_4);
    //freq_id_insert_4_second.execute_stateful_alu_from_hash(hash_heavy_4);
    //freq_id_insert_4_third.execute_stateful_alu_from_hash(hash_heavy_4);
    //modify_field(myFlow.id, meta.register_id);
}

table freq_id_4_table {
    actions {
        freq_id_4_action;
    }
    default_action: freq_id_4_action();
}

/*--*--* actions and blackboxes of lights *--*--*/
blackbox stateful_alu light_insert {
    reg: lights;
    update_lo_1_value: register_lo + myFlow.freq;
}
action light_insert_action() {
    light_insert.execute_stateful_alu_from_hash(hash_light);
    //drop();
}
table light_table {
    // reads {
    //     meta.branch: exact;
    // }
    actions {
        // real_drop;
        light_insert_action;
    }
    // default_action: real_drop();
}


control ingress {

    /* input mapping - derive an ifindex */
    process_ingress_port_mapping();

    /* read and apply system configuration parametes */
    process_global_params();
#ifdef PKTGEN_ENABLE
   if (VALID_PKTGEN_PACKET) {
        /* process pkt_gen generated packets */
        process_pktgen();
    } else {
#endif /* PKTGEN_ENABLE */
        /* process outer packet headers */
        process_validate_outer_header();

        /* process bfd rx packets */
        process_bfd_rx_packet();

#ifdef OPENFLOW_ENABLE
        if (ingress_metadata.port_type == PORT_TYPE_CPU) {
            apply(packet_out);
        }
#endif /* OPENFLOW_ENABLE */

        /* derive bd and its properties  */
        process_port_vlan_mapping();

        /* SRv6 endpoint lookup */
        process_srv6();

        /* spanning tree state checks */
        process_spanning_tree();

        /* ingress fabric processing */
        process_ingress_fabric();

#if !defined(TUNNEL_PARSING_DISABLE)
        /* tunnel termination processing */
        process_tunnel();
#endif /* !TUNNEL_PARSING_DISABLE */

        /* IPSG */
        process_ip_sourceguard();

        /* ingress sflow determination */
        process_ingress_sflow();

        /* storm control */
        process_storm_control();

#ifdef PKTGEN_ENABLE
    }
#endif
    /* common (tx and rx) bfd processing */
    process_bfd_packet();

#ifdef FABRIC_ENABLE
    if (ingress_metadata.port_type != PORT_TYPE_FABRIC) {
#endif
#ifndef MPLS_DISABLE
        if (not (valid(mpls[0]) and (l3_metadata.fib_hit == TRUE))) {
#endif /* MPLS_DISABLE */
            /* validate packet */
            process_validate_packet();

            /* perform ingress l4 port range */
            process_ingress_l4port();

            /* l2 lookups */
            process_mac();

#if !defined(ACL_SWAP)
            /* port and vlan ACL */
            if (l3_metadata.lkp_ip_type == IPTYPE_NONE) {
                process_mac_acl();
            } else {
                process_ip_acl();
            }
#endif

#if !defined(ENT_DC_GENERAL_PROFILE) && \
    defined(INGRESS_PORT_MIRROR_ENABLE) && !defined(MIRROR_DISABLE)
            apply(ingress_port_mirror);
#endif /* ENT_DC_GENERAL_PROFILE */


	    if (l2_metadata.lkp_pkt_type == L2_UNICAST) {
#if defined(L2_DISABLE) && defined(L2_MULTICAST_DISABLE) && defined(L3_MULTICAST_DISABLE)
		    {
		        {
#else
                apply(rmac) {
                    rmac_hit {
#endif /* L2_DISABLE && L2_MULTICAST_DISABLE && L3_MULTICAST_DISABLE */
                        if (DO_LOOKUP(L3)) {
                            if ((l3_metadata.lkp_ip_type == IPTYPE_IPV4) and
                                (ipv4_metadata.ipv4_unicast_enabled == TRUE)) {
                                /* router ACL/PBR */
#ifndef RACL_SWAP
                            process_ipv4_racl();
#endif /* !RACL_SWAP */
                            process_ipv4_urpf();
                            process_ipv4_fib();
#ifdef RACL_SWAP
                            process_ipv4_racl();
#endif /* RACL_SWAP */

                            } else {
                                if ((l3_metadata.lkp_ip_type == IPTYPE_IPV6) and
                                    (ipv6_metadata.ipv6_unicast_enabled == TRUE)) {
                                    /* router ACL/PBR */
#ifndef RACL_SWAP
                                process_ipv6_racl();
#endif /* !RACL_SWAP */
                                process_ipv6_urpf();
                                process_ipv6_fib();
#ifdef RACL_SWAP
                                process_ipv6_racl();
#endif /* RACL_SWAP */
                                }
                            }
                            process_urpf_bd();
                        }
                    }
		}
	    } else {
                process_multicast();
            }

#if defined(ACL_SWAP)
            /* port and vlan ACL */
            if (l3_metadata.lkp_ip_type == IPTYPE_NONE) {
                process_mac_acl();
            } else {
                process_ip_acl();
            }
#endif

            /* ingress NAT */
            process_ingress_nat();

#ifdef ENT_DC_AGGR_PROFILE
	    /* ingress qos map */
	    process_ingress_qos_map();

	    /* FCoE ACL */
	    apply(fcoe_acl);

#endif /* ENT_DC_AGGR_PROFILE */

#ifndef MPLS_DISABLE
        }
#endif /* MPLS_DISABLE */
#ifdef FABRIC_ENABLE
    }
#endif

    /* prepare metadata for telemetry */
    process_telemetry_ingress_prepare();

    /* int_sink process for packets with int_header */
    process_telemetry_int_sink();

    /* compute hashes based on packet type  */
    process_hashes();

    process_meter_index();


    apply(sentry_1_table);
    apply(freq_id_1_table);
    /*--* The second hash table of the heavy part *--*/
    apply(sentry_2_table);
    apply(freq_id_2_table);
    // /*--* The third hash table of the heavy part *--*/
    apply(sentry_3_table);
    apply(freq_id_3_table);
    // /*--* The fourth hash table of the heavy part *--*/
    apply(sentry_4_table);
    apply(freq_id_4_table);
    /*--* The light part *--*/
    apply(light_table);



    /* apply telemetry watchlist */
    process_telemetry_watchlist();

    /* INT i2e mirror */
    process_telemetry_int_upstream_report();

#ifdef FABRIC_ENABLE
    if (ingress_metadata.port_type != PORT_TYPE_FABRIC) {
#endif /* FABRIC_ENABLE */
        /* update statistics */
        process_ingress_bd_stats();
        process_ingress_acl_stats();
        process_ingress_racl_stats();
        process_storm_control_stats();

        /* decide final forwarding choice */
        process_fwd_results();

	process_meter_action();

#ifndef ENT_DC_AGGR_PROFILE
        /* ingress qos map */
        process_ingress_qos_map();
#endif

	/* IPv4 Mirror ACL */
	if (l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
	    process_ipv4_mirror_acl();
	}

#if defined(ENT_DC_GENERAL_PROFILE)
#if defined(INGRESS_PORT_MIRROR_ENABLE) && !defined(MIRROR_DISABLE)
        process_ingress_port_mirroring();
#endif
#endif /* ENT_DC_GENERAL_PROFILE */

        /* flowlet */
        process_flowlet();

        /* ecmp/nexthop lookup */
        process_nexthop();

	/* set queue id for tm */
	process_traffic_class();

	/* IPv6 Mirror ACL */
	if (l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
	  process_ipv6_mirror_acl();
	}

    process_telemetry_mod_watchlist();

	if (ingress_metadata.egress_ifindex == IFINDEX_FLOOD) {
            /* resolve multicast index for flooding */
            process_multicast_flooding();
        } else {
            if (tunnel_metadata.tunnel_index != 0) {
                /* tunnel id */
                process_tunnel_id();
            } else {
                /* resolve final egress port for unicast traffic */
                process_lag();
            }
        }

#ifdef OPENFLOW_ENABLE
        /* openflow processing for ingress */
        process_ofpat_ingress();
#endif /* OPENFLOW_ENABLE */

        /* generate learn notify digest if permitted */
        process_mac_learning();
#ifdef FABRIC_ENABLE
    }
#endif /* FABRIC_ENABLE */

    /* IPv6 Mirror ACL */
    process_ingress_mirror_acl_stats();

    /* resolve fabric port to destination device */
    process_fabric_lag();

    /* apply telemetry queue related watchlist after queue is chosen */
    process_telemetry_queue_watchlist();

    if (ingress_metadata.port_type != PORT_TYPE_FABRIC) {
        /* system acls */
        process_system_acl();
    }

    process_ecn_acl();




}

control egress {


    // apply(sentry_1_table);
    // apply(freq_id_1_table);

#ifdef OPENFLOW_ENABLE
    if (openflow_metadata.ofvalid == TRUE) {
        process_ofpat_egress();
    } else {
#endif /* OPENFLOW_ENABLE */
        /*
         * if bfd rx pkt is for recirc to correct pipe,
         * skip the rest of the pipeline
         */
        process_bfd_recirc();

        /* Process lag selection fallback */
        process_lag_fallback();

        /* Record egress port for telemetry in case of DoD */
        if (not pkt_is_mirrored) {
            process_telemetry_record_egress_port();
        }

        /* check for -ve mirrored pkt */
        if (egress_metadata.bypass == FALSE) {
            if (eg_intr_md.deflection_flag == FALSE){

                /* multi-destination replication */
                process_rid();

                /* check if pkt is mirrored */
                if (not pkt_is_mirrored) {
                    process_egress_bfd_packet();
                    process_telemetry_prepare_egress();
                } else {
                    /* mirror processing */
                    process_mirroring();
                    process_bfd_mirror_to_cpu();
                }

                /* multi-destination replication */
                process_replication();

                if (not pkt_is_mirrored) {
                    /* Telemetry processing -- detect local change and e2e */
                    process_telemetry_local_report1();
                }

                /* determine egress port properties */
                apply(egress_port_mapping) {
                    egress_port_type_normal {

#ifdef REWRITE_SWAP
                        /* apply nexthop_index based packet rewrites */
                        process_rewrite();
#endif /* REWRITE_SWAP */

                        if (pkt_is_not_mirrored) {
                            /* strip vlan header */
                            process_vlan_decap();
                        }

#if !defined(TUNNEL_PARSING_DISABLE)
                        /* perform tunnel decap */
                        process_tunnel_decap();
#endif /* !TUNNEL_PARSING_DISABLE */

                        /* egress qos map */
                        process_egress_qos_map();

                        /* process segment routing rewrite */
                        process_srv6_rewrite();

#ifndef REWRITE_SWAP
                        /* apply nexthop_index based packet rewrites */
                        process_rewrite();
#endif /* !REWRITE_SWAP */
                    }
                }

                if (not pkt_is_mirrored) {
                    /* Telemetry processing -- detect local change and e2e */
                    process_telemetry_local_report2();
                }
                if (egress_metadata.port_type == PORT_TYPE_NORMAL){

                    /* perform egress l4 port range */
                    process_egress_l4port();

                    /* egress bd properties */
                    process_egress_bd();

                    /* egress acl */
                    process_egress_acl();

                    /* wred processing */
                    process_wred();
                }

                if (egress_metadata.port_type == PORT_TYPE_NORMAL){

                    /* rewrite source/destination mac if needed */
                    process_mac_rewrite();

                    /* egress mtu checks */
                    process_mtu();

                    /* egress nat processing */
                    process_egress_nat();

#if !defined(ENT_DC_GENERAL_PROFILE)
                    /* update egress bd stats */
                    process_egress_bd_stats();
#endif /* ENT_DC_GENERAL_PROFILE */

                    /* update egress acl stats */
                    process_egress_acl_stats();
                }

                if (pkt_is_mirrored) {
                /* Telemetry processing -- convert h/w port to frontend port */
                    process_telemetry_port_convert();
                }else{
                /* Telemetry processing -- insert header */
                    process_telemetry_insert();
                }

#if defined(TUNNEL_PARSING_DISABLE)
		/* ERSPAN Encapsulation */
		process_erspan_rewrite();
#else
                /* perform tunnel encap */
                process_tunnel_encap();
#endif /* !TUNNEL_PARSING_DISABLE */


                /* update L4 checksums (if needed) */
                process_l4_checksum();

                /* Telemetry processing -- update header */
                if (pkt_is_mirrored){
                    process_telemetry_report_encap();
                }else{
                    process_telemetry_insert_2();
                }

                if (egress_metadata.port_type == PORT_TYPE_NORMAL) {
                    /* egress vlan translation */
                    process_vlan_xlate();
                }

#if defined(ENT_DC_GENERAL_PROFILE)
                /* update egress bd stats */
                process_egress_bd_stats();
#endif /* ENT_DC_GENERAL_PROFILE */

                /* egress filter */
                process_egress_filter();
            }else{
                process_telemetry_deflect_on_drop();
            }
        }

        /* apply egress acl */
        process_egress_system_acl();
#ifdef OPENFLOW_ENABLE
    }
#endif /* OPENFLOW_ENABLE */
}
