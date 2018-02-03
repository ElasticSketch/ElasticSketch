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
 * IPv4 processing
 */

/*
 * IPv4 metadata
 */
header_type ipv4_metadata_t {
    fields {
        lkp_ipv4_sa : 32;
        lkp_ipv4_da : 32;
        ipv4_unicast_enabled : 1;      /* is ipv4 unicast routing enabled */
#if !defined(URPF_DISABLE)
        ipv4_urpf_mode : 2;            /* 0: none, 1: strict, 3: loose */
#endif /* URPF_DISABLE */
    }
}

#if defined(TUNNEL_PARSING_DISABLE)
@pragma pa_alias ingress ipv4_metadata.lkp_ipv4_sa ipv4.srcAddr
@pragma pa_alias ingress ipv4_metadata.lkp_ipv4_da ipv4.dstAddr
#endif /* !TUNNEL_PARSING_DISABLE */

metadata ipv4_metadata_t ipv4_metadata;

#if !defined(L3_DISABLE) && !defined(IPV4_DISABLE)
/*****************************************************************************/
/* Validate outer IPv4 header                                                */
/*****************************************************************************/
action set_valid_outer_ipv4_packet() {
    modify_field(l3_metadata.lkp_ip_type, IPTYPE_IPV4);
    modify_field(l3_metadata.lkp_dscp, ipv4.diffserv);
    modify_field(l3_metadata.lkp_ip_version, ipv4.version);
}

action set_malformed_outer_ipv4_packet(drop_reason) {
    modify_field(ingress_metadata.drop_flag, TRUE);
    modify_field(ingress_metadata.drop_reason, drop_reason);
}

table validate_outer_ipv4_packet {
    reads {
        ipv4.version : ternary;
        ipv4.ihl: ternary;
        ipv4.ttl : ternary;
        ipv4.srcAddr mask 0xFF000000 : ternary;
    }
    actions {
        set_valid_outer_ipv4_packet;
        set_malformed_outer_ipv4_packet;
    }
    size : VALIDATE_PACKET_TABLE_SIZE;
}
#endif /* L3_DISABLE && IPV4_DISABLE */

control validate_outer_ipv4_header {
#if !defined(L3_DISABLE) && !defined(IPV4_DISABLE)
    apply(validate_outer_ipv4_packet);
#endif /* L3_DISABLE && IPV4_DISABLE */
}

#if !defined(L3_DISABLE) && !defined(IPV4_DISABLE)
#define IPV4_HOST_MATCH_SPEC \
        l3_metadata.vrf : exact; \
        ipv4_metadata.lkp_ipv4_da : exact;

/*****************************************************************************/
/* IPv4 FIB local hosts lookup                                               */
/*****************************************************************************/
#ifdef IPV4_LOCAL_HOST_TABLE_SIZE
table ipv4_fib_local_hosts {
    reads {
        IPV4_HOST_MATCH_SPEC
    }
    actions {
        on_miss;
        fib_hit_nexthop;
        fib_hit_myip;
        fib_hit_ecmp;
    }
    size : IPV4_LOCAL_HOST_TABLE_SIZE;
}
#endif

/*****************************************************************************/
/* IPv4 FIB lookup                                                           */
/*****************************************************************************/
table ipv4_fib {
    reads {
        IPV4_HOST_MATCH_SPEC
    }
    actions {
        on_miss;
        fib_hit_nexthop;
        fib_hit_myip;
        fib_hit_ecmp;
    }
    size : IPV4_HOST_TABLE_SIZE;
}

#ifdef FIB_ATCAM
action set_ipv4_fib_partition_index(partition_index) {
    modify_field(l3_metadata.fib_partition_index, partition_index);
}

table ipv4_fib_partition {
    reads {
        l3_metadata.vrf : exact;
        ipv4_metadata.lkp_ipv4_da : lpm;
    }
    actions {
        set_ipv4_fib_partition_index;
    }
    size : IPV4_FIB_PARTITION_TABLE_SIZE;
}
#endif /* FIB_ATCAM */

#if defined(FIB_ALPM)
@pragma alpm 1
@pragma ways 6
@pragma pa_solitary ingress ipv4_fib_lpm__metadata.ipv4_fib_lpm_partition_index
#elif defined(FIB_ATCAM)
@pragma atcam_number_partitions IPV4_FIB_PARTITION_TABLE_SIZE
@pragma atcam_partition_index l3_metadata.fib_partition_index
@pragma ways 4
#elif defined(FIB_CLPM)
@pragma clpm_prefix ipv4_metadata.lkp_ipv4_da
@pragma clpm_prefix_length 0 15 IPV4_PREFIX_0_15_TABLE_SIZE
@pragma clpm_prefix_length 16 IPV4_PREFIX_16_TABLE_SIZE
@pragma clpm_prefix_length 17 IPV4_PREFIX_17_TABLE_SIZE
@pragma clpm_prefix_length 18 IPV4_PREFIX_18_TABLE_SIZE
@pragma clpm_prefix_length 19 IPV4_PREFIX_19_TABLE_SIZE
@pragma clpm_prefix_length 20 IPV4_PREFIX_20_TABLE_SIZE
@pragma clpm_prefix_length 21 IPV4_PREFIX_21_TABLE_SIZE
@pragma clpm_prefix_length 22 IPV4_PREFIX_22_TABLE_SIZE
@pragma clpm_prefix_length 23 IPV4_PREFIX_23_TABLE_SIZE
@pragma clpm_prefix_length 24 IPV4_PREFIX_24_TABLE_SIZE
@pragma clpm_prefix_length 25 31 IPV4_PREFIX_25_31_TABLE_SIZE
#endif

table ipv4_fib_lpm {
    reads {
#ifdef FIB_ATCAM
        l3_metadata.fib_partition_index : exact;
#endif /* FIB_ATCAM */
        l3_metadata.vrf : exact;
        ipv4_metadata.lkp_ipv4_da : lpm;
    }
    actions {
        on_miss;
        fib_hit_nexthop;
        fib_hit_ecmp;
    }
    size : IPV4_LPM_TABLE_SIZE;
}
#endif /* L3_DISABLE && IPV4_DISABLE */

control process_ipv4_fib {
#if !defined(L3_DISABLE) && !defined(IPV4_DISABLE)
#if defined(FIB_ATCAM)
    apply(ipv4_fib_partition);
#endif /* FIB_ATCAM */
#ifdef IPV4_LOCAL_HOST_TABLE_SIZE
    apply(ipv4_fib_local_hosts) {
        on_miss {
#endif
            apply(ipv4_fib) {
                on_miss {
                    apply(ipv4_fib_lpm);
                }
            }
#ifdef IPV4_LOCAL_HOST_TABLE_SIZE
        }
    }
#endif
#endif /* L3_DISABLE && IPV4_DISABLE */
}

#if !defined(L3_DISABLE) && !defined(IPV4_DISABLE) && !defined(URPF_DISABLE)
#define IPV4_HOST_URPF_MATCH_SPEC \
        l3_metadata.vrf : exact; \
        ipv4_metadata.lkp_ipv4_sa : exact;

/*****************************************************************************/
/* IPv4 uRPF lookup                                                          */
/*****************************************************************************/
action ipv4_urpf_hit(urpf_bd_group) {
    modify_field(l3_metadata.urpf_hit, TRUE);
    modify_field(l3_metadata.urpf_bd_group, urpf_bd_group);
    modify_field(l3_metadata.urpf_mode, ipv4_metadata.ipv4_urpf_mode);
}

table ipv4_urpf_lpm {
    reads {
        l3_metadata.vrf : exact;
        ipv4_metadata.lkp_ipv4_sa : lpm;
    }
    actions {
        ipv4_urpf_hit;
        urpf_miss;
    }
    size : IPV4_LPM_TABLE_SIZE;
}

#ifdef IPV4_LOCAL_HOST_TABLE_SIZE
table ipv4_local_hosts_urpf {
    reads {
        IPV4_HOST_URPF_MATCH_SPEC
    }
    actions {
        on_miss;
        ipv4_urpf_hit;
    }
    size : IPV4_LOCAL_HOST_TABLE_SIZE;
}
#endif

table ipv4_urpf {
    reads {
        IPV4_HOST_URPF_MATCH_SPEC
    }
    actions {
        on_miss;
        ipv4_urpf_hit;
    }
    size : IPV4_HOST_TABLE_SIZE;
}
#endif /* L3_DISABLE && IPV4_DISABLE && URPF_DISABLE */

control process_ipv4_urpf {
#if !defined(L3_DISABLE) && !defined(IPV4_DISABLE) && !defined(URPF_DISABLE)
    /* unicast rpf lookup */
    if (ipv4_metadata.ipv4_urpf_mode != URPF_MODE_NONE) {
#ifdef IPV4_LOCAL_HOST_TABLE_SIZE
        apply(ipv4_local_hosts_urpf) {
            on_miss {
#endif
                apply(ipv4_urpf) {
                    on_miss {
                        apply(ipv4_urpf_lpm);
                    }
                }
#ifdef IPV4_LOCAL_HOST_TABLE_SIZE
            }
        }
#endif
    }
#endif /* L3_DISABLE && IPV4_DISABLE && URPF_DISABLE */
}
