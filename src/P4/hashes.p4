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
/*****************************************************************************/
/* HASH calculation                                                          */
/*****************************************************************************/
header_type hash_metadata_t {
    fields {
#if defined(HASH_32BIT_ENABLE)
        hash1 : 32;
        hash2 : 32;
#else
        hash1 : 16;
        hash2 : 16;
#endif /* HASH_32BIT_ENABLE */
        entropy_hash : 16;
    }
}

@pragma pa_atomic ingress hash_metadata.hash1
@pragma pa_solitary ingress hash_metadata.hash1
@pragma pa_atomic ingress hash_metadata.hash2
@pragma pa_solitary ingress hash_metadata.hash2
metadata hash_metadata_t hash_metadata;

#if defined(SYMMETRIC_HASH_ENABLE)
@pragma symmetric ipv4_metadata.lkp_ipv4_sa ipv4_metadata.lkp_ipv4_da
@pragma symmetric ipv6_metadata.lkp_ipv6_sa ipv6_metadata.lkp_ipv6_da
@pragma symmetric l3_metadata.lkp_l4_sport l3_metadata.lkp_l4_dport
@pragma symmetric l2_metadata.lkp_mac_sa l2_metadata.lkp_mac_da
#endif /* SYMMETRIC_HASH_ENABLE */

field_list lkp_ipv4_hash1_fields {
    ipv4_metadata.lkp_ipv4_sa;
    ipv4_metadata.lkp_ipv4_da;
    l3_metadata.lkp_ip_proto;
    l3_metadata.lkp_l4_sport;
    l3_metadata.lkp_l4_dport;
}
field_list lkp_ipv4_hash1_fields_1 {
    l3_metadata.lkp_ip_proto;
    l3_metadata.lkp_l4_dport;
    ipv4_metadata.lkp_ipv4_da;
    l3_metadata.lkp_l4_sport;
    ipv4_metadata.lkp_ipv4_sa;
}

// UNUSED
//field_list lkp_ipv4_hash2_fields {
//    l2_metadata.lkp_mac_sa;
//    l2_metadata.lkp_mac_da;
//    ipv4_metadata.lkp_ipv4_sa;
//    ipv4_metadata.lkp_ipv4_da;
//    l3_metadata.lkp_ip_proto;
//    l3_metadata.lkp_l4_sport;
//    l3_metadata.lkp_l4_dport;
//}

field_list_calculation lkp_ipv4_hash1 {
    input {
        lkp_ipv4_hash1_fields; 
        lkp_ipv4_hash1_fields_1;
   }
#if defined(BMV2) && defined(INT_ENABLE)
    algorithm : crc16_custom;
#elif defined(HASH_32BIT_ENABLE)
    algorithm {
        crc_32;
        crc_32_bzip2;
        crc_32c;
        crc_32d;
    }
#else
    algorithm {
        crc16;
	crc_16_dect;
	crc_16_genibus;
	crc_16_dnp;
	crc_16_teledisk;
    }
#endif
#if defined(HASH_32BIT_ENABLE)    
    output_width : 32;
#else
    output_width : 16;
#endif
}

// UNUSED
//field_list_calculation lkp_ipv4_hash2 {
//    input {
//        lkp_ipv4_hash2_fields;
//    }
//#if defined(BMV2) && defined(INT_ENABLE)
//    algorithm : crc16_custom;
//#else
//    algorithm : crc16;
//#endif
//    output_width : 16;
//}

action compute_lkp_ipv4_hash() {
#if defined(HASH_32BIT_ENABLE)
    modify_field_with_hash_based_offset(hash_metadata.hash1, 0,
                                        lkp_ipv4_hash1, 4294967296);
#else
    modify_field_with_hash_based_offset(hash_metadata.hash1, 0,
                                        lkp_ipv4_hash1, 65536);
#endif /* HASH_32BIT_ENABLE */
}

field_list lkp_ipv6_hash1_fields {
    ipv6_metadata.lkp_ipv6_sa;
    ipv6_metadata.lkp_ipv6_da;
    l3_metadata.lkp_ip_proto;
    l3_metadata.lkp_l4_sport;
    l3_metadata.lkp_l4_dport;
}
field_list lkp_ipv6_hash1_fields_1 {
    l3_metadata.lkp_ip_proto;
    l3_metadata.lkp_l4_dport;
    ipv6_metadata.lkp_ipv6_sa;
    l3_metadata.lkp_l4_sport;
    ipv6_metadata.lkp_ipv6_da;
}

// UNUSED
//field_list lkp_ipv6_hash2_fields {
//    l2_metadata.lkp_mac_sa;
//    l2_metadata.lkp_mac_da;
//    ipv6_metadata.lkp_ipv6_sa;
//    ipv6_metadata.lkp_ipv6_da;
//    l3_metadata.lkp_ip_proto;
//    l3_metadata.lkp_l4_sport;
//    l3_metadata.lkp_l4_dport;
//}

field_list_calculation lkp_ipv6_hash1 {
    input {
        lkp_ipv6_hash1_fields;
        lkp_ipv6_hash1_fields_1;
    }
#if defined(BMV2) && defined(INT_ENABLE)
    algorithm : crc16_custom;
#elif defined(HASH_32BIT_ENABLE)
    algorithm {
        crc_32;
        crc_32_bzip2;
        crc_32c;
        crc_32d;
    }
#else
    algorithm {
        crc16;
	crc_16_dect;
	crc_16_genibus;
	crc_16_dnp;
	crc_16_teledisk;
    }
#endif
#if defined(HASH_32BIT_ENABLE)    
    output_width : 32;
#else
    output_width : 16;
#endif
}

// UNUSED
//field_list_calculation lkp_ipv6_hash2 {
//    input {
//        lkp_ipv6_hash2_fields;
//    }
//#if defined(BMV2) && defined(INT_ENABLE)
//    algorithm : crc16_custom;
//#else
//    algorithm : crc16;
//#endif
//    output_width : 16;
//}

action compute_lkp_ipv6_hash() {
#if defined(HASH_32BIT_ENABLE)
    modify_field_with_hash_based_offset(hash_metadata.hash1, 0,
                                        lkp_ipv6_hash1, 4294967296);
#else
    modify_field_with_hash_based_offset(hash_metadata.hash1, 0,
                                        lkp_ipv6_hash1, 65536);
#endif /* HASH_32BIT_ENABLE */
}

field_list lkp_non_ip_hash1_fields {
    ingress_metadata.ifindex;
    l2_metadata.lkp_mac_sa;
    l2_metadata.lkp_mac_da;
    l2_metadata.lkp_mac_type;
}
field_list lkp_non_ip_hash1_fields_1 {
    l2_metadata.lkp_mac_type;
    l2_metadata.lkp_mac_sa;
    ingress_metadata.ifindex;
    l2_metadata.lkp_mac_da;
}

field_list_calculation lkp_non_ip_hash1 {
    input {
        lkp_non_ip_hash1_fields;
        lkp_non_ip_hash1_fields_1;
    }
#if defined(HASH_32BIT_ENABLE)
    algorithm {
        crc_32;
        crc_32_bzip2;
        crc_32c;
        crc_32d;
    }
    output_width : 32;
#else
    algorithm {
        crc16;
	crc_16_dect;
	crc_16_genibus;
	crc_16_dnp;
	crc_16_teledisk;
    }
    output_width : 16;
#endif
}

action compute_lkp_non_ip_hash() {
#if defined(HASH_32BIT_ENABLE)
    modify_field_with_hash_based_offset(hash_metadata.hash1, 0,
                                        lkp_non_ip_hash1, 4294967296);
#else
    modify_field_with_hash_based_offset(hash_metadata.hash1, 0,
                                        lkp_non_ip_hash1, 65536);
#endif /* HASH_32BIT_ENABLE */
}

table compute_ipv4_hashes {
#ifdef __TARGET_TOFINO__
    reads {
        ethernet: valid;
    }
#endif /* __TARGET_TOFINO__ */
    actions {
        compute_lkp_ipv4_hash;
    }
}

table compute_ipv6_hashes {
#ifdef __TARGET_TOFINO__
    reads {
        ethernet: valid;
    }
#endif /* __TARGET_TOFINO__ */
    actions {
        compute_lkp_ipv6_hash;
    }
}

table compute_non_ip_hashes {
#ifdef __TARGET_TOFINO__
    reads {
        ethernet: valid;
    }
#endif /* __TARGET_TOFINO__ */
    actions {
        compute_lkp_non_ip_hash;
    }
}

action compute_other_hashes() {
    shift_right(hash_metadata.hash2, hash_metadata.hash1, 2);
    modify_field(ig_intr_md_for_tm.level1_mcast_hash, hash_metadata.hash1);
    shift_right(ig_intr_md_for_tm.level2_mcast_hash, hash_metadata.hash1, 3);
    modify_field(hash_metadata.entropy_hash, hash_metadata.hash1);
}

@pragma ternary 1
table compute_other_hashes {
#ifdef __TARGET_TOFINO__
    reads {
        ethernet: valid;
    }
#endif /* __TARGET_TOFINO__ */
    actions {
        compute_other_hashes;
    }
}

control process_hashes {
    if (((tunnel_metadata.tunnel_terminate == FALSE) and valid(ipv4)) or
        ((tunnel_metadata.tunnel_terminate == TRUE) and valid(inner_ipv4))) {
#ifndef IPV4_DISABLE
        apply(compute_ipv4_hashes);
#endif /* IPV4_DISABLE */
    }
#ifndef IPV6_DISABLE
    else {
        if (((tunnel_metadata.tunnel_terminate == FALSE) and valid(ipv6)) or
             ((tunnel_metadata.tunnel_terminate == TRUE) and valid(inner_ipv6))) {
            apply(compute_ipv6_hashes);
        }
#endif /* IPV6_DISABLE */
        else {
#ifndef L2_DISABLE
            apply(compute_non_ip_hashes);
#endif /* L2_DISABLE */
        }
#ifndef IPV6_DISABLE
    }
#endif /* IPV6_DISABLE */
    apply(compute_other_hashes);
}
