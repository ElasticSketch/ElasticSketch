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
 * Segment routing processing
 */

#ifdef SRV6_ENABLE

header_type sr_metadata_t {
    fields {
        endpoint_hit : 1;
        srh_len : 16;
    }
}

metadata sr_metadata_t sr_metadata;

/*
/******************************************************************************/
/* SID lookup                                                                 */
/******************************************************************************/
table srv6_sid {
    reads {
        l3_metadata.vrf : ternary;
        ipv6.dstAddr : ternary;
        ipv6_srh.segLeft : ternary;
        ipv6_srh : valid;
    }
    actions {
        transit;
        endpoint;
    }
    size : SRV6_LOCAL_SID_TABLE_SIZE;
}

action transit() {

}

action endpoint() {
    modify_field(ipv6.dstAddr, ipv6_metadata.lkp_ipv6_da);
    modify_field(sr_metadata.endpoint_hit, TRUE);
}

/******************************************************************************/
/* SR tunnel decap                                                            */
/******************************************************************************/

action remove_ipv6_srh() {
    remove_header(ipv6_srh);
    remove_header(ipv6_srh_seg_list[0]);
    remove_header(ipv6_srh_seg_list[1]);
    remove_header(ipv6_srh_seg_list[2]);
}

action decap_sr_inner_non_ip() {
    copy_header(ethernet, inner_ethernet);
    remove_header(inner_ethernet);
    remove_header(ipv6);
    remove_ipv6_srh();
}

action decap_sr_inner_ipv4() {
    modify_field(ethernet.etherType, ETHERTYPE_IPV4);
    copy_header(ipv4, inner_ipv4);
    remove_header(inner_ipv4);
    remove_header(ipv6);
    remove_ipv6_srh();

}

action decap_sr_inner_ipv6() {
    modify_field(ethernet.etherType, ETHERTYPE_IPV6);
    copy_header(ipv6, inner_ipv6);
    remove_header(inner_ipv6);
    remove_ipv6_srh();
}

/******************************************************************************/
/* SR rewrite                                                                 */
/******************************************************************************/
table srv6_rewrite {
    reads {
        sr_metadata.endpoint_hit : exact;
        ipv6_srh : valid;
        ipv6_srh.segLeft : ternary;
    }

    actions {
        nop;
        rewrite_ipv6_srh;
        rewrite_ipv6_and_remove_srh;
    }
}

table process_srh_len {
    reads {
        ipv6_srh : valid;
        ipv6_srh.hdrExtLen : exact;
    }
    actions {
        nop;
        calculate_srh_total_len;
    }
}

action rewrite_ipv6_and_remove_srh() {
    subtract_from_field(ipv6_srh.segLeft, 1);
    modify_field(ipv6.nextHdr, ipv6_srh.nextHdr);
    subtract_from_field(ipv6.payloadLen, sr_metadata.srh_len);
    remove_header(ipv6_srh);
    remove_header(ipv6_srh_seg_list[0]);
    remove_header(ipv6_srh_seg_list[1]);
    remove_header(ipv6_srh_seg_list[2]);
}

action rewrite_ipv6_srh(srh_len) {
    subtract_from_field(ipv6_srh.segLeft, 1);
}

action calculate_srh_total_len(total_len) {
    // Precomputed values for SRH total length.
    // total_len = (ipv6_srh.hdrExtLen << 3) + 8
    add_to_field(sr_metadata.srh_len, total_len);
}

/******************************************************************************/
/* SR tunnel encap                                                            */
/******************************************************************************/
action f_insert_ipv6_srh(proto) {
    add_header(ipv6_srh);
    modify_field(ipv6_srh.nextHdr, proto);
    modify_field(ipv6_srh.hdrExtLen, 0);
    modify_field(ipv6_srh.routingType, 0x4);
    modify_field(ipv6_srh.segLeft, 0);
    modify_field(ipv6_srh.firstSeg, 0);
    modify_field(ipv6_srh.flags, 0);
    modify_field(ipv6_srh.reserved, 0);
}

action srv6_rewrite() {
    f_insert_ipv6_header(IP_PROTOCOLS_SR);
    f_insert_ipv6_srh(tunnel_metadata.inner_ip_proto);
    modify_field(ethernet.etherType, ETHERTYPE_IPV6);
}

action set_srh_rewrite(srh_len, seg_left) {
    modify_field(ipv6_srh.hdrExtLen, srh_len);
    modify_field(ipv6_srh.segLeft, seg_left);
    modify_field(ipv6_srh.firstSeg, seg_left);
}

action set_srv6_rewrite_segments1(
        sid0, outer_bd, smac_idx, sip_index, dip_index) {
    modify_field(egress_metadata.outer_bd, outer_bd);
    modify_field(tunnel_metadata.tunnel_smac_index, smac_idx);
    set_ip_index(sip_index, dip_index);
    add_header(ipv6_srh_seg_list[0]);
    modify_field(ipv6_srh_seg_list[0].sid, sid0);
    add(ipv6.payloadLen, egress_metadata.payload_length, 0x18);
    set_srh_rewrite(0x2, 0);
}

action set_srv6_rewrite_segments2(
        sid0, sid1, outer_bd, smac_idx, sip_index, dip_index) {
    modify_field(egress_metadata.outer_bd, outer_bd);
    modify_field(tunnel_metadata.tunnel_smac_index, smac_idx);
    set_ip_index(sip_index, dip_index);
    add_header(ipv6_srh_seg_list[0]);
    add_header(ipv6_srh_seg_list[1]);
    modify_field(ipv6_srh_seg_list[0].sid, sid0);
    modify_field(ipv6_srh_seg_list[1].sid, sid1);
    add(ipv6.payloadLen, egress_metadata.payload_length, 0x28);
    set_srh_rewrite(0x4, 1);
}

action set_srv6_rewrite_segments3(
        sid0, sid1, sid2, outer_bd, smac_idx, sip_index, dip_index) {
    modify_field(egress_metadata.outer_bd, outer_bd);
    modify_field(tunnel_metadata.tunnel_smac_index, smac_idx);
    set_ip_index(sip_index, dip_index);
    add_header(ipv6_srh_seg_list[0]);
    add_header(ipv6_srh_seg_list[1]);
    add_header(ipv6_srh_seg_list[2]);
    modify_field(ipv6_srh_seg_list[0].sid, sid0);
    modify_field(ipv6_srh_seg_list[1].sid, sid1);
    modify_field(ipv6_srh_seg_list[2].sid, sid2);
    add(ipv6.payloadLen, egress_metadata.payload_length, 0x38);
    set_srh_rewrite(0x6, 2);
}

#endif /* SRV6_ENABLE */


control process_srv6_rewrite {
#ifdef SRV6_ENABLE
    apply(process_srh_len);
    apply(srv6_rewrite);
#endif /* SRV6_ENABLE */
}

control process_srv6 {
#ifdef SRV6_ENABLE
    if (valid(ipv6)) {
        apply(srv6_sid);
    }
#endif /* SRV6_ENABLE */
}
