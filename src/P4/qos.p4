
/*****************************************************************************/
/* Qos Processing                                                            */
/*****************************************************************************/

header_type qos_metadata_t {
    fields {
        ingress_qos_group: 5;
        tc_qos_group: 5;
        egress_qos_group: 5;
        lkp_tc: 8;
        trust_dscp: 1;
        trust_pcp: 1;
    }
}

metadata qos_metadata_t qos_metadata;

/*****************************************************************************/
/* Ingress QOS Map                                                           */
/*****************************************************************************/
#ifdef QOS_CLASSIFICATION_ENABLE
action set_ingress_tc_and_color(tc, color) {
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(meter_metadata.packet_color, color);
}

action set_ingress_tc(tc) {
    modify_field(qos_metadata.lkp_tc, tc);
}

action set_ingress_color(color) {
  modify_field(meter_metadata.packet_color, color);
}

table ingress_qos_map_dscp {
    reads {
        qos_metadata.ingress_qos_group: ternary;
        l3_metadata.lkp_dscp: ternary;
    }

    actions {
        nop;
        set_ingress_tc;
        set_ingress_color;
        set_ingress_tc_and_color;
    }

    size: DSCP_TO_TC_AND_COLOR_TABLE_SIZE;
}

table ingress_qos_map_pcp {
    reads {
        qos_metadata.ingress_qos_group: ternary;
        l2_metadata.lkp_pcp: ternary;
    }

    actions {
        nop;
        set_ingress_tc;
        set_ingress_color;
        set_ingress_tc_and_color;
    }

    size: PCP_TO_TC_AND_COLOR_TABLE_SIZE;
}

#endif /* QOS_CLASSIFICATION_ENABLE */

#if !defined(QOS_CLASSIFICATION_ENABLE) && defined(SS_QOS_CLASSIFICATION_ENABLE)
action set_ingress_qid_and_tc_and_color(tc, icos, qid, color) {
    modify_field(qos_metadata.lkp_tc, tc);
    modify_field(ig_intr_md_for_tm.ingress_cos, icos);
    modify_field(ig_intr_md_for_tm.qid, qid);
    modify_field(meter_metadata.packet_color, color);
}

table ingress_qos_map {
    reads {
        qos_metadata.ingress_qos_group: ternary;
        l3_metadata.lkp_dscp: ternary;
        l2_metadata.lkp_pcp: ternary;
        qos_metadata.trust_dscp: ternary;
        qos_metadata.trust_pcp: ternary;
      // Following fields may be needed in the match key if we want to
      // take care of these corner cases :
      // -- trust_dscp is enabled, incoming packet is non-IP and port-default
      //    policy is different than dscp=0 policy
      // -- trust_cos is enabled, incoming packet doesn't have a vlan tag
      //    and port-default policy is different than PCP=0 policy
//        ipv4: valid;
//        ipv6: valid;
//        vlan_tag_[0]: valid;
     }
 
    actions {
         nop;
         set_ingress_qid_and_tc_and_color;
    }
    size: INGRESS_QOS_MAP_TABLE_SIZE;
}
#endif /* SS_QOS_CLASSIFICATION_ENABLE */

control process_ingress_qos_map {
    if (DO_LOOKUP(QOS)) {
#if defined(QOS_CLASSIFICATION_ENABLE)
#if defined(MAC_QOS_ACL_ENABLE) && defined(IPV4_QOS_ACL_ENABLE)
	    /* l2 and ipv4 qos ACL */
	    if (l3_metadata.lkp_ip_type == IPTYPE_NONE) {
	      apply(mac_qos_acl) {
		nop {
		  if ((qos_metadata.trust_pcp == TRUE) and (valid(vlan_tag_[0]))) {
		    apply(ingress_qos_map_pcp);
		  }
		}
	      }
	    } else if (l3_metadata.lkp_ip_type == IPTYPE_IPV4)  {
	      apply(ipv4_qos_acl) {
		nop {
		  if (qos_metadata.trust_dscp == TRUE) {
		    apply(ingress_qos_map_dscp);
		  }
		}
	      }
	    } else if (l3_metadata.lkp_ip_type == IPTYPE_IPV6)  {
//	      apply(ipv6_qos_acl) {
//		nop {
		  if (qos_metadata.trust_dscp == TRUE) {
		    apply(ingress_qos_map_dscp);
		  }
//		}
//	      }
	    }
#else      
      if ((qos_metadata.trust_dscp == TRUE) and (l3_metadata.lkp_ip_type != IPTYPE_NONE)) {
	  apply(ingress_qos_map_dscp);
      } else if ((qos_metadata.trust_pcp == TRUE) and (valid(vlan_tag_[0]))) {
	  apply(ingress_qos_map_pcp);
      }
#endif      
#elif defined(SS_QOS_CLASSIFICATION_ENABLE)
	apply(ingress_qos_map);
#endif /* SS_QOS_CLASSIFICATION_ENABLE */
    }
}


/*****************************************************************************/
/* Queuing                                                                   */
/*****************************************************************************/

#ifdef QOS_CLASSIFICATION_ENABLE
action set_icos(icos) {
    modify_field(ig_intr_md_for_tm.ingress_cos, icos);
}

action set_queue(qid) {
    modify_field(ig_intr_md_for_tm.qid, qid);
}

action set_icos_and_queue(icos, qid) {
    modify_field(ig_intr_md_for_tm.ingress_cos, icos);
    modify_field(ig_intr_md_for_tm.qid, qid);
}

table traffic_class {
    reads {
        qos_metadata.tc_qos_group: ternary;
        qos_metadata.lkp_tc: ternary;
    }

    actions {
        nop;
        set_icos;
        set_queue;
        set_icos_and_queue;
    }
    size: QUEUE_TABLE_SIZE;
}
#endif /* QOS_CLASSIFICATION_ENABLE */

control process_traffic_class{
#ifdef QOS_CLASSIFICATION_ENABLE
    apply(traffic_class);
#endif /* QOS_CLASSIFICATION_ENABLE */
}

/*****************************************************************************/
/* Egress QOS Map                                                            */
/*****************************************************************************/
#if defined(QOS_MARKING_ENABLE)
action set_mpls_exp_marking(exp) {
    modify_field(l3_metadata.lkp_dscp, exp, 0xfc);
}

action set_ip_dscp_marking(dscp) {
    modify_field(l3_metadata.lkp_dscp, dscp, 0xfc);
}

action set_vlan_pcp_marking(pcp) {
    modify_field(l2_metadata.lkp_pcp, pcp);
}

table egress_qos_map {
    reads {
        qos_metadata.egress_qos_group: ternary;
        qos_metadata.lkp_tc: ternary;
        //meter_metadata.packet_color : ternary;
    }
    actions {
        nop;
        set_mpls_exp_marking;
        set_ip_dscp_marking;
        set_vlan_pcp_marking;
    }
    size: EGRESS_QOS_MAP_TABLE_SIZE;
}
#endif /* QOS_MARKING_ENABLE */

control process_egress_qos_map {
#if defined(QOS_MARKING_ENABLE)
    if (DO_LOOKUP(QOS)) {
        apply(egress_qos_map);
    }
#endif /* QOS_MARKING_ENABLE */
}
