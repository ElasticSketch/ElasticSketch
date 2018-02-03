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
 * System global parameters
 */

action set_config_parameters(enable_flowlet, switch_id) {
    /* initialization */
    modify_field(i2e_metadata.ingress_tstamp, _ingress_global_tstamp_);
    modify_field(ingress_metadata.ingress_port, ig_intr_md.ingress_port);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, INVALID_PORT_ID);
#ifdef FLOWLET_ENABLE
    modify_field(flowlet_metadata.enable, enable_flowlet);
#endif
    modify_field(global_config_metadata.switch_id, switch_id);
}

#if defined(ENT_DC_GENERAL_PROFILE)
/* The packet length on egress is not necessary for mirrored packets.
   This pragma indicates that the packet length does not need to be
   adjusted for mirrored packets, which eliminates the need for
   additional memory to be used. */
@pragma no_egress_length_correct_for_mirror 1
#endif
table switch_config_params {
    actions {
        set_config_parameters;
    }
    size : 1;
}

control process_global_params {
    /* set up global controls/parameters */
    apply(switch_config_params);
#ifdef SFLOW_ENABLE
    apply(sflow_config);
#endif /* SFLOW_ENABLE */
}
