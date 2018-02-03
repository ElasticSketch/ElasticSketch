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
 * Meter processing
 */

/*
 * Meter metadata
 */
 header_type meter_metadata_t {
     fields {
         storm_control_color : 2;
         qos_meter_color : 2;
         packet_color : 2;               /* packet color */
         meter_drop : 1;                 /* meter drop */
         meter_index : 16;               /* meter index */
     }
 }

#if defined(QOS_METERING_ENABLE)
@pragma pa_atomic ingress meter_metadata.packet_color
@pragma pa_solitary ingress meter_metadata.packet_color

@pragma pa_atomic ingress meter_metadata.meter_index
@pragma pa_solitary ingress meter_metadata.meter_index
#endif /* QOS_METERING_ENABLE */

metadata meter_metadata_t meter_metadata;

/*****************************************************************************/
/* Meters                                                                    */
/*****************************************************************************/
#if defined(QOS_METERING_ENABLE)
action meter_deny() {
    modify_field(meter_metadata.meter_drop, TRUE);
}

action meter_permit() {
}

#ifndef STATS_DISABLE
counter meter_stats {
    type : packets;
    direct : meter_action;
}
#endif /* STATS_DISABLE */

table meter_action {
    reads {
        meter_metadata.packet_color : exact;
        meter_metadata.meter_index : exact;
    }

    actions {
        meter_permit;
        meter_deny;
    }
    size: METER_ACTION_TABLE_SIZE;
}

meter meter_index {
    type : bytes;
    direct : meter_index;
    result : meter_metadata.packet_color;
}

@pragma ternary 1
table meter_index {
    reads {
        meter_metadata.meter_index: exact;
    }
    actions {
        nop;
    }
    size: METER_INDEX_TABLE_SIZE;
}
#endif /* QOS_METERING_ENABLE */

control process_meter_index {
#if defined(QOS_METERING_ENABLE)
    if (DO_LOOKUP(METER)) {
        apply(meter_index);
    }
#endif /* QOS_METERING_ENABLE */
}

control process_meter_action {
#if defined(QOS_METERING_ENABLE)
    if (DO_LOOKUP(METER)) {
        apply(meter_action);
    }
#endif /* QOS_METERING_ENABLE */
}
