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
#ifndef _P4_TABLE_SIZES_H_
#define _P4_TABLE_SIZES_H_

// default undefs
#undef IPV4_LOCAL_HOST_TABLE_SIZE

#if defined(MIN_TABLE_SIZES)
/******************************************************************************
 *  Min Table Size profile
 *****************************************************************************/
#define MIN_SRAM_TABLE_SIZE                    1024
#define MIN_TCAM_TABLE_SIZE                    512

#define VALIDATE_PACKET_TABLE_SIZE             MIN_TCAM_TABLE_SIZE
#define PORTMAP_TABLE_SIZE                     288
#define STORM_CONTROL_TABLE_SIZE               MIN_TCAM_TABLE_SIZE
#define STORM_CONTROL_METER_TABLE_SIZE         MIN_SRAM_TABLE_SIZE
#define STORM_CONTROL_STATS_TABLE_SIZE         MIN_SRAM_TABLE_SIZE
#define PORT_VLAN_TABLE_SIZE                   4096
#define OUTER_ROUTER_MAC_TABLE_SIZE            MIN_SRAM_TABLE_SIZE
#define DEST_TUNNEL_TABLE_SIZE                 MIN_SRAM_TABLE_SIZE
#define IPV4_SRC_TUNNEL_TABLE_SIZE             MIN_SRAM_TABLE_SIZE
#define IPV6_SRC_TUNNEL_TABLE_SIZE             MIN_SRAM_TABLE_SIZE
#define TUNNEL_SRC_REWRITE_TABLE_SIZE          MIN_SRAM_TABLE_SIZE
#define TUNNEL_DST_REWRITE_TABLE_SIZE          MIN_SRAM_TABLE_SIZE
#define TUNNEL_TO_MGID_MAPPING_TABLE_SIZE      MIN_SRAM_TABLE_SIZE
#define OUTER_MULTICAST_STAR_G_TABLE_SIZE      MIN_TCAM_TABLE_SIZE
#define OUTER_MULTICAST_S_G_TABLE_SIZE         MIN_SRAM_TABLE_SIZE
#define VNID_MAPPING_TABLE_SIZE                MIN_SRAM_TABLE_SIZE
#define BD_TABLE_SIZE                          MIN_SRAM_TABLE_SIZE
#define EGRESS_OUTER_BD_MAPPING_TABLE_SIZE     MIN_SRAM_TABLE_SIZE
#define EGRESS_OUTER_BD_STATS_TABLE_SIZE       MIN_SRAM_TABLE_SIZE
#define CPU_BD_TABLE_SIZE                      MIN_SRAM_TABLE_SIZE
#define BD_FLOOD_TABLE_SIZE                    MIN_SRAM_TABLE_SIZE
#define BD_STATS_TABLE_SIZE                    MIN_SRAM_TABLE_SIZE
#define OUTER_MCAST_RPF_TABLE_SIZE             MIN_SRAM_TABLE_SIZE
#define MPLS_TABLE_SIZE                        MIN_SRAM_TABLE_SIZE
#define VALIDATE_MPLS_TABLE_SIZE               MIN_TCAM_TABLE_SIZE

#define ROUTER_MAC_TABLE_SIZE                  MIN_SRAM_TABLE_SIZE
#define MAC_TABLE_SIZE                         MIN_SRAM_TABLE_SIZE
#define IPSG_TABLE_SIZE                        MIN_SRAM_TABLE_SIZE
#define IPSG_PERMIT_SPECIAL_TABLE_SIZE         MIN_TCAM_TABLE_SIZE
#define INGRESS_MAC_ACL_TABLE_SIZE             MIN_TCAM_TABLE_SIZE
#define INGRESS_IP_ACL_TABLE_SIZE              MIN_TCAM_TABLE_SIZE
#define INGRESS_IPV6_ACL_TABLE_SIZE            MIN_TCAM_TABLE_SIZE
#define INGRESS_ECN_ACL_TABLE_SIZE             MIN_TCAM_TABLE_SIZE
#define INGRESS_MAC_QOS_ACL_TABLE_SIZE         MIN_TCAM_TABLE_SIZE
#define INGRESS_IPV4_QOS_ACL_TABLE_SIZE        MIN_TCAM_TABLE_SIZE
#define INGRESS_IPV6_QOS_ACL_TABLE_SIZE        MIN_TCAM_TABLE_SIZE
#define EGRESS_MAC_ACL_TABLE_SIZE              MIN_TCAM_TABLE_SIZE
#define EGRESS_IP_ACL_TABLE_SIZE               MIN_TCAM_TABLE_SIZE
#define EGRESS_IPV6_ACL_TABLE_SIZE             MIN_TCAM_TABLE_SIZE
#define INGRESS_IP_RACL_TABLE_SIZE             MIN_TCAM_TABLE_SIZE
#define INGRESS_IPV6_RACL_TABLE_SIZE           MIN_TCAM_TABLE_SIZE
#define IP_NAT_TABLE_SIZE                      MIN_SRAM_TABLE_SIZE
#define IP_NAT_FLOW_TABLE_SIZE                 MIN_TCAM_TABLE_SIZE
#define EGRESS_NAT_TABLE_SIZE                  MIN_SRAM_TABLE_SIZE
#define UPDATE_L4_CHECKSUM_TABLE_SIZE          MIN_SRAM_TABLE_SIZE
#define IPV4_LPM_TABLE_SIZE                    MIN_TCAM_TABLE_SIZE
#define IPV6_LPM_TABLE_SIZE                    MIN_TCAM_TABLE_SIZE
#define IPV4_HOST_TABLE_SIZE                   MIN_SRAM_TABLE_SIZE
#define IPV6_HOST_TABLE_SIZE                   MIN_SRAM_TABLE_SIZE
#define IPV4_MULTICAST_STAR_G_TABLE_SIZE       MIN_SRAM_TABLE_SIZE
#define IPV4_MULTICAST_S_G_TABLE_SIZE          MIN_SRAM_TABLE_SIZE
#define IPV6_MULTICAST_STAR_G_TABLE_SIZE       MIN_SRAM_TABLE_SIZE
#define IPV6_MULTICAST_S_G_TABLE_SIZE          MIN_SRAM_TABLE_SIZE
#define MCAST_RPF_TABLE_SIZE                   MIN_SRAM_TABLE_SIZE
#define FWD_RESULT_TABLE_SIZE                  MIN_TCAM_TABLE_SIZE
#define URPF_GROUP_TABLE_SIZE                  MIN_SRAM_TABLE_SIZE
#define ECMP_GROUP_TABLE_SIZE                  MIN_SRAM_TABLE_SIZE
#define ECMP_SELECT_TABLE_SIZE                 MIN_SRAM_TABLE_SIZE
#define WCMP_GROUP_TABLE_SIZE                  MIN_TCAM_TABLE_SIZE
#define NEXTHOP_TABLE_SIZE                     MIN_SRAM_TABLE_SIZE
#define LAG_GROUP_TABLE_SIZE                   MIN_SRAM_TABLE_SIZE
#define LAG_SELECT_TABLE_SIZE                  MIN_SRAM_TABLE_SIZE
#define SYSTEM_ACL_SIZE                        MIN_TCAM_TABLE_SIZE
#define LEARN_NOTIFY_TABLE_SIZE                MIN_TCAM_TABLE_SIZE
#define INGRESS_ECN_ACL_TABLE_SIZE             MIN_TCAM_TABLE_SIZE
#define INGRESS_MIRROR_ACL_TABLE_SIZE          MIN_TCAM_TABLE_SIZE

#define MAC_REWRITE_TABLE_SIZE                 MIN_TCAM_TABLE_SIZE
#define EGRESS_VNID_MAPPING_TABLE_SIZE         MIN_SRAM_TABLE_SIZE
#define EGRESS_BD_MAPPING_TABLE_SIZE           MIN_SRAM_TABLE_SIZE
#define EGRESS_BD_STATS_TABLE_SIZE             MIN_SRAM_TABLE_SIZE
#define REPLICA_TYPE_TABLE_SIZE                MIN_TCAM_TABLE_SIZE
#define RID_TABLE_SIZE                         MIN_SRAM_TABLE_SIZE
#define TUNNEL_DECAP_TABLE_SIZE                MIN_SRAM_TABLE_SIZE
#define L3_MTU_TABLE_SIZE                      MIN_SRAM_TABLE_SIZE
#define EGRESS_VLAN_XLATE_TABLE_SIZE           MIN_SRAM_TABLE_SIZE
#define SPANNING_TREE_TABLE_SIZE               MIN_SRAM_TABLE_SIZE
#define FABRIC_REWRITE_TABLE_SIZE              MIN_TCAM_TABLE_SIZE
#define EGRESS_ACL_TABLE_SIZE                  MIN_TCAM_TABLE_SIZE
#define INGRESS_ACL_RANGE_TABLE_SIZE           MIN_TCAM_TABLE_SIZE
#define EGRESS_ACL_RANGE_TABLE_SIZE            MIN_TCAM_TABLE_SIZE
#define VLAN_DECAP_TABLE_SIZE                  MIN_SRAM_TABLE_SIZE
#define TUNNEL_HEADER_TABLE_SIZE               MIN_SRAM_TABLE_SIZE
#define TUNNEL_REWRITE_TABLE_SIZE              MIN_SRAM_TABLE_SIZE
#define TUNNEL_SMAC_REWRITE_TABLE_SIZE         MIN_SRAM_TABLE_SIZE
#define TUNNEL_DMAC_REWRITE_TABLE_SIZE         MIN_SRAM_TABLE_SIZE
#define MIRROR_SESSIONS_TABLE_SIZE             MIN_SRAM_TABLE_SIZE
#define MIRROR_COALESCING_SESSIONS_TABLE_SIZE  MIN_SRAM_TABLE_SIZE
#define DROP_STATS_TABLE_SIZE                  MIN_SRAM_TABLE_SIZE
#define ACL_STATS_TABLE_SIZE                   MIN_SRAM_TABLE_SIZE
#define RACL_STATS_TABLE_SIZE                  MIN_SRAM_TABLE_SIZE
#define EGRESS_ACL_STATS_TABLE_SIZE            MIN_SRAM_TABLE_SIZE
#define METER_INDEX_TABLE_SIZE                 MIN_SRAM_TABLE_SIZE
#define METER_ACTION_TABLE_SIZE                MIN_SRAM_TABLE_SIZE
#define MIRROR_ACL_STATS_TABLE_SIZE            MIN_SRAM_TABLE_SIZE

#define TELEMETRY_HASH_WIDTH                   16
#define TELEMETRY_MAX_MIRROR_SESSION_PER_GROUP 120
#define TELEMETRY_BLOOM_FILTER_SIZE            65536
#define TELEMETRY_WATCHLIST_TABLE_SIZE         256
#define TELEMETRY_CONFIG_SESSIONS              256
// TELEMETRY_CONFIG_SESSIONS + 3
#define TELEMETRY_CONFIG_SESSIONS_AND_L4       259
#define TELEMETRY_QUEUE_TABLE_SIZE             1024
#define MIRROR_ON_DROP_ENCAP_TABLE_SIZE        16

#define SFLOW_INGRESS_TABLE_SIZE               512
#define SFLOW_EGRESS_TABLE_SIZE                512
#define MAX_SFLOW_SESSIONS                     16

#define INGRESS_QOS_MAP_TABLE_SIZE             512
#define EGRESS_QOS_MAP_TABLE_SIZE              512
#define QUEUE_TABLE_SIZE                       512
#define DSCP_TO_TC_AND_COLOR_TABLE_SIZE        64
#define PCP_TO_TC_AND_COLOR_TABLE_SIZE         64

// very small # of session on model since model pktgen is about 16 pkts per sec
#define MAX_BFD_SESSIONS                       16   // 256
#define MAX_BFD_SESSIONS_PER_PIPE              4    // 64
#define MAX_BFD_SESSIONS_PER_PIPE_2X           8    // 128
#define BFD_TX_TIMER_TABLE_SIZE                18   // max + 2 = 258

#define FLOWLET_MAP_SIZE                       8192
#define FLOWLET_MAP_WIDTH                      13

#define LAG_FAILOVER_TABLE_SIZE                MIN_SRAM_TABLE_SIZE
#define ECMP_FAILOVER_TABLE_SIZE               MIN_SRAM_TABLE_SIZE
#define LAG_FAILOVER_REG_INSTANCE_COUNT        131072
#define ECMP_FAILOVER_REG_INSTANCE_COUNT       131072

#define WRED_INDEX_TABLE_SIZE                  8192
#define WRED_ACTION_TABLE_SIZE                 1536
#define WRED_TABLE_SIZE                        256

#define COPP_METER_TABLE_SIZE                  64
#define COPP_TABLE_SIZE                        128

#define EGRESS_PORT_LKP_FIELD_SIZE             4

#define ADJUST_PACKET_LENGTH_TABLE_SIZE        4

#define SRV6_LOCAL_SID_TABLE_SIZE              MIN_SRAM_TABLE_SIZE

/******************************************************************************
 *  A typical profile for DC
 *****************************************************************************/
#elif defined(ENT_DC_GENERAL_TABLE_SIZES)

   // Misc
#define VALIDATE_PACKET_TABLE_SIZE             64
#define VALIDATE_MPLS_TABLE_SIZE               512
#define FWD_RESULT_TABLE_SIZE                  512
#define SYSTEM_ACL_SIZE                        512
#define LEARN_NOTIFY_TABLE_SIZE                512
#define EGRESS_PORT_LKP_FIELD_SIZE             4
#define ADJUST_PACKET_LENGTH_TABLE_SIZE        4
   //#define SRV6_LOCAL_SID_TABLE_SIZE              1024
#define DROP_STATS_TABLE_SIZE                  256
#define UPDATE_L4_CHECKSUM_TABLE_SIZE          512
#define MAC_REWRITE_TABLE_SIZE                 512
#define L3_MTU_TABLE_SIZE                      512
#define FABRIC_REWRITE_TABLE_SIZE              512
#define VLAN_DECAP_TABLE_SIZE                  256

      // Number of ports = 288
#define PORTMAP_TABLE_SIZE                     288

// 4K L2 vlans + 4K VXLAN
// 8K BDs
// 8K {port,vlan} <-> BD mappings
#define PORT_VLAN_TABLE_SIZE                   8192 // 32k in maxsizes
#define BD_TABLE_SIZE                          8192 // 16k in maxsizes
#define BD_FLOOD_TABLE_SIZE                   24576 // 48k in maxsizes
#define BD_STATS_TABLE_SIZE                    8192 // 16k in maxsizes
#define EGRESS_VLAN_XLATE_TABLE_SIZE           8192
#define EGRESS_VNID_MAPPING_TABLE_SIZE         8192
#define EGRESS_BD_MAPPING_TABLE_SIZE           8192
#define EGRESS_BD_STATS_TABLE_SIZE             8192
#define SPANNING_TREE_TABLE_SIZE               4096
#define VNID_MAPPING_TABLE_SIZE                4096
#define CPU_BD_TABLE_SIZE                      4096
#define EGRESS_OUTER_BD_MAPPING_TABLE_SIZE     4096
#define EGRESS_OUTER_BD_STATS_TABLE_SIZE       4096

   // 32K MACs
#define MAC_TABLE_SIZE                         32768 // 65536

   // Router MACs
#define OUTER_ROUTER_MAC_TABLE_SIZE            512
#define ROUTER_MAC_TABLE_SIZE                  512

   // Tunnels - 4K IPv4 + 1K IPv6
#define DEST_TUNNEL_TABLE_SIZE                 512
#define IPV4_SRC_TUNNEL_TABLE_SIZE             4096 // 16K
#define IPV6_SRC_TUNNEL_TABLE_SIZE             1024 // 4K
#define TUNNEL_SRC_REWRITE_TABLE_SIZE          512
#define TUNNEL_DST_REWRITE_TABLE_SIZE          4096 // 16384
#define TUNNEL_TO_MGID_MAPPING_TABLE_SIZE      1024 // 4096
#define OUTER_MULTICAST_STAR_G_TABLE_SIZE      512
#define OUTER_MULTICAST_S_G_TABLE_SIZE         1024
#define OUTER_MCAST_RPF_TABLE_SIZE             512
#define MPLS_TABLE_SIZE                        512 // Not a real table
#define TUNNEL_DECAP_TABLE_SIZE                512
#define TUNNEL_HEADER_TABLE_SIZE               256
#define TUNNEL_REWRITE_TABLE_SIZE              4096 // 16384
#define TUNNEL_SMAC_REWRITE_TABLE_SIZE         512
#define TUNNEL_DMAC_REWRITE_TABLE_SIZE         4096 // 16384

   // Security (not enabled)
#define IPSG_TABLE_SIZE                        8192
#define IPSG_PERMIT_SPECIAL_TABLE_SIZE         512
#define URPF_GROUP_TABLE_SIZE                  32768

   // Storm Control
#define STORM_CONTROL_TABLE_SIZE               512
#define STORM_CONTROL_METER_TABLE_SIZE         512
#define STORM_CONTROL_STATS_TABLE_SIZE         1024

   // Ingress ACLs
#define INGRESS_MAC_ACL_TABLE_SIZE             512
#define INGRESS_IP_ACL_TABLE_SIZE              1024 //1024
#define INGRESS_IPV6_ACL_TABLE_SIZE             512 // 512
#define INGRESS_IP_RACL_TABLE_SIZE             1024 //1024
#define INGRESS_IPV6_RACL_TABLE_SIZE           512  // 512
#define INGRESS_ACL_RANGE_TABLE_SIZE           256
#define ACL_STATS_TABLE_SIZE                   2048
#define RACL_STATS_TABLE_SIZE                  2048

   // Egress ACLs
#define EGRESS_MAC_ACL_TABLE_SIZE              512
#define EGRESS_IP_ACL_TABLE_SIZE               512
#define EGRESS_IPV6_ACL_TABLE_SIZE             512
#define EGRESS_ACL_TABLE_SIZE                  256
#define EGRESS_ACL_RANGE_TABLE_SIZE            256
#define EGRESS_ACL_STATS_TABLE_SIZE            1536

   // NAT ( not enabled )
#define IP_NAT_TABLE_SIZE                      512
#define IP_NAT_FLOW_TABLE_SIZE                 512
#define EGRESS_NAT_TABLE_SIZE                  512


    // IP Hosts/Routes
#define IPV4_HOST_TABLE_SIZE                   32768
#define IPV4_LPM_TABLE_SIZE                    16384

#define IPV6_HOST_TABLE_SIZE                   16384
#define IPV6_LPM_TABLE_SIZE                    16384

    // Multicast
#define IPV4_MULTICAST_STAR_G_TABLE_SIZE       2048 // 2048
#define IPV4_MULTICAST_S_G_TABLE_SIZE          4096 // 4096
#define IPV6_MULTICAST_STAR_G_TABLE_SIZE       512  // 512
#define IPV6_MULTICAST_S_G_TABLE_SIZE          512  // 512
#define MCAST_RPF_TABLE_SIZE                   8192 // 32768

#define REPLICA_TYPE_TABLE_SIZE                16
#define RID_TABLE_SIZE                         32768

   // ECMP/Nexthop
#define ECMP_GROUP_TABLE_SIZE                  1024
#define ECMP_SELECT_TABLE_SIZE                 16384
#define WCMP_GROUP_TABLE_SIZE                  6144
#define NEXTHOP_TABLE_SIZE                     32768

    // LAG
#define LAG_GROUP_TABLE_SIZE                   1024
#define LAG_SELECT_TABLE_SIZE                  1024

    // Mirror
#define MIRROR_SESSIONS_TABLE_SIZE             1024
#define MIRROR_COALESCING_SESSIONS_TABLE_SIZE  8

    // TELEMETRY (not enabled )
#define TELEMETRY_HASH_WIDTH                   16
#define TELEMETRY_MAX_MIRROR_SESSION_PER_GROUP 120
#define TELEMETRY_BLOOM_FILTER_SIZE            65536
#define TELEMETRY_WATCHLIST_TABLE_SIZE         1024
#define TELEMETRY_CONFIG_SESSIONS              256
// TELEMETRY_CONFIG_SESSIONS + 3
#define TELEMETRY_CONFIG_SESSIONS_AND_L4       259
#define TELEMETRY_QUEUE_TABLE_SIZE             1024
#define MIRROR_ON_DROP_ENCAP_TABLE_SIZE        16

   // QoS
#define INGRESS_QOS_MAP_TABLE_SIZE             512
#define EGRESS_QOS_MAP_TABLE_SIZE              512
#define QUEUE_TABLE_SIZE                       512
#define DSCP_TO_TC_AND_COLOR_TABLE_SIZE        64
#define PCP_TO_TC_AND_COLOR_TABLE_SIZE         512

    // sFlow
#define SFLOW_INGRESS_TABLE_SIZE               512
#define SFLOW_EGRESS_TABLE_SIZE                512
#define MAX_SFLOW_SESSIONS                     16

    // Copp/Metering
#define COPP_METER_TABLE_SIZE                  64
#define COPP_TABLE_SIZE                        128
#define METER_INDEX_TABLE_SIZE                 256
#define METER_ACTION_TABLE_SIZE                512

// BFD
#define MAX_BFD_SESSIONS                       256
#define MAX_BFD_SESSIONS_PER_PIPE              64
#define MAX_BFD_SESSIONS_PER_PIPE_2X           128
#define BFD_TX_TIMER_TABLE_SIZE                258 // max + 2

	    // Flowlet
#define FLOWLET_MAP_SIZE                       8192
#define FLOWLET_MAP_WIDTH                      13

	    // Fast Failover
//#define LAG_FAILOVER_TABLE_SIZE                512
//#define ECMP_FAILOVER_TABLE_SIZE               65536
//#define LAG_FAILOVER_REG_INSTANCE_COUNT        131072
//#define ECMP_FAILOVER_REG_INSTANCE_COUNT       131072

	    // WRED ( not enabled )
#define WRED_INDEX_TABLE_SIZE                  128
#define WRED_ACTION_TABLE_SIZE                 512
#define WRED_TABLE_SIZE                        16

#if defined(TELEMETRY_FIN_TABLE_SIZES)

#undef PORT_VLAN_TABLE_SIZE
#undef IPV4_LPM_TABLE_SIZE
#undef IPV4_HOST_TABLE_SIZE
#undef IPV4_MULTICAST_STAR_G_TABLE_SIZE
#undef IPV4_MULTICAST_S_G_TABLE_SIZE
#undef MCAST_RPF_TABLE_SIZE
#undef MAC_TABLE_SIZE
#undef INGRESS_MAC_ACL_TABLE_SIZE
#undef INGRESS_IP_ACL_TABLE_SIZE
#undef EGRESS_MAC_ACL_TABLE_SIZE
#undef EGRESS_IP_ACL_TABLE_SIZE
#undef NEXTHOP_TABLE_SIZE
#undef SPANNING_TREE_TABLE_SIZE

#define PORT_VLAN_TABLE_SIZE                   4096

#define IPV4_HOST_TABLE_SIZE                   32768
#define MAC_TABLE_SIZE                         32768
#define IPV4_LPM_TABLE_SIZE                    24576

#define IPV4_MULTICAST_STAR_G_TABLE_SIZE       4096
#define IPV4_MULTICAST_S_G_TABLE_SIZE          4096
#define MCAST_RPF_TABLE_SIZE                   16384

#define INGRESS_MAC_ACL_TABLE_SIZE             512
#define INGRESS_IP_ACL_TABLE_SIZE              2048
#define EGRESS_MAC_ACL_TABLE_SIZE              1024
#define EGRESS_IP_ACL_TABLE_SIZE               1024
#define INGRESS_IP_RACL_TABLE_SIZE             1024

#define NEXTHOP_TABLE_SIZE                     32768
#define INGRESS_MIRROR_ACL_TABLE_SIZE          512
#define SPANNING_TREE_TABLE_SIZE               2048

#if defined(ENT_FIN_LEAF_PROFILE)
#undef IPV4_LPM_TABLE_SIZE
#define IPV4_LPM_TABLE_SIZE                    16384
#endif

#endif /*defined(TELEMETRY_FIN)*/

#else
/******************************************************************************
 *  Default MAX Profile
 *****************************************************************************/
#define VALIDATE_PACKET_TABLE_SIZE             64
#define PORTMAP_TABLE_SIZE                     288
#define STORM_CONTROL_TABLE_SIZE               512
#define STORM_CONTROL_METER_TABLE_SIZE         512
#define STORM_CONTROL_STATS_TABLE_SIZE         1024
#define PORT_VLAN_TABLE_SIZE                   16384
#define OUTER_ROUTER_MAC_TABLE_SIZE            512
#define DEST_TUNNEL_TABLE_SIZE                 512
#define IPV4_SRC_TUNNEL_TABLE_SIZE             16384
#define IPV6_SRC_TUNNEL_TABLE_SIZE             4096
#define TUNNEL_SRC_REWRITE_TABLE_SIZE          512
#define TUNNEL_DST_REWRITE_TABLE_SIZE          16384
#define TUNNEL_TO_MGID_MAPPING_TABLE_SIZE      4096
#define OUTER_MULTICAST_STAR_G_TABLE_SIZE      512
#define OUTER_MULTICAST_S_G_TABLE_SIZE         1024
#define VNID_MAPPING_TABLE_SIZE                16384
#define BD_TABLE_SIZE                          16384
#define CPU_BD_TABLE_SIZE                      8192
#define BD_FLOOD_TABLE_SIZE                    49152
#define BD_STATS_TABLE_SIZE                    16384
#define OUTER_MCAST_RPF_TABLE_SIZE             512
#define MPLS_TABLE_SIZE                        4096
#define VALIDATE_MPLS_TABLE_SIZE               512

#define ROUTER_MAC_TABLE_SIZE                  512
#define MAC_TABLE_SIZE                         65536
#define IPSG_TABLE_SIZE                        8192
#define IPSG_PERMIT_SPECIAL_TABLE_SIZE         512
#define INGRESS_MAC_ACL_TABLE_SIZE             512
#define INGRESS_IP_ACL_TABLE_SIZE              1024
#define INGRESS_IPV6_ACL_TABLE_SIZE            512
#define EGRESS_MAC_ACL_TABLE_SIZE              512
#define EGRESS_IP_ACL_TABLE_SIZE               512
#define EGRESS_IPV6_ACL_TABLE_SIZE             512
#define INGRESS_IP_RACL_TABLE_SIZE             1024
#define INGRESS_IPV6_RACL_TABLE_SIZE           512
#define IP_NAT_TABLE_SIZE                      4096
#define IP_NAT_FLOW_TABLE_SIZE                 512
#define EGRESS_NAT_TABLE_SIZE                  16384
#define UPDATE_L4_CHECKSUM_TABLE_SIZE          512

#define IPV4_LPM_TABLE_SIZE                    32768
#define IPV6_LPM_TABLE_SIZE                    16384
#define IPV4_HOST_TABLE_SIZE                   65536
#define IPV6_HOST_TABLE_SIZE                   16384

#define IPV4_MULTICAST_STAR_G_TABLE_SIZE       2048
#define IPV4_MULTICAST_S_G_TABLE_SIZE          4096
#define IPV6_MULTICAST_STAR_G_TABLE_SIZE       512
#define IPV6_MULTICAST_S_G_TABLE_SIZE          512
#define MCAST_RPF_TABLE_SIZE                   32768

#define FWD_RESULT_TABLE_SIZE                  512
#define URPF_GROUP_TABLE_SIZE                  32768
#define ECMP_GROUP_TABLE_SIZE                  1024
#define ECMP_SELECT_TABLE_SIZE                 16384
#define WCMP_GROUP_TABLE_SIZE                  6144
#define NEXTHOP_TABLE_SIZE                     49152
#define LAG_GROUP_TABLE_SIZE                   1024
#define LAG_SELECT_TABLE_SIZE                  1024
#define SYSTEM_ACL_SIZE                        512
#define LEARN_NOTIFY_TABLE_SIZE                512

#define MAC_REWRITE_TABLE_SIZE                 512
#define EGRESS_VNID_MAPPING_TABLE_SIZE         16384
#define EGRESS_BD_MAPPING_TABLE_SIZE           16384
#define EGRESS_BD_STATS_TABLE_SIZE             16384
#define REPLICA_TYPE_TABLE_SIZE                16
#define RID_TABLE_SIZE                         30720  // FIXME: 32768
#define TUNNEL_DECAP_TABLE_SIZE                512
#define L3_MTU_TABLE_SIZE                      512
#define EGRESS_VLAN_XLATE_TABLE_SIZE           16384
#define SPANNING_TREE_TABLE_SIZE               4096
#define FABRIC_REWRITE_TABLE_SIZE              512
#define EGRESS_ACL_TABLE_SIZE                  1024
#define INGRESS_ACL_RANGE_TABLE_SIZE           256
#define EGRESS_ACL_RANGE_TABLE_SIZE            256
#define VLAN_DECAP_TABLE_SIZE                  256
#define TUNNEL_HEADER_TABLE_SIZE               256
#define TUNNEL_REWRITE_TABLE_SIZE              16384
#define TUNNEL_SMAC_REWRITE_TABLE_SIZE         512
#define TUNNEL_DMAC_REWRITE_TABLE_SIZE         16384

#define MIRROR_SESSIONS_TABLE_SIZE             1024
#define MIRROR_COALESCING_SESSIONS_TABLE_SIZE  8

#define DROP_STATS_TABLE_SIZE                  256
#define ACL_STATS_TABLE_SIZE                   8192
#define RACL_STATS_TABLE_SIZE                  2048
#define EGRESS_ACL_STATS_TABLE_SIZE            2048
#define METER_INDEX_TABLE_SIZE                 2048
#define METER_ACTION_TABLE_SIZE                8192

#define TELEMETRY_HASH_WIDTH                   16
#define TELEMETRY_MAX_MIRROR_SESSION_PER_GROUP 120
#define TELEMETRY_BLOOM_FILTER_SIZE            65536
#define TELEMETRY_WATCHLIST_TABLE_SIZE         1024
#define TELEMETRY_CONFIG_SESSIONS              256
// TELEMETRY_CONFIG_SESSIONS + 3
#define TELEMETRY_CONFIG_SESSIONS_AND_L4       259
#define TELEMETRY_QUEUE_TABLE_SIZE             1024
#define MIRROR_ON_DROP_ENCAP_TABLE_SIZE        16

#define INGRESS_QOS_MAP_TABLE_SIZE             512
#define EGRESS_QOS_MAP_TABLE_SIZE              512
#define QUEUE_TABLE_SIZE                       512
#define DSCP_TO_TC_AND_COLOR_TABLE_SIZE        64
#define PCP_TO_TC_AND_COLOR_TABLE_SIZE         64

#define SFLOW_INGRESS_TABLE_SIZE               512
#define SFLOW_EGRESS_TABLE_SIZE                512
#define MAX_SFLOW_SESSIONS                     16

#define MAX_BFD_SESSIONS                       512
#define MAX_BFD_SESSIONS_PER_PIPE              128
#define MAX_BFD_SESSIONS_PER_PIPE_2X           256
#define BFD_TX_TIMER_TABLE_SIZE                514 // max + 2

#define FLOWLET_MAP_SIZE                       8192
#define FLOWLET_MAP_WIDTH                      13

#define LAG_FAILOVER_TABLE_SIZE                512
#define ECMP_FAILOVER_TABLE_SIZE               65536
#define LAG_FAILOVER_REG_INSTANCE_COUNT        131072
#define ECMP_FAILOVER_REG_INSTANCE_COUNT       131072

#define WRED_INDEX_TABLE_SIZE                  8192
#define WRED_ACTION_TABLE_SIZE                 1536
#define WRED_TABLE_SIZE                        256

#define COPP_METER_TABLE_SIZE                  64
#define COPP_TABLE_SIZE                        128

#define EGRESS_PORT_LKP_FIELD_SIZE             4

#define ADJUST_PACKET_LENGTH_TABLE_SIZE        4

#define SRV6_LOCAL_SID_TABLE_SIZE              1024

#endif /* !MIN_TABLE_SIZES */

#if defined(L2_PROFILE)
#undef MAC_TABLE_SIZE
#undef NEXTHOP_TABLE_SIZE

#define MAC_TABLE_SIZE                         460000
#define NEXTHOP_TABLE_SIZE                     16384
#endif /* L2_PROFILE */

#if defined(L3_IPV4_FIB_CLPM_PROFILE)
#undef IPV4_LPM_TABLE_SIZE
#undef NEXTHOP_TABLE_SIZE

#define IPV4_LPM_TABLE_SIZE                    1039360
#define IPV4_PREFIX_0_15_TABLE_SIZE            4096
#define IPV4_PREFIX_16_TABLE_SIZE              61440
#define IPV4_PREFIX_17_TABLE_SIZE              61440
#define IPV4_PREFIX_18_TABLE_SIZE              81920
#define IPV4_PREFIX_19_TABLE_SIZE              81920
#define IPV4_PREFIX_20_TABLE_SIZE              81920
#define IPV4_PREFIX_21_TABLE_SIZE              133120
#define IPV4_PREFIX_22_TABLE_SIZE              133120
#define IPV4_PREFIX_23_TABLE_SIZE              133120
#define IPV4_PREFIX_24_TABLE_SIZE              266240
#define IPV4_PREFIX_25_31_TABLE_SIZE           1024
#define NEXTHOP_TABLE_SIZE                     16384

#endif /* L3_IPV4_FIB_CLPM_PROFILE */

#if defined(ACL_IPV4_PROFILE)
#undef IPV4_HOST_TABLE_SIZE
#undef IPV4_LPM_TABLE_SIZE
#undef INGRESS_IP_ACL_TABLE_SIZE

#define IPV4_HOST_TABLE_SIZE                   165888
#define IPV4_LPM_TABLE_SIZE                    4096
#define INGRESS_IP_ACL_TABLE_SIZE              17408
#endif /* ACL_IPV4_PROFILE */

#ifdef ACL_DISABLE
#undef INGRESS_IP_RACL_TABLE_SIZE
#undef INGRESS_IPV6_RACL_TABLE_SIZE
#undef INGRESS_MAC_ACL_TABLE_SIZE
#undef INGRESS_IP_ACL_TABLE_SIZE
#undef INGRESS_IPV6_ACL_TABLE_SIZE
#undef EGRESS_MAC_ACL_TABLE_SIZE
#undef EGRESS_IP_ACL_TABLE_SIZE
#undef EGRESS_IPV6_ACL_TABLE_SIZE
#undef ACL_STATS_TABLE_SIZE
#undef RACL_STATS_TABLE_SIZE
#undef EGRESS_ACL_STATS_TABLE_SIZE
#undef EGRESS_ACL_TABLE_SIZE
#undef INGRESS_ACL_RANGE_TABLE_SIZE
#undef EGRESS_ACL_RANGE_TABLE_SIZE

#define INGRESS_IP_RACL_TABLE_SIZE             128
#define INGRESS_IPV6_RACL_TABLE_SIZE           128
#define INGRESS_MAC_ACL_TABLE_SIZE             128
#define INGRESS_IP_ACL_TABLE_SIZE              128
#define INGRESS_IPV6_ACL_TABLE_SIZE            128
#define EGRESS_MAC_ACL_TABLE_SIZE              128
#define EGRESS_IP_ACL_TABLE_SIZE               128
#define EGRESS_IPV6_ACL_TABLE_SIZE             128
#define ACL_STATS_TABLE_SIZE                   128
#define RACL_STATS_TABLE_SIZE                  128
#define EGRESS_ACL_TABLE_SIZE                  128
#define EGRESS_ACL_STATS_TABLE_SIZE            128
#define INGRESS_ACL_RANGE_TABLE_SIZE           128
#define EGRESS_ACL_RANGE_TABLE_SIZE            128
#endif /* ACL_DISABLE */

#if defined(MSDC_TABLE_SIZES)

#undef PORT_VLAN_TABLE_SIZE                 
#undef BD_TABLE_SIZE                        
#undef BD_FLOOD_TABLE_SIZE                  
#undef BD_STATS_TABLE_SIZE                  
#undef EGRESS_VLAN_XLATE_TABLE_SIZE         
#undef EGRESS_VNID_MAPPING_TABLE_SIZE       
#undef EGRESS_BD_MAPPING_TABLE_SIZE         
#undef EGRESS_BD_STATS_TABLE_SIZE           
#undef VNID_MAPPING_TABLE_SIZE              
#undef CPU_BD_TABLE_SIZE                    
#undef MAC_TABLE_SIZE                       
#undef IPV4_SRC_TUNNEL_TABLE_SIZE           
#undef IPV6_SRC_TUNNEL_TABLE_SIZE           
#undef TUNNEL_DST_REWRITE_TABLE_SIZE        
#undef TUNNEL_TO_MGID_MAPPING_TABLE_SIZE    
#undef TUNNEL_REWRITE_TABLE_SIZE            
#undef TUNNEL_DMAC_REWRITE_TABLE_SIZE       
#undef INGRESS_MAC_ACL_TABLE_SIZE           
#undef INGRESS_IP_ACL_TABLE_SIZE            
#undef INGRESS_IPV6_ACL_TABLE_SIZE          
#undef INGRESS_IP_RACL_TABLE_SIZE           
#undef INGRESS_IPV6_RACL_TABLE_SIZE         
#undef INGRESS_ACL_RANGE_TABLE_SIZE         
#undef ACL_STATS_TABLE_SIZE                 
#undef RACL_STATS_TABLE_SIZE                
#undef INGRESS_ECN_ACL_TABLE_SIZE           
#undef IPV4_LOCAL_HOST_TABLE_SIZE
#undef IPV4_HOST_TABLE_SIZE                 
#undef IPV4_LPM_TABLE_SIZE                  
#undef IPV6_HOST_TABLE_SIZE                 
#undef IPV6_LPM_TABLE_SIZE                  
#undef ECMP_GROUP_TABLE_SIZE                
#undef ECMP_SELECT_TABLE_SIZE               
#undef NEXTHOP_TABLE_SIZE                   
#undef WRED_INDEX_TABLE_SIZE                
#undef WRED_ACTION_TABLE_SIZE               
#undef WRED_TABLE_SIZE                                 

// 4K L2 vlans + 4K VXLANs
// 8K BDs
// 8K {port,vlan} <-> BD mappings
#define PORT_VLAN_TABLE_SIZE                   8192
#define BD_TABLE_SIZE                          8192
#define BD_FLOOD_TABLE_SIZE                    8192
#define BD_STATS_TABLE_SIZE                    8192
#define EGRESS_VLAN_XLATE_TABLE_SIZE           8192
#define EGRESS_VNID_MAPPING_TABLE_SIZE         8192
#define EGRESS_BD_MAPPING_TABLE_SIZE           8192
#define EGRESS_BD_STATS_TABLE_SIZE             8192
#define VNID_MAPPING_TABLE_SIZE                8192
#define CPU_BD_TABLE_SIZE                      8192

// 16K MACs
#define MAC_TABLE_SIZE                         16384

// Tunnels - 4K IPv4 + 1K IPv6
#define IPV4_SRC_TUNNEL_TABLE_SIZE             4096 // 16K
#define IPV6_SRC_TUNNEL_TABLE_SIZE             1024 // 4K
#define TUNNEL_DST_REWRITE_TABLE_SIZE          4096 // 16384
#define TUNNEL_TO_MGID_MAPPING_TABLE_SIZE      1024 // 4096
#define TUNNEL_REWRITE_TABLE_SIZE              4096 // 16384
#define TUNNEL_DMAC_REWRITE_TABLE_SIZE         4096 // 16384

// Ingress ACLs
#define INGRESS_MAC_ACL_TABLE_SIZE             512
#define INGRESS_IP_ACL_TABLE_SIZE              1024
#define INGRESS_IPV6_ACL_TABLE_SIZE            512
#define INGRESS_IP_RACL_TABLE_SIZE             1024
#define INGRESS_IPV6_RACL_TABLE_SIZE           512 
#define INGRESS_ACL_RANGE_TABLE_SIZE           256
#define ACL_STATS_TABLE_SIZE                   2048
#define RACL_STATS_TABLE_SIZE                  2048
#define MIRROR_ACL_STATS_TABLE_SIZE            1024
#define INGRESS_ECN_ACL_TABLE_SIZE              64
#define INGRESS_MIRROR_ACL_TABLE_SIZE          512

// IP Hosts/Routes
#define IPV4_LOCAL_HOST_TABLE_SIZE             8192
#define IPV4_HOST_TABLE_SIZE                   40960
#define IPV4_LPM_TABLE_SIZE                    24576
#define IPV6_HOST_TABLE_SIZE                   16384
#define IPV6_LPM_TABLE_SIZE                    16384

// ECMP/Nexthop
#define ECMP_GROUP_TABLE_SIZE                  1024
#define ECMP_SELECT_TABLE_SIZE                 16384
#define NEXTHOP_TABLE_SIZE                     32768

// WRED
#define WRED_INDEX_TABLE_SIZE                  4096
#define WRED_ACTION_TABLE_SIZE                 1536
#define WRED_TABLE_SIZE                        256

#endif /* MSDC_TABLE_SIZES */

#if defined(MSDC_IPV4_TABLE_SIZES)

#undef PORT_VLAN_TABLE_SIZE                 
#undef BD_TABLE_SIZE                        
#undef BD_FLOOD_TABLE_SIZE                  
#undef BD_STATS_TABLE_SIZE                  
#undef EGRESS_VLAN_XLATE_TABLE_SIZE         
#undef EGRESS_VNID_MAPPING_TABLE_SIZE       
#undef EGRESS_BD_MAPPING_TABLE_SIZE         
#undef EGRESS_BD_STATS_TABLE_SIZE           
#undef EGRESS_OUTER_BD_MAPPING_TABLE_SIZE
#undef EGRESS_OUTER_BD_STATS_TABLE_SIZE
#undef VNID_MAPPING_TABLE_SIZE              
#undef CPU_BD_TABLE_SIZE                    
#undef MAC_TABLE_SIZE                       
#undef IPV4_SRC_TUNNEL_TABLE_SIZE           
#undef TUNNEL_DST_REWRITE_TABLE_SIZE        
#undef TUNNEL_TO_MGID_MAPPING_TABLE_SIZE    
#undef TUNNEL_REWRITE_TABLE_SIZE            
#undef TUNNEL_DMAC_REWRITE_TABLE_SIZE       
#undef INGRESS_MAC_ACL_TABLE_SIZE           
#undef INGRESS_IP_ACL_TABLE_SIZE            
#undef INGRESS_IP_RACL_TABLE_SIZE           
#undef INGRESS_ACL_RANGE_TABLE_SIZE         
#undef ACL_STATS_TABLE_SIZE                 
#undef RACL_STATS_TABLE_SIZE                
#undef INGRESS_ECN_ACL_TABLE_SIZE           
#undef IPV4_HOST_TABLE_SIZE                 
#undef IPV4_LPM_TABLE_SIZE                  
#undef ECMP_GROUP_TABLE_SIZE                
#undef ECMP_SELECT_TABLE_SIZE               
#undef NEXTHOP_TABLE_SIZE                   
#undef WRED_INDEX_TABLE_SIZE                
#undef WRED_ACTION_TABLE_SIZE               
#undef WRED_TABLE_SIZE                                 


// 1K L2 vlans + 1K VXLANs
// 2K BDs
// 2K {port,vlan} <-> BD mappings
#define PORT_VLAN_TABLE_SIZE                   1024
#define BD_TABLE_SIZE                          1024
#define BD_FLOOD_TABLE_SIZE                    3072
#define BD_STATS_TABLE_SIZE                    4096
#define EGRESS_VLAN_XLATE_TABLE_SIZE           1024
#define EGRESS_VNID_MAPPING_TABLE_SIZE         1024
#define EGRESS_BD_MAPPING_TABLE_SIZE           2048
#define EGRESS_BD_STATS_TABLE_SIZE             4096
#define VNID_MAPPING_TABLE_SIZE                1024
#define CPU_BD_TABLE_SIZE                      2048
#define EGRESS_OUTER_BD_MAPPING_TABLE_SIZE     1024
#define EGRESS_OUTER_BD_STATS_TABLE_SIZE       4096

// 4K MACs
#define MAC_TABLE_SIZE                         4096

// Tunnels - 
#define NUM_TUNNELS                            16384
#define NUM_TUNNEL_NHOP_GROUPS                 1024
#define NUM_TUNNEL_NHOP                        4096
#define IPV4_SRC_TUNNEL_TABLE_SIZE             NUM_TUNNELS
#define TUNNEL_DST_REWRITE_TABLE_SIZE          NUM_TUNNELS
#define TUNNEL_TO_MGID_MAPPING_TABLE_SIZE      NUM_TUNNEL_NHOP_GROUPS
#define TUNNEL_REWRITE_TABLE_SIZE              NUM_TUNNELS
#define TUNNEL_DMAC_REWRITE_TABLE_SIZE         NUM_TUNNEL_NHOP

// Ingress ACLs
#define INGRESS_MAC_ACL_TABLE_SIZE             512
#define INGRESS_IP_ACL_TABLE_SIZE              1024
#define INGRESS_IPV6_ACL_TABLE_SIZE            512
#define INGRESS_IP_RACL_TABLE_SIZE             1024
#define INGRESS_IPV6_RACL_TABLE_SIZE           512 
#define INGRESS_ACL_RANGE_TABLE_SIZE           256
#define ACL_STATS_TABLE_SIZE                   2048
#define RACL_STATS_TABLE_SIZE                  2048
#define MIRROR_ACL_STATS_TABLE_SIZE            1024
#define INGRESS_ECN_ACL_TABLE_SIZE              64
#define INGRESS_MIRROR_ACL_TABLE_SIZE          512

// IP Hosts/Routes
#define NUM_HOSTS                              131072 //327680 //262144 //475136 // 464k //524288 //393216 //262144 //196608
#define IPV4_HOST_TABLE_SIZE                   NUM_HOSTS
#define IPV4_LPM_TABLE_SIZE                    4096
//#define IPV6_HOST_TABLE_SIZE                   16384
//#define IPV6_LPM_TABLE_SIZE                    16384

// ECMP/Nexthop
#define NUM_NEXTHOPS                           NUM_HOSTS
#define ECMP_GROUP_TABLE_SIZE                  1024
#define ECMP_SELECT_TABLE_SIZE                 16384
#define NEXTHOP_TABLE_SIZE                     NUM_NEXTHOPS

// WRED
#define WRED_INDEX_TABLE_SIZE                  4096
#define WRED_ACTION_TABLE_SIZE                 1536
#define WRED_TABLE_SIZE                        256

#endif /* MSDC_IPV4_TABLE_SIZES */

#if defined(MSDC_L3_TABLE_SIZES)

#undef PORT_VLAN_TABLE_SIZE
#undef BD_TABLE_SIZE
#undef BD_FLOOD_TABLE_SIZE
#undef BD_STATS_TABLE_SIZE
#undef EGRESS_VLAN_XLATE_TABLE_SIZE
#undef EGRESS_VNID_MAPPING_TABLE_SIZE
#undef EGRESS_BD_MAPPING_TABLE_SIZE
#undef EGRESS_BD_STATS_TABLE_SIZE
#undef VNID_MAPPING_TABLE_SIZE
#undef CPU_BD_TABLE_SIZE
#undef MAC_TABLE_SIZE
#undef IPV4_SRC_TUNNEL_TABLE_SIZE
#undef IPV6_SRC_TUNNEL_TABLE_SIZE
#undef TUNNEL_DST_REWRITE_TABLE_SIZE
#undef TUNNEL_TO_MGID_MAPPING_TABLE_SIZE
#undef TUNNEL_REWRITE_TABLE_SIZE
#undef TUNNEL_DMAC_REWRITE_TABLE_SIZE
#undef INGRESS_MAC_ACL_TABLE_SIZE
#undef INGRESS_IP_ACL_TABLE_SIZE
#undef INGRESS_IPV6_ACL_TABLE_SIZE
#undef INGRESS_IP_RACL_TABLE_SIZE
#undef INGRESS_IPV6_RACL_TABLE_SIZE
#undef INGRESS_ACL_RANGE_TABLE_SIZE
#undef ACL_STATS_TABLE_SIZE
#undef RACL_STATS_TABLE_SIZE
#undef INGRESS_ECN_ACL_TABLE_SIZE
#undef IPV4_HOST_TABLE_SIZE
#undef IPV4_LPM_TABLE_SIZE
#undef IPV6_HOST_TABLE_SIZE
#undef IPV6_LPM_TABLE_SIZE
#undef ECMP_GROUP_TABLE_SIZE
#undef ECMP_SELECT_TABLE_SIZE
#undef NEXTHOP_TABLE_SIZE
#undef WRED_INDEX_TABLE_SIZE
#undef WRED_ACTION_TABLE_SIZE
#undef WRED_TABLE_SIZE

// 4K L3 interfaces
#define PORT_VLAN_TABLE_SIZE                   4096
#define BD_TABLE_SIZE                          4096
#define BD_FLOOD_TABLE_SIZE                    4096
#define BD_STATS_TABLE_SIZE                    4096
#define EGRESS_VLAN_XLATE_TABLE_SIZE           4096
#define EGRESS_VNID_MAPPING_TABLE_SIZE         4096
#define EGRESS_BD_MAPPING_TABLE_SIZE           4096
#define EGRESS_BD_STATS_TABLE_SIZE             4096
#define VNID_MAPPING_TABLE_SIZE                4096
#define CPU_BD_TABLE_SIZE                      4096

// 1K MACs
#define MAC_TABLE_SIZE                        1024

// Tunnels - 4K IPv4 + 1K IPv6
#define IPV4_SRC_TUNNEL_TABLE_SIZE             4096 // 16K
#define IPV6_SRC_TUNNEL_TABLE_SIZE             1024 // 4K
#define TUNNEL_DST_REWRITE_TABLE_SIZE          4096 // 16384
#define TUNNEL_TO_MGID_MAPPING_TABLE_SIZE      1024 // 4096
#define TUNNEL_REWRITE_TABLE_SIZE              4096 // 16384
#define TUNNEL_DMAC_REWRITE_TABLE_SIZE         4096 // 16384

// Ingress ACLs
#define INGRESS_MAC_ACL_TABLE_SIZE             512
#define INGRESS_IP_ACL_TABLE_SIZE              2048
#define INGRESS_IPV6_ACL_TABLE_SIZE            512
#define INGRESS_IP_RACL_TABLE_SIZE             2048
#define INGRESS_IPV6_RACL_TABLE_SIZE           512
#define INGRESS_ACL_RANGE_TABLE_SIZE           256
#define ACL_STATS_TABLE_SIZE                   2048
#define RACL_STATS_TABLE_SIZE                  2048
#define MIRROR_ACL_STATS_TABLE_SIZE            1024
#define INGRESS_ECN_ACL_TABLE_SIZE              64
#define INGRESS_MIRROR_ACL_TABLE_SIZE          512

// IP Hosts/Routes
#define IPV4_HOST_TABLE_SIZE                   32768
#define IPV4_LPM_TABLE_SIZE                    65536
#define IPV6_HOST_TABLE_SIZE                   32768
#define IPV6_LPM_TABLE_SIZE                    16384

// ECMP/Nexthop
#define ECMP_GROUP_TABLE_SIZE                   4096
#define ECMP_SELECT_TABLE_SIZE                 32768
#define NEXTHOP_TABLE_SIZE                     32768

// WRED
#define WRED_INDEX_TABLE_SIZE                  4096
#define WRED_ACTION_TABLE_SIZE                 1536
#define WRED_TABLE_SIZE                        256

#endif /* MSDC_L3_TABLE_SIZES */

/* Keep MSDC TELEMETRY configs after MSDC_TABLE_SIZES */
/******************************************************************************
 *  A telemetry profile for MSDC
 *****************************************************************************/
#if defined(MSDC_LEAF_TELEMETRY_INT_PROFILE) ||\
    defined(MSDC_SPINE_TELEMETRY_INT_PROFILE) ||\
    defined(MSDC_TELEMETRY_POSTCARD_PROFILE) || \
    defined(TEST_ENT_DC_POSTCARD_PROFILE)

#undef IPV4_HOST_TABLE_SIZE
#undef IPV4_LPM_TABLE_SIZE
#undef IPV6_HOST_TABLE_SIZE
#undef IPV6_LPM_TABLE_SIZE

    // TELEMETRY
#define TELEMETRY_HASH_WIDTH                   16
#define TELEMETRY_MAX_MIRROR_SESSION_PER_GROUP 120
#define TELEMETRY_BLOOM_FILTER_SIZE            65536
#define TELEMETRY_WATCHLIST_TABLE_SIZE         1024
#define TELEMETRY_QUEUE_TABLE_SIZE             1024
#define MIRROR_ON_DROP_ENCAP_TABLE_SIZE        16
#define TELEMETRY_CONFIG_SESSIONS              256
// TELEMETRY_CONFIG_SESSIONS entries for UDP and 3 more for TCP/ICMP and default
#define TELEMETRY_CONFIG_SESSIONS_AND_L4       259

#if defined(MSDC_LEAF_TELEMETRY_INT_PROFILE)
#define IPV4_HOST_TABLE_SIZE                   16384
#define IPV4_LPM_TABLE_SIZE                    24576
#define IPV6_HOST_TABLE_SIZE                   6144
#define IPV6_LPM_TABLE_SIZE                    6144
#endif // MSDC_LEAF_TELEMETRY_INT_PROFILE

#if defined(MSDC_SPINE_TELEMETRY_INT_PROFILE)
#define IPV4_HOST_TABLE_SIZE                   8192
#define IPV4_LPM_TABLE_SIZE                    32768
#define IPV6_HOST_TABLE_SIZE                   4096
#define IPV6_LPM_TABLE_SIZE                    8192
#endif // MSDC_SPINE_TELEMETRY_INT_PROFILE

#if defined(MSDC_TELEMETRY_POSTCARD_PROFILE)
#define IPV4_HOST_TABLE_SIZE                   16384
#define IPV4_LPM_TABLE_SIZE                    32768
#define IPV6_HOST_TABLE_SIZE                   6144
#define IPV6_LPM_TABLE_SIZE                    8192
#endif // MSDC_TELEMETRY_POSTCARD_PROFILE

#if defined(TEST_ENT_DC_POSTCARD_PROFILE)
#undef NEXTHOP_TABLE_SIZE
#define IPV4_HOST_TABLE_SIZE                   50176
#define IPV4_LPM_TABLE_SIZE                    50176
#define IPV6_HOST_TABLE_SIZE                   6144
#define IPV6_LPM_TABLE_SIZE                    8192

#define NEXTHOP_TABLE_SIZE                     50176
#endif // TEST_ENT_DC_POSTCARD_PROFILE

#endif // MSDC TELEMETRY PROFILES

#if defined(ENT_DC_AGGR_TABLE_SIZES)

#undef PORT_VLAN_TABLE_SIZE                 
#undef BD_TABLE_SIZE                        
#undef BD_FLOOD_TABLE_SIZE                  
#undef BD_STATS_TABLE_SIZE                  
#undef EGRESS_VLAN_XLATE_TABLE_SIZE         
#undef EGRESS_VNID_MAPPING_TABLE_SIZE       
#undef EGRESS_BD_MAPPING_TABLE_SIZE         
#undef EGRESS_BD_STATS_TABLE_SIZE           
#undef VNID_MAPPING_TABLE_SIZE              
#undef CPU_BD_TABLE_SIZE                    
#undef MAC_TABLE_SIZE                       
#undef INGRESS_MAC_ACL_TABLE_SIZE           
#undef INGRESS_IP_ACL_TABLE_SIZE            
#undef INGRESS_IPV6_ACL_TABLE_SIZE          
#undef INGRESS_IP_RACL_TABLE_SIZE           
#undef INGRESS_IPV6_RACL_TABLE_SIZE         
#undef INGRESS_ACL_RANGE_TABLE_SIZE         
#undef ACL_STATS_TABLE_SIZE                 
#undef RACL_STATS_TABLE_SIZE                
#undef INGRESS_ECN_ACL_TABLE_SIZE           
#undef IPV4_HOST_TABLE_SIZE                 
#undef IPV4_LPM_TABLE_SIZE                  
#undef IPV6_HOST_TABLE_SIZE                 
#undef IPV6_LPM_TABLE_SIZE                  
#undef ECMP_GROUP_TABLE_SIZE                
#undef ECMP_SELECT_TABLE_SIZE               
#undef NEXTHOP_TABLE_SIZE                   
#undef RID_TABLE_SIZE

// 4K L2 vlans + 4K VXLANs
// 8K BDs
// 8K {port,vlan} <-> BD mappings
#define PORT_VLAN_TABLE_SIZE                   4096
#define BD_TABLE_SIZE                          4096
#define BD_FLOOD_TABLE_SIZE                    4096 //12288
#define BD_STATS_TABLE_SIZE                    4096
#define EGRESS_VLAN_XLATE_TABLE_SIZE           4096
#define EGRESS_VNID_MAPPING_TABLE_SIZE         4096
#define EGRESS_BD_MAPPING_TABLE_SIZE           4096
#define EGRESS_BD_STATS_TABLE_SIZE             4096
#define VNID_MAPPING_TABLE_SIZE                4096
#define CPU_BD_TABLE_SIZE                      4096

// 16K MACs
#define MAC_TABLE_SIZE                         65536

// ACLs
#define INGRESS_MAC_ACL_TABLE_SIZE             512
#define INGRESS_IP_ACL_TABLE_SIZE              2048
#define INGRESS_IPV6_ACL_TABLE_SIZE            512
#define INGRESS_IP_RACL_TABLE_SIZE             2048
#define INGRESS_IPV6_RACL_TABLE_SIZE           512
#define INGRESS_ACL_RANGE_TABLE_SIZE           256
#define ACL_STATS_TABLE_SIZE                   4096
#define RACL_STATS_TABLE_SIZE                  4096
#define EGRESS_IP_ACL_TABLE_SIZE               512
#define EGRESS_IPV6_ACL_TABLE_SIZE             512
//#define MIRROR_ACL_STATS_TABLE_SIZE            1024
//#define INGRESS_ECN_ACL_TABLE_SIZE              64
//#define INGRESS_MIRROR_ACL_TABLE_SIZE          512
#define INGRESS_MAC_QOS_ACL_TABLE_SIZE         512
#define INGRESS_IPV4_QOS_ACL_TABLE_SIZE        512
#define INGRESS_IPV6_QOS_ACL_TABLE_SIZE        512
#define INGRESS_MIRROR_ACL_TABLE_SIZE          512
#define INGRESS_FCOE_ACL_TABLE_SIZE            512

// IP Hosts/Routes
#define IPV4_HOST_TABLE_SIZE                   65536
#define IPV4_LPM_TABLE_SIZE                     4096
#define IPV6_HOST_TABLE_SIZE                   16384
#define IPV6_LPM_TABLE_SIZE                     4096

// ECMP/Nexthop
#define ECMP_GROUP_TABLE_SIZE                  1024
#define ECMP_SELECT_TABLE_SIZE                 16384
#define NEXTHOP_TABLE_SIZE                     65536

// Multicast
#define RID_TABLE_SIZE                         32768

#endif /* ENT_DC_AGGR_TABLE_SIZES */

// override disable
#ifdef IPV4_LOCAL_HOST_TABLE_SIZE
#define URPF_DISABLE
#endif

#endif /* _P4_TABLE_SIZES_H_ */
