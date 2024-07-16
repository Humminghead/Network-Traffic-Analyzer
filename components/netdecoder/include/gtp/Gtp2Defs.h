#pragma once

// clang-format off

#define GTPV2_IE_RESERVED               0
#define GTPV2_IE_IMSI                   1
#define GTPV2_IE_CAUSE                  2
#define GTPV2_REC_REST_CNT              3
#define GTPV2_APN                       71
#define GTPV2_AMBR                      72
#define GTPV2_EBI                       73
#define GTPV2_IP_ADDRESS                74
#define GTPV2_MEI                       75
#define GTPV2_IE_MSISDN                 76
#define GTPV2_INDICATION                77
#define GTPV2_PCO                       78
#define GTPV2_PAA                       79
#define GTPV2_BEARER_QOS                80
#define GTPV2_FLOW_QOS                  81
#define GTPV2_IE_RAT_TYPE               82
#define GTPV2_IE_SERV_NET               83
#define GTPV2_BEARER_TFT                84
#define GTPV2_TAD                       85
#define GTPV2_ULI                       86
#define GTPV2_F_TEID                    87
#define GTPV2_G_CN_ID                   89
#define GTPV2_DELAY_VALUE               92
#define GTPV2_BEARER_CTX                93
#define GTPV2_CHARGING_ID               94
#define GTPV2_CHARGING_CHARACTERISTIC   95
#define GTPV2_BEARER_FLAG               97
#define GTPV2_PDN_TYPE                  99
#define GTPV2_PTI                       100
#define GTPV2_PDN_CONN                  109
#define GTPV2_UE_TIME_ZONE              114
#define GTPV2_F_CONTAINER               118
#define GTPV2_F_CAUSE                   119
#define GTPV2_TARGET_ID                 121
#define GTPV2_APN_RESTRICTION           127
#define GTPV2_SELEC_MODE                128
#define GTPV2_BEARER_CONTROL_MODE       130
#define GTPV2_CNG_REP_ACT               131
#define GTPV2_NODE_TYPE                 135
#define GTPV2_FQDN                      136
#define GTPV2_TI                        137
#define GTPV2_PRIVATE_EXT               255

/* Definition of User Location Info (AVP 22) masks */
#define GTPv2_ULI_CGI_MASK                0x01
#define GTPv2_ULI_SAI_MASK                0x02
#define GTPv2_ULI_RAI_MASK                0x04
#define GTPv2_ULI_TAI_MASK                0x08
#define GTPv2_ULI_ECGI_MASK               0x10


#define GTPV2_CREATE_SESSION_REQUEST     32
#define GTPV2_CREATE_SESSION_RESPONSE    33
#define GTPV2_MODIFY_BEARER_REQUEST      34
#define GTPV2_MODIFY_BEARER_RESPONSE     35
#define GTPV2_DELETE_SESSION_REQUEST     36
#define GTPV2_DELETE_SESSION_RESPONSE    37
#define GTPV2_BEARER_RESOURCE_COMMAND    68
#define GTPV2_CREATE_BEARER_REQUEST      95
#define GTPV2_CREATE_BEARER_RESPONSE     96
#define GTPV2_UPDATE_BEARER_REQUEST      97
#define GTPV2_UPDATE_BEARER_RESPONSE     98
#define GTPV2_DELETE_BEARER_REQUEST      99
#define GTPV2_DELETE_BEARER_RESPONSE    100
#define GTPV2_DELETE_SESSION_REQUEST     36
#define GTPV2_DELETE_SESSION_RESPONSE    37

#define GTPV2_RELEASE_ACCESS_BEARER_REQUEST    170
#define GTPV2_RELEASE_ACCESS_BEARER_RESPONSE   171
#define GTPV2_DD_NOTIFICAION                   176
#define GTPV2_DD_NOTIFICAION_ACK               177
#define GTPV2_MODIFY_BEARER_COMMAND            64

// clang-format on
