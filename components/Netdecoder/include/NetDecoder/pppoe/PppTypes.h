#pragma once

// Copied from Wireshark: ppptypes.h

/** Padding Protocol */
#define PCPP_PPP_PADDING		0x1
/** ROHC small-CID */
#define PCPP_PPP_ROHC_SCID		0x3
/** ROHC large-CID */
#define PCPP_PPP_ROHC_LCID		0x5
/** Internet Protocol version 4 */
#define PCPP_PPP_IP				0x21
/** OSI Network Layer */
#define PCPP_PPP_OSI			0x23
/** Xerox NS IDP */
#define PCPP_PPP_XNSIDP			0x25
/** DECnet Phase IV */
#define PCPP_PPP_DEC4			0x27
/** AppleTalk */
#define PCPP_PPP_AT				0x29
/** Novell IPX */
#define PCPP_PPP_IPX			0x2b
/** Van Jacobson Compressed TCP/IP */
#define PCPP_PPP_VJC_COMP		0x2d
/** Van Jacobson Uncompressed TCP/IP */
#define PCPP_PPP_VJC_UNCOMP		0x2f
/** Bridging PDU */
#define PCPP_PPP_BCP			0x31
/** Stream Protocol (ST-II) */
#define PCPP_PPP_ST				0x33
/** Banyan Vines */
#define PCPP_PPP_VINES			0x35
/** AppleTalk EDDP */
#define PCPP_PPP_AT_EDDP		0x39
/** AppleTalk SmartBuffered */
#define PCPP_PPP_AT_SB			0x3b
/** Multi-Link */
#define PCPP_PPP_MP				0x3d
/** NETBIOS Framing */
#define PCPP_PPP_NB				0x3f
/** Cisco Systems */
#define PCPP_PPP_CISCO			0x41
/** Ascom Timeplex */
#define PCPP_PPP_ASCOM			0x43
/** Fujitsu Link Backup and Load Balancing */
#define PCPP_PPP_LBLB			0x45
/** DCA Remote Lan */
#define PCPP_PPP_RL				0x47
/** Serial Data Transport Protocol */
#define PCPP_PPP_SDTP			0x49
/** SNA over 802.2 */
#define PCPP_PPP_LLC			0x4b
/** SNA */
#define PCPP_PPP_SNA			0x4d
/** IPv6 Header Compression  */
#define PCPP_PPP_IPV6HC			0x4f
/** KNX Bridging Data */
#define PCPP_PPP_KNX			0x51
/** Encryption */
#define PCPP_PPP_ENCRYPT		0x53
/** Individual Link Encryption */
#define PCPP_PPP_ILE			0x55
/** Internet Protocol version 6 */
#define PCPP_PPP_IPV6			0x57
/** PPP Muxing */
#define PCPP_PPP_MUX			0x59
/** Vendor-Specific Network Protocol (VSNP) */
#define PCPP_PPP_VSNP			0x5b
/** TRILL Network Protocol (TNP) */
#define PCPP_PPP_TNP			0x5d
/** RTP IPHC Full Header */
#define PCPP_PPP_RTP_FH			0x61
/** RTP IPHC Compressed TCP */
#define PCPP_PPP_RTP_CTCP		0x63
/** RTP IPHC Compressed Non TCP */
#define PCPP_PPP_RTP_CNTCP		0x65
/** RTP IPHC Compressed UDP 8 */
#define PCPP_PPP_RTP_CUDP8		0x67
/** RTP IPHC Compressed RTP 8 */
#define PCPP_PPP_RTP_CRTP8		0x69
/** Stampede Bridging */
#define PCPP_PPP_STAMPEDE		0x6f
/** MP+ Protocol */
#define PCPP_PPP_MPPLUS			0x73
/** NTCITS IPI */
#define PCPP_PPP_NTCITS_IPI		0xc1
/** Single link compression in multilink */
#define PCPP_PPP_ML_SLCOMP		0xfb
/** Compressed datagram */
#define PCPP_PPP_COMP			0xfd
/** 802.1d Hello Packets */
#define PCPP_PPP_STP_HELLO		0x0201
/** IBM Source Routing BPDU */
#define PCPP_PPP_IBM_SR			0x0203
/** DEC LANBridge100 Spanning Tree */
#define PCPP_PPP_DEC_LB			0x0205
/** Cisco Discovery Protocol */
#define PCPP_PPP_CDP			0x0207
/** Netcs Twin Routing */
#define PCPP_PPP_NETCS			0x0209
/** STP - Scheduled Transfer Protocol */
#define PCPP_PPP_STP			0x020b
/** EDP - Extreme Discovery Protocol */
#define PCPP_PPP_EDP			0x020d
/** Optical Supervisory Channel Protocol */
#define PCPP_PPP_OSCP			0x0211
/** Optical Supervisory Channel Protocol */
#define PCPP_PPP_OSCP2			0x0213
/** Luxcom */
#define PCPP_PPP_LUXCOM			0x0231
/** Sigma Network Systems */
#define PCPP_PPP_SIGMA			0x0233
/** Apple Client Server Protocol */
#define PCPP_PPP_ACSP			0x0235
/** MPLS Unicast */
#define PCPP_PPP_MPLS_UNI		0x0281
/** MPLS Multicast */
#define PCPP_PPP_MPLS_MULTI		0x0283
/** IEEE p1284.4 standard - data packets */
#define PCPP_PPP_P12844			0x0285
/** ETSI TETRA Network Protocol Type 1 */
#define PCPP_PPP_TETRA			0x0287
/** Multichannel Flow Treatment Protocol */
#define PCPP_PPP_MFTP			0x0289
/** RTP IPHC Compressed TCP No Delta */
#define PCPP_PPP_RTP_CTCPND		0x2063
/** RTP IPHC Context State */
#define PCPP_PPP_RTP_CS			0x2065
/** RTP IPHC Compressed UDP 16 */
#define PCPP_PPP_RTP_CUDP16		0x2067
/** RTP IPHC Compressed RTP 16 */
#define PCPP_PPP_RTP_CRDP16		0x2069
/** Cray Communications Control Protocol */
#define PCPP_PPP_CCCP			0x4001
/** CDPD Mobile Network Registration Protocol */
#define PCPP_PPP_CDPD_MNRP		0x4003
/** Expand accelerator protocol */
#define PCPP_PPP_EXPANDAP		0x4005
/** ODSICP NCP */
#define PCPP_PPP_ODSICP			0x4007
/** DOCSIS DLL */
#define PCPP_PPP_DOCSIS			0x4009
/** Cetacean Network Detection Protocol */
#define PCPP_PPP_CETACEANNDP	0x400b
/** Stacker LZS */
#define PCPP_PPP_LZS			0x4021
/** RefTek Protocol */
#define PCPP_PPP_REFTEK			0x4023
/** Fibre Channel */
#define PCPP_PPP_FC				0x4025
/** EMIT Protocols */
#define PCPP_PPP_EMIT			0x4027
/** Vendor-Specific Protocol (VSP) */
#define PCPP_PPP_VSP			0x405b
/** TRILL Link State Protocol (TLSP) */
#define PCPP_PPP_TLSP			0x405d
/** Internet Protocol Control Protocol */
#define PCPP_PPP_IPCP			0x8021
/** OSI Network Layer Control Protocol */
#define PCPP_PPP_OSINLCP		0x8023
/** Xerox NS IDP Control Protocol */
#define PCPP_PPP_XNSIDPCP		0x8025
/** DECnet Phase IV Control Protocol */
#define PCPP_PPP_DECNETCP		0x8027
/** AppleTalk Control Protocol */
#define PCPP_PPP_ATCP			0x8029
/** Novell IPX Control Protocol */
#define PCPP_PPP_IPXCP			0x802b
/** Bridging NCP */
#define PCPP_PPP_BRIDGENCP		0x8031
/** Stream Protocol Control Protocol */
#define PCPP_PPP_SPCP			0x8033
/** Banyan Vines Control Protocol */
#define PCPP_PPP_BVCP			0x8035
/** Multi-Link Control Protocol */
#define PCPP_PPP_MLCP			0x803d
/** NETBIOS Framing Control Protocol */
#define PCPP_PPP_NBCP			0x803f
/** Cisco Systems Control Protocol */
#define PCPP_PPP_CISCOCP		0x8041
/** Ascom Timeplex Control Protocol (?) */
#define PCPP_PPP_ASCOMCP		0x8043
/** Fujitsu LBLB Control Protocol */
#define PCPP_PPP_LBLBCP			0x8045
/** DCA Remote Lan Network Control Protocol */
#define PCPP_PPP_RLNCP			0x8047
/** Serial Data Control Protocol */
#define PCPP_PPP_SDCP			0x8049
/** SNA over 802.2 Control Protocol */
#define PCPP_PPP_LLCCP			0x804b
/** SNA Control Protocol */
#define PCPP_PPP_SNACP			0x804d
/** IP6 Header Compression Control Protocol */
#define PCPP_PPP_IP6HCCP		0x804f
/** KNX Bridging Control Protocol */
#define PCPP_PPP_KNXCP			0x8051
/** Encryption Control Protocol */
#define PCPP_PPP_ECP			0x8053
/** Individual Link Encryption Control Protocol */
#define PCPP_PPP_ILECP			0x8055
/** IPv6 Control Protocol */
#define PCPP_PPP_IPV6CP			0x8057
/** PPP Muxing Control Protocol */
#define PCPP_PPP_MUXCP			0x8059
/** Vendor-Specific Network Control Protocol (VSNCP)   [RFC3772] */
#define PCPP_PPP_VSNCP			0x805b
/** TRILL Network Control Protocol (TNCP) */
#define PCPP_PPP_TNCP			0x805d
/** Stampede Bridging Control Protocol */
#define PCPP_PPP_STAMPEDECP		0x806f
/** MP+ Contorol Protocol */
#define PCPP_PPP_MPPCP			0x8073
/** NTCITS IPI Control Protocol */
#define PCPP_PPP_IPICP			0x80c1
/** Single link compression in multilink control */
#define PCPP_PPP_SLCC			0x80fb
/** Compression Control Protocol */
#define PCPP_PPP_CCP			0x80fd
/** Cisco Discovery Protocol Control Protocol */
#define PCPP_PPP_CDPCP			0x8207
/** Netcs Twin Routing */
#define PCPP_PPP_NETCSCP		0x8209
/** STP - Control Protocol */
#define PCPP_PPP_STPCP			0x820b
/** EDPCP - Extreme Discovery Protocol Control Protocol */
#define PCPP_PPP_EDPCP			0x820d
/** Apple Client Server Protocol Control */
#define PCPP_PPP_ACSPC			0x8235
/** MPLS Control Protocol */
#define PCPP_PPP_MPLSCP			0x8281
/** IEEE p1284.4 standard - Protocol Control */
#define PCPP_PPP_P12844CP		0x8285
/** ETSI TETRA TNP1 Control Protocol */
#define PCPP_PPP_TETRACP		0x8287
/** Multichannel Flow Treatment Protocol */
#define PCPP_PPP_MFTPCP			0x8289
/** Link Control Protocol */
#define PCPP_PPP_LCP			0xc021
/** Password Authentication Protocol */
#define PCPP_PPP_PAP			0xc023
/** Link Quality Report */
#define PCPP_PPP_LQR			0xc025
/** Shiva Password Authentication Protocol */
#define PCPP_PPP_SPAP			0xc027
/** CallBack Control Protocol (CBCP) */
#define PCPP_PPP_CBCP			0xc029
/** BACP Bandwidth Allocation Control Protocol */
#define PCPP_PPP_BACP			0xc02b
/** BAP Bandwidth Allocation Protocol */
#define PCPP_PPP_BAP			0xc02d
/** Vendor-Specific Authentication Protocol (VSAP) */
#define PCPP_PPP_VSAP			0xc05b
/** Container Control Protocol */
#define PCPP_PPP_CONTCP			0xc081
/** Challenge Handshake Authentication Protocol */
#define PCPP_PPP_CHAP			0xc223
/** RSA Authentication Protocol */
#define PCPP_PPP_RSAAP			0xc225
/** Extensible Authentication Protocol */
#define PCPP_PPP_EAP			0xc227
/** Mitsubishi Security Information Exchange Protocol (SIEP) */
#define PCPP_PPP_SIEP			0xc229
/** Stampede Bridging Authorization Protocol */
#define PCPP_PPP_SBAP			0xc26f
/** Proprietary Authentication Protocol */
#define PCPP_PPP_PRPAP			0xc281
/** Proprietary Authentication Protocol */
#define PCPP_PPP_PRPAP2			0xc283
/** Proprietary Node ID Authentication Protocol */
#define PCPP_PPP_PRPNIAP		0xc481
