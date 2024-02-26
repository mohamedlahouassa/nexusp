#ifndef __HEADERS__
#define __HEADERS__

#include "defines.p4"

header ethernet_t {
    mac_t dst_addr;
    mac_t src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4>          version;
    bit<4>          ihl;
    bit<6>          dscp;
    bit<2>          ecn;
    bit<16>         len;
    bit<16>         identification;
    bit<3>          flags;
    bit<13>         frag_offset;
    bit<8>          ttl;
    bit<8>          protocol;
    bit<16>         hdr_checksum;
    ip_address_t    src_addr;
    ip_address_t    dst_addr;
}

header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}


header tcp_options_t {
    varbit<320> options;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length_;
    bit<16> checksum;
}

header http_t {
    bit<8> char;
}

struct metadata_t {
    bit<32> flows_size;                         // Nombre de flux actuels
    bit<32> flow_hash;
    bit<32> flow_packets_number;   
    bit<32> flow_syn_number;                    // Tableau de nombre de paquets par flux indicé par leur hash
    bit<32> flow_bytes_number;                  // Tableau de nombre d'octets par flux indicé par leur hash 
    bit<32> flow_pps_number;                    // Tableau de nombre d'octets par flux indicé par leur hash
    bit<32> flow_pps_tmp_number;                // Tableau de nombre d'octets par flux indicé par leur hash
    bit<48> flow_first_seen_packet_timestamp;
    bit<48> flow_pps_breakpoint;
    bit<48> flow_last_seen_packet_timestamp;
    bit<48> flow_last_inter_packets_gap_value;
    bit<1>  blocked;
    bit<16> payload_len;
    bool    http_get_request_start;
    bool    http_request_is_complete;
    bool    http_request;
    bool    http_response;
    bool    ipv4_forward_hit;
  
}

struct headers_t {
    ethernet_t                  ethernet;
    ipv4_t                      ipv4;
    icmp_t                      icmp;
    tcp_t                       tcp;
    tcp_options_t               tcp_options;
    udp_t                       udp;
    http_t[PAYLOAD_MAX_LENGHT]  http;
}

#endif