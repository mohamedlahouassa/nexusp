#ifndef __DEFINES__
#define __DEFINES__

#define ETH_TYPE_IPV4       0x0800
#define IP_PROTO_ICMP       8w1
#define IP_PROTO_TCP        8w6
#define IP_PROTO_UDP        8w17
#define HTTP_PORT           16w80

#define PAYLOAD_MAX_LENGHT 1446 // (1500B -14B -20B -20B)

typedef bit<48> mac_t;
typedef bit<32> ip_address_t;
typedef bit<9>  port_t;

const bit<48> THRESHOLD_INTER_GAP = 1000000; // 1s
const bit<32> THRESHOLD_MIN_PACKET = 5; // nombre de paquets minimum pour un flux avant de le filtrer
const bit<48> THRESHOLD_SESSION_DURATION = 10000000; // 10s
const bit<4>  THRESHOLD_HTTP_GET_CONNECTION_PER_IP = 15;
const bit<4>  THRESHOLD_HTTP_GET_PACKET_PER_REQUEST = 8;

const bit<40> HTTP_REQ_GET_SEP  = 0x474554202f; // => "GET /"

const bit<16> CRLF = 0x0d0a; // => "\r\n"


// registre pour stocker les informations sur les flux HTTP
register<bit<32>>(1)     flows_size;
register<bit<32>>(65536) flows_known;
register<bit<32>>(65536) flows_packets_counter;
register<bit<32>>(65536) flows_bytes_counter;
register<bit<32>>(65536) flows_syn_counter;
register<bit<48>>(65536) flows_first_seen_packet;
register<bit<48>>(65536) flows_last_seen_packet;
register<bit<48>>(65536) flows_inter_packets_gap;
register<bit<32>>(65536) flow_pps;
register<bit<32>>(65536) flow_last_pps;
register<bit<1>>(65536)  flow_blocked;
register<bit<48>>(65536) flow_breakpoint;
register<bit<4>>(65536)  flows_http_get_connection_count;
register<bit<4>>(65536)  flows_http_get_packet_count;



#endif