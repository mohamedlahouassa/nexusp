#ifndef __PARSERS__
#define __PARSERS__

#include "headers.p4"
#include "defines.p4"

parser parser_impl(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {
    
    bit<16> loop;

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETH_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_ICMP: parse_icmp;
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }
    
    state parse_icmp {
        packet.extract<icmp_t>(hdr.icmp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.tcp.data_offset){
            5: parse_app_len;
            default: parse_tcp_options;
        }
    }

    state parse_tcp_options {
        bit<10> len = ((bit<10>)(hdr.tcp.data_offset - 5) * 4 * 8);
        packet.extract(hdr.tcp_options, (bit<32>)len);
        transition parse_app_len;
    }

    state parse_udp {
        packet.extract<udp_t>(hdr.udp);
        transition accept;
    }

    state parse_app_len {
        meta.payload_len = 
            hdr.ipv4.len - ((bit<16>)hdr.ipv4.ihl + (bit<16>)hdr.tcp.data_offset) * 4;
        transition select(meta.payload_len) {
            0: accept;
            default: parse_app_dst_port;
        }
    }

    state parse_app_dst_port {
        transition select(hdr.tcp.dst_port) {
            HTTP_PORT: parse_http_request_1;
            default: parse_app_src_port;
        }
    }

    state parse_app_src_port {
        transition select(hdr.tcp.src_port) {
            HTTP_PORT: parse_http_response;
            default: accept;
        }
    }


    state parse_http_request_1 {
        // "GET / HTTP/1.1" length is 14 (minimal size for a start line)
        bool length_enough = meta.payload_len >= 14;
        meta.http_request = true;
        transition select(length_enough) {
            true: parse_http_request_2;
            default: accept;
        }
    }

    state parse_http_request_2 {
        transition select(packet.lookahead<bit<40>>()) {
            HTTP_REQ_GET_SEP: parse_http_get_request_start;
            default: accept;
        }
    }

    state parse_http_get_request_start {
        meta.http_get_request_start = true;
        loop = 0;
        transition parse_http_get_request;
    }

    state parse_http_get_request {
        packet.extract(hdr.http.next);
        loop = loop + 1;
        bool more_char = loop + 2 <= meta.payload_len;
        transition select(more_char){
            true: parse_search_crlf;
            default: accept;
        }
    }

    state parse_search_crlf {
        transition select(packet.lookahead<bit<16>>()) {
            CRLF: parse_http_crlf;
            default: parse_http_get_request;
        }
    }

    state parse_http_crlf {
        packet.extract(hdr.http.next);
        packet.extract(hdr.http.next);
        bool more_char = loop + 2 <= meta.payload_len;
        transition select(more_char){
            true: parse_search_crlf_2;
            default: accept;
        }
    }
    
    state parse_search_crlf_2 {
        transition select(packet.lookahead<bit<16>>()) {
            CRLF: parse_http_request_complete;
            default: parse_http_get_request;
        }
    }

    state parse_http_request_complete {
        meta.http_request_is_complete = true;
        transition accept;
    }

    state parse_http_response {
        meta.http_response = true;
        transition accept;
    }

}


control deparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_options);
        packet.emit(hdr.icmp);
        packet.emit(hdr.udp);
        packet.emit(hdr.http);
    }
}

#endif