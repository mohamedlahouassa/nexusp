#include <core.p4>
#include <v1model.p4>

#include "includes/defines.p4"
#include "includes/parsers.p4"
#include "includes/headers.p4"
#include "includes/checksums.p4"
#include "includes/ipv4_fowarding.p4"
#include "includes/syn_flood.p4"
#include "includes/udp_flood.p4"
#include "includes/icmp_flood.p4"
#include "includes/slowloris.p4"



control ingress(inout headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    
    IPV4_Forward() ipv4Forward;
    SYN_Flood() synFlood;
    UDP_Flood() udpFlood;
    ICMP_Flood() icmpFlood;
    Slowloris() slowloris;
  
    apply{
        ipv4Forward.apply(hdr,meta,standard_metadata);
        if(meta.ipv4_forward_hit){
                udpFlood.apply(hdr,meta,standard_metadata);
                icmpFlood.apply(hdr,meta,standard_metadata);
                synFlood.apply(hdr,meta,standard_metadata);
                slowloris.apply(hdr,meta,standard_metadata);
        }
    }
   
}

control egress(inout headers_t hdr,
               inout metadata_t local_metadata,
               inout standard_metadata_t standard_metadata) {

    apply {
    }
}


V1Switch(
        parser_impl(),
        verify_checksum_control(),
        ingress(),
        egress(),
        compute_checksum_control(),
        deparser()
) main;