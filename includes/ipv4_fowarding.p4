#ifndef __IPV4_FOWARDING__
#define __IPV4_FOWARDING__

#include "headers.p4"
#include "defines.p4"

control IPV4_Forward(inout headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    
    action ipv4_forward(mac_t dst_addr, port_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dst_addr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            ipv4_forward;

            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    
    apply{
        if (hdr.ipv4.isValid()) {
            meta.ipv4_forward_hit = ipv4_lpm.apply().hit;
        }
    }
}

   
#endif

