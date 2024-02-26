#ifndef __CHECKSUMS__
#define __CHECKSUMS__

#include "headers.p4"

control verify_checksum_control(inout headers_t hdr,
                                inout metadata_t local_metadata) {
    apply {
    }
}

control compute_checksum_control(inout headers_t hdr,
                                 inout metadata_t local_metadata) {
        apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.len,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.frag_offset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_addr,
              hdr.ipv4.dst_addr },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
    }
}

#endif