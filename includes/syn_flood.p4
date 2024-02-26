#ifndef __SYN_FLOODING__
#define __SYN_FLOODING__

#include "headers.p4"
#include "defines.p4"


control SYN_Flood(inout headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata){

    bit<32> host_ip;

    apply {
        if(hdr.tcp.isValid()){
            if(hdr.ipv4.src_addr > hdr.ipv4.dst_addr){
                hash(meta.flow_hash, 
                    HashAlgorithm.crc32,
                    10w0,
                    {hdr.ipv4.src_addr,
                        hdr.ipv4.dst_addr,
                        hdr.tcp.src_port,
                        hdr.tcp.dst_port},
                    10w1023);
            }
            else{
                hash(meta.flow_hash,
                    HashAlgorithm.crc32,
                    10w0,
                    {hdr.ipv4.dst_addr,
                        hdr.ipv4.src_addr,
                        hdr.tcp.dst_port,
                        hdr.tcp.src_port},
                    10w1023);
                }
            
            hash(host_ip, 
                HashAlgorithm.crc32,
                10w0,
                {hdr.ipv4.src_addr},
                10w1023);
            
            flow_blocked.read(meta.blocked,host_ip);

            if(meta.blocked==0){
                flows_packets_counter.read(meta.flow_packets_number,meta.flow_hash);
                flows_bytes_counter.read(meta.flow_bytes_number,meta.flow_hash);

                if(meta.flow_packets_number==0){
                    flows_size.read(meta.flows_size,0);
                    flows_known.write(meta.flows_size,meta.flow_hash);
                    flows_size.write(0,meta.flows_size+1);
                    flows_first_seen_packet.write(meta.flow_hash, standard_metadata.ingress_global_timestamp);
                }
            
                flows_last_seen_packet.read(meta.flow_last_seen_packet_timestamp,meta.flow_hash);
                flows_packets_counter.write(meta.flow_hash,meta.flow_packets_number+1);
                flows_last_seen_packet.write(meta.flow_hash, standard_metadata.ingress_global_timestamp);
                flows_bytes_counter.write(meta.flow_hash,meta.flow_bytes_number+(bit<32>)hdr.ipv4.len);
                
                if(hdr.tcp.ctrl == 0x02){
                    flows_syn_counter.read(meta.flow_syn_number,meta.flow_hash);
                    flows_syn_counter.write(meta.flow_hash,meta.flow_syn_number+1);
                }
                else if(hdr.tcp.ctrl==0x10){
                    flows_syn_counter.write(meta.flow_hash,0);
                }

                flows_syn_counter.read(meta.flow_syn_number,meta.flow_hash);
                
                if(meta.flow_syn_number >= 20 && hdr.tcp.ctrl == 0x02){
                    flow_blocked.write(host_ip,1);
                }
                
            }
            else{
                mark_to_drop(standard_metadata);
            }
        }
    }
}


   
#endif

