#ifndef __ICMP_FLOODING__
#define __ICMP_FLOODING__

#include "headers.p4"
#include "defines.p4"

control ICMP_Flood(inout headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata){
    
    bit<32> host_ip;

    apply {

        if(hdr.icmp.isValid()){
            hash(meta.flow_hash, 
                HashAlgorithm.crc32,
                10w0,
                {hdr.ipv4.src_addr, 
                    hdr.ipv4.dst_addr,
                    hdr.ipv4.protocol,
                    hdr.icmp.typeCode},
                10w1023);

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
                    flow_breakpoint.write(meta.flow_hash,standard_metadata.ingress_global_timestamp);
                }

                flow_breakpoint.read(meta.flow_pps_breakpoint,meta.flow_hash);

                if(standard_metadata.ingress_global_timestamp-meta.flow_pps_breakpoint < 1000000){
                    flow_last_pps.read(meta.flow_pps_tmp_number,meta.flow_hash);
                    flow_last_pps.write(meta.flow_hash,meta.flow_pps_tmp_number+1);
                }
                else{
                    flow_last_pps.read(meta.flow_pps_tmp_number,meta.flow_hash);
                    flow_pps.read(meta.flow_pps_number,meta.flow_hash);

                    if(meta.flow_pps_number==0){
                        flow_pps.write(meta.flow_hash,meta.flow_pps_tmp_number);
                    }
                    else{
                        bit <32> moy;
                        moy=(meta.flow_pps_number+meta.flow_pps_tmp_number)/2;
                        flow_pps.write(meta.flow_hash,moy);
                    }

                    flow_last_pps.write(meta.flow_hash,0);
                    flow_breakpoint.write(meta.flow_hash,standard_metadata.ingress_global_timestamp);
                }
            
                flows_last_seen_packet.read(meta.flow_last_seen_packet_timestamp,meta.flow_hash);

                bit <48> interval;
                bit <48> moyenne;

                if(meta.flow_last_seen_packet_timestamp==0){
                    interval=0;
                }
                else{
                    interval=standard_metadata.ingress_global_timestamp-meta.flow_last_seen_packet_timestamp; 
                }

                flows_inter_packets_gap.read(meta.flow_last_inter_packets_gap_value,meta.flow_hash);
                moyenne=(interval+meta.flow_last_inter_packets_gap_value)/2;
                flows_inter_packets_gap.write(meta.flow_hash,moyenne);
                flows_packets_counter.write(meta.flow_hash,meta.flow_packets_number+1);
                flows_last_seen_packet.write(meta.flow_hash, standard_metadata.ingress_global_timestamp);
                flows_bytes_counter.write(meta.flow_hash,meta.flow_bytes_number+(bit<32>)hdr.ipv4.len);
                flow_pps.read(meta.flow_pps_tmp_number,meta.flow_hash);
                
                if(meta.flow_pps_tmp_number>200){
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

