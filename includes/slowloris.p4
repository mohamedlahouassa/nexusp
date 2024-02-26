#ifndef __SLOWLORIS__
#define __SLOWLORIS__

#include "headers.p4"
#include "defines.p4"

control Slowloris(inout headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata){
    
    bit<4> buffer;
    bit<32> flow_ip_only_hash;
    bit<32> host_ip;

    apply {
        if(hdr.tcp.isValid()){
            hash(flow_ip_only_hash, 
                HashAlgorithm.crc32,
                10w0,
                {hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr},
                10w1023);
            
            hash(host_ip, 
                HashAlgorithm.crc32,
                10w0,
                {hdr.ipv4.src_addr},
                10w1023);

            flow_blocked.read(meta.blocked, host_ip);

            if(meta.blocked==0){
                if(meta.http_request){
                    //  First packet include GET method
                    if(meta.http_get_request_start){
                        if(!meta.http_request_is_complete){
                            hash(meta.flow_hash, 
                                HashAlgorithm.crc32,
                                10w0,
                                {hdr.ipv4.src_addr,
                                    hdr.ipv4.dst_addr,
                                    hdr.tcp.src_port,
                                    hdr.tcp.dst_port},
                                10w1023);

                            flows_http_get_connection_count.read(buffer,flow_ip_only_hash);

                            if (buffer+1 < THRESHOLD_HTTP_GET_CONNECTION_PER_IP){
                                flows_http_get_connection_count.write(flow_ip_only_hash,buffer+1);
                                flows_http_get_packet_count.read(buffer,meta.flow_hash);
                                flows_http_get_packet_count.write(meta.flow_hash,buffer+1);
                            }
                            else{
                                flow_blocked.write(host_ip,1);
                                mark_to_drop(standard_metadata);
                            }
                        }

                    }
                    // HTTP packet not include GET in payload, maybe header of GET method, maybe other method 
                    else{
                        flows_http_get_packet_count.read(buffer,meta.flow_hash);
                        if (buffer > 0){
                            if (buffer+1 < THRESHOLD_HTTP_GET_PACKET_PER_REQUEST){
                                flows_http_get_packet_count.write(flow_ip_only_hash,buffer+1);
                            }
                            else{
                                flow_blocked.write(host_ip,1);
                                mark_to_drop(standard_metadata);
                            }
                        }
                    }
                }
                if(meta.http_response){
                    hash(meta.flow_hash, 
                        HashAlgorithm.crc32,
                        10w0,
                        {hdr.ipv4.src_addr,
                            hdr.ipv4.dst_addr,
                            hdr.tcp.dst_port,
                            hdr.tcp.src_port},
                        10w1023);

                    flows_http_get_packet_count.read(buffer,meta.flow_hash);

                    if (buffer > 0){
                        flows_http_get_packet_count.write(meta.flow_hash, 0);
                        flows_http_get_connection_count.read(buffer,flow_ip_only_hash);
                        flows_http_get_connection_count.write(flow_ip_only_hash, buffer-1);
                    }                 
                }
            }
            else{
                mark_to_drop(standard_metadata);
            }
        }
    }
}
   
#endif

