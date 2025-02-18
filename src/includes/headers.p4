/*
Copyright 2013-present Barefoot Networks, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#pragma once
/* for random number generation */
#define RANDOM_GEN_BIT_WIDTH 20
typedef bit<RANDOM_GEN_BIT_WIDTH> random_gen_bitwidth_t;


typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<32> timestamp_t;
typedef bit<1> hash_t;


struct port_metadata_t {
    bit<8> switch_id;
};

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header pfc_h {
    bit<16> opcode;
    bit<16> flags;
    bit<16> c0;
    bit<16> c1;
    bit<16> c2;
    bit<16> c3;
    bit<16> c4;
    bit<16> c5;
    bit<16> c6;
    bit<16> c7;
    bit<16> pad;
}

header arp_h {
    bit<16> htype;
    bit<16> ptype;
    bit<8> hlen;
    bit<8> plen;
    bit<16> oper;
    mac_addr_t sender_hw_addr;
    ipv4_addr_t sender_ip_addr;
    mac_addr_t target_hw_addr;
    ipv4_addr_t target_ip_addr;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header icmp_h {
    bit<8> type_;
    bit<8> code;
    bit<16> hdr_checksum;
    bit<16> id;
    bit<16> seq_no;
    bit<64> data_time;
}

/*---- RDMA monitoring -----*/
header ib_bth_h { // 12 bytes
    /**
     * @brief opcode
     *  --RC--
     *  0x04        RC RDMA SEND-ONLY (4)
     *  0x0A        RC RDMA WRITE-ONLY (10)
     *  0x06        RC RDMA WRITE FIRST (6) - RETH
     *  0x07        RC RDMA WRITE MIDDLE (7)
     *  0x08        RC RDMA WRITE LAST (8)
     *  0x11        RC RDMA ACK/NACK (17) - AETH
     *  0x10        RC RDMA Read-response ONLY (16)
     *  0x0C        RC RDMA Read-request (13)
     *  0x81        Mellanox's CNP packet (129)
     */
    bit<8> opcode;
    bit<8> flags;  // 1 bit solicited event, 1 bit migreq, 2 bit padcount, 4 bit headerversion
    bit<16> partition_key;
    bit<8> reserved0;
    bit<24> destination_qp;
    bit<1> ack_request;
    bit<7> reserved1;
    bit<24> packet_seqnum;
}

// RC FIRST WR
header ib_reth_h {
    bit<64> virtual_addr;
    bit<32> remote_key;
    bit<32> dma_length;
}

// RC SEND-ONLY (4)
header ib_deth_h {
    bit<32> queue_key;
    bit<8> reserved2;
    bit<24> source_qp;
}

// ACK
header ib_aeth_h {
    bit<1> reserved;
    bit<2> opcode;      // (0: ACK, 3: NACK)
    bit<5> error_code;  // (PSN SEQ ERROR)
    bit<8> msg_seq_number;
}

/* Any metadata to be bridged from ig to eg */
header bridged_meta_h {
}

const bit<3> IG_MIRROR_TYPE_1 = 1; // corresponds to ig_mirror1_h

header ig_mirror1_h {
    bit<48> ingress_mac_timestamp;
    bit<8> opcode;
    bit<8> mirrored;
    bit<8> last_ack;
    bit<32> rdma_seqnum;
}

struct header_t {
    /* custom bridged info, needs to be deparsed from ig to eg */
    bridged_meta_h bridged_meta;  

    /* Normal headers */
    ethernet_h ethernet;
    pfc_h pfc;
    ipv4_h ipv4;
    arp_h arp;
    tcp_h tcp;
    udp_h udp;
    icmp_h icmp;

    /* RDMA headers */
    ib_bth_h bth;
    ib_reth_h reth;
    ib_deth_h deth;
    ib_aeth_h aeth;
}


struct metadata_t {
    /* switch's ID for our virtual topology */
    port_metadata_t port_md;    // 8
    timestamp_t current_time;  // 32
    // timestamp_t time_gap;   // 32
    // hash_t hash_val;   // 16
    bit<1> new_flowlet;
    bit<2> min_link;
    // bit<32> counter0;
    // bit<32> counter1;
    // bit<32> counter2;
    // bit<32> counter3;
    bit<32> counter;
    ig_mirror1_h ig_mirror1;
    MirrorId_t mirror_session;
}
