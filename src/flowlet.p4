/* -*- P4_16 -*- */
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "includes/headers.p4"
#include "includes/parser.p4"

#define FLOWLET_TABLE_SIZE 1

const int MCAST_GRP_ID = 1; // for ARP
const bit<10> MIRROR_SESSION_RDMA_ID_IG = 10w777;	// for mirror id
// const bit<32> FLOWLET_TABLE_SIZE=32w1<<8;	// a table for different flowlet 2^8
const timestamp_t FLOWLET_TIMEOUT = 32w5000>>8;	// 5us
const int MAX_PORTS = 256;


control SwitchIngress(
    inout header_t hdr,
    inout metadata_t meta,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr,
    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
    inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm){

    // Hash<hash_t>(HashAlgorithm_t.CRC8) flowlet_hash;

	// flowlet table
	Register<timestamp_t,hash_t>(FLOWLET_TABLE_SIZE) flowlet_time;
	Register<bit<8>,hash_t>(FLOWLET_TABLE_SIZE) flowlet_port_index;


	RegisterAction<timestamp_t,hash_t,bit<1>>(flowlet_time)
	check_new_flowlet={
		void apply(inout timestamp_t data,out bit<1> new_flowlet){
			new_flowlet=0;

			if(meta.current_time-data>=FLOWLET_TIMEOUT){
				new_flowlet=1;
			}
			data=meta.current_time;
		}
	};

	RegisterAction<bit<8>,hash_t,bit<8>>(flowlet_port_index)
	read_port_index={
		void apply(inout bit<8> data,out bit<8> port_index){
			port_index=data;
		}
	};

	RegisterAction<bit<8>,hash_t,bit<8>>(flowlet_port_index)
	write_port_index={
		void apply(inout bit<8> data){
			data=(bit<8>)meta.port_index;
		}
	};

	Register<bit<32>,bit<2>>(4) path_counter;

	RegisterAction<bit<32>,bit<2>,bit<32>>(path_counter)
	read_path_counter={
		void apply(inout bit<32> data,out bit<32> counter){
			counter=data;
		}
	};

	RegisterAction<bit<32>,bit<2>,bit<32>>(path_counter)
	update_path_counter={
		void apply(inout bit<32> data){
			data=data|+|1;
		}
	};




	action forward(PortId_t port){
		ig_intr_md_for_tm.ucast_egress_port=port;
	}

	action miss(bit<3> drop_bits) {
		ig_intr_md_for_dprsr.drop_ctl = drop_bits;
	}

	table random_forward{
		key = {
			hdr.ethernet.dst_addr: exact;
			meta.min_link: exact;
		}
		actions = {
			forward;
			@defaultonly miss;
		}
		const default_action = miss(0x1);
	}

	action mirror_to_collector(bit<10> ing_mir_ses){
        ig_intr_md_for_dprsr.mirror_type = IG_MIRROR_TYPE_1;
        meta.mirror_session = ing_mir_ses;
		meta.ig_mirror1.ingress_mac_timestamp = ig_intr_md.ingress_mac_tstamp;
		meta.ig_mirror1.opcode = hdr.bth.opcode;
		meta.ig_mirror1.mirrored = (bit<8>)IG_MIRROR_TYPE_1;
    }

	action find_lowest_path(){
		bit<32> min_value = meta.counter0;  

		if (meta.counter1 < min_value) {  
			min_value = counter1;  
			meta.min_link = 1;  
		}  
		if (meta.counter2 < min_value) {  
			min_value = counter2;  
			meta.min_link = 2;  
		}  
		if (meta.counter3 < min_value) {  
			min_value = counter3;  
			meta.min_link = 3;  
		}  
	}

	apply {
		if(hdr.ethernet.ether_type == (bit<16>) ether_type_t.ARP){
			// do the broadcast to all involved ports
			ig_intr_md_for_tm.mcast_grp_a = MCAST_GRP_ID;
			ig_intr_md_for_tm.rid = 0;
		} else { // non-arp packet	

			if (hdr.bth.isValid()){ // if RDMA
				if(hdr.pfc.isValid()){
					hdr.ethernet.dst_addr = 48w0x0180c2000001;
				}
				// meta.timeout = get_flowlet_timeout.execute(0);
				meta.current_time=ig_intr_md.ingress_mac_tstamp[39:8];
				// meta.hash_val=flowlet_hash.get({hdr.ethernet.src_addr,hdr.ethernet.dst_addr,hdr.bth.destination_qp});


				// check current transport link is valid
				meta.valid=check_valid.execute(0);

				meta.new_flowlet=check_new_flowlet.execute(0);
				meta.min_link=read_port_index.execute(0)[1:0];


				if(meta.new_flowlet==1){
					meta.counter0=read_path_counter.execute(0);
					meta.counter1=read_path_counter.execute(1);
					meta.counter2=read_path_counter.execute(2);
					meta.counter3=read_path_counter.execute(3);
					find_lowest_path();
					write_port_index.execute(meta.min_link);
				}
				update_path_counter.execute(meta.min_link);
				random_forward.apply();
				#ifdef IG_MIRRORING_ENABLED
				mirror_to_collector(MIRROR_SESSION_RDMA_ID_IG); // ig_mirror all RDMA packets
				#endif
			}else
				random_forward.apply();
		}
	}

}  // End of SwitchIngressControl





/*******************
 * Egress Pipeline *
 * *****************/

control SwitchEgress(
    inout header_t hdr,
    inout metadata_t meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport){

	apply{

		#ifdef IG_MIRRORING_ENABLED
		if (meta.ig_mirror1.mirrored == (bit<8>)IG_MIRROR_TYPE_1) {
			/* Timestamp -> MAC Src Address*/
			hdr.ethernet.src_addr = meta.ig_mirror1.ingress_mac_timestamp; // 48 bits
			/* Sequence Number -> MAC Dst Address */
			hdr.ethernet.dst_addr = 48w0xe8ebd358a0bc;
        	hdr.udp.src_port=16w4791;
		}
		#endif
	}


} // End of SwitchEgress


Pipeline(SwitchIngressParser(),
		 SwitchIngress(),
		 SwitchIngressDeparser(),
		 SwitchEgressParser(),
		 SwitchEgress(),
		 SwitchEgressDeparser()
		 ) pipe;

Switch(pipe) main;
