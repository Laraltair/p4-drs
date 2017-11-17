#include <core.p4>
#include <v1model.p4>

typedef bit<48> EthernetAddress;
typedef bit<32> IPv4Address;

const bit<8> Routeselectprotocol = 8w0xbc;

header Ethernet_h {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16> ethernetType;
}


header IPv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    IPv4Address srcAddr;
    IPv4Address dstAddr;
    //varbit<320>  options;
}

header Routeselect_h {
    bit<32> route_number;
}

struct headers {
    Ethernet_h ethernet;
    IPv4_h ipv4;
    Routeselect_h routeselect;
}


struct mystruct_t {
    bit<32> a;
}


struct metadata {
    mystruct_t mystruct1;
}

typedef tuple<bit<4>, bit<4>, bit<8>, varbit<56>> myTuple1;

error {
    Ipv4ChecksumError
}


parser ipParser(packet_in pkt, out headers hdr, 
                    inout metadata meta, inout standard_metadata_t stdmeta)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethernetType) {
            0x0800 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            0xbc : parse_routeselect;
            default : accept;
        }
    }

    state parse_routeselect {
        pkt.extract(hdr.routeselect);
        transition accept;
    }
}


control ipIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t stdmeta)
{
    //count,length,route_number
    register<bit<32>>(6) rgt;

    bit<32> packet_count_position = 0;
    bit<32> packet_length_position = 1;
    bit<32> select_position = 2;
    bit<32> threhold_position = 3;
    bit<32> route_position = 4;
    bit<32> route_standby_position = 5;

    bit<32> total_count = 0;
    bit<32> total_length = 0;
    bit<32> select_number = 0;
    bit<32> threhold = 0;
    bit<32> route_number = 0;
    
    bit<32> stat_data = 0;

    action read_register() {
        rgt.read(total_count, packet_count_position);
        rgt.read(total_length, packet_length_position);
        rgt.read(select_number, select_position);
        rgt.read(threhold, threhold_position);
        rgt.read(route_number, route_position);
        rgt.read(stat_data, select_number);
    }

    action write_stat() {
        rgt.write(packet_count_position, 1 + total_count);
        rgt.write(packet_length_position, stdmeta.packet_length + total_length);
    }

    bit<32> write_route_buf1;
    bit<32> write_route_buf2;
    action reset_route() {
        rgt.read(write_route_buf1, route_position);
        rgt.read(write_route_buf2, route_standby_position);

        rgt.write(route_position, write_route_buf2);
        rgt.write(route_standby_position, write_route_buf1);

        rgt.write(packet_count_position, 0);
        rgt.write(packet_length_position, 0);

        rgt.read(route_number, route_position);        
    }

    action forward(bit<9> port) {
        stdmeta.egress_spec = port;
    }

    action broadcast() {
        stdmeta.mcast_grp = 1;
    }


    action write_signal(bit<32> port1, bit<32> src, bit<32> dst, bit<9> port2) {
        clone(CloneType.I2E, port1);
        hdr.ipv4.protocol = Routeselectprotocol;
        hdr.ipv4.srcAddr = src;
        hdr.ipv4.dstAddr = dst;
        hdr.routeselect.setValid();
        hdr.routeselect.route_number = route_number;
        stdmeta.egress_spec = port2;
    }

    bit<32> handle_signal_buf;
    action handle_signal() {
        handle_signal_buf = hdr.routeselect.route_number;
        rgt.write(route_position, handle_signal_buf);
        route_number = hdr.routeselect.route_number;
    }
/*
    table icmp_to_myproto {
        actions = {copy_and_myproto;}
    }


    table handle_arp {
        key = {
            //hdr.ethernet.srcAddr:exact;
            hdr.ethernet.ethernetType:exact;
        }
        actions = {broadcast;NoAction;}
        //actions = {forward;NoAction;}
        default_action = NoAction();
    }
*/

    table match_ipv4_route_1 {
        key = {
            hdr.ipv4.dstAddr:exact;
        }
        actions = {forward;NoAction();}
        size = 16384;
        default_action = NoAction();
    }

    table match_ipv4_route_2 {
        key = {
            hdr.ipv4.dstAddr:exact;
        }
        actions = {forward;NoAction();}
        size = 16384;
        default_action = NoAction();
    }

    table match_inport {
        key = {
            stdmeta.ingress_port:exact;
        }
        actions = {forward;}
    }

    table generate_signal {
        key = {
            hdr.ipv4.dstAddr : exact;
        }
        actions = {write_signal;}
    }

    table receive_signal {
        actions = {handle_signal;}
    }

    table acquire_state {
        actions = {read_register;}
    }

    table update_stat {
        actions = {write_stat;}
    }

    table update_route {
        actions = {reset_route;}
    }

    apply {
        //handle_arp.apply();
        match_inport.apply();

        acquire_state.apply();
        if (hdr.ethernet.ethernetType == 0x0800) {
            update_stat.apply();
        }

        if (stat_data > threhold && (stdmeta.ingress_port == 2 || stdmeta.ingress_port == 3)) {
            update_route.apply();
            generate_signal.apply();
        }

        if (hdr.ipv4.protocol == 0xbc) {
            receive_signal.apply();
        }

        if (route_number == 0 && hdr.ipv4.protocol != 0xbc) {
            match_ipv4_route_1.apply();
        }
        
        if (route_number == 1 && hdr.ipv4.protocol != 0xbc) {
            match_ipv4_route_2.apply();
        }

    }

}



control ipEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t stdmeta)
{   

    apply {

    }
}

control ipVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true,
        {   hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr//,hdr.ipv4.options
        },hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control ipUpdateChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true,
        {   hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr//,hdr.ipv4.options
        },hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }    
}

control ipDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.routeselect);
    }

}

V1Switch<headers, metadata>(ipParser(), ipVerifyChecksum(), ipIngress(), ipEgress(), ipUpdateChecksum(),ipDeparser()) main;