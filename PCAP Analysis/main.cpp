//
//  main.cpp
//  PCAP Analysis
//
//  Created by Devon Hjelm on 12/11/12.
//  Copyright (c) 2012 Devon Hjelm. All rights reserved.
//

#include <sstream>
#include <vector>
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "dirent.h"
#include <sys/stat.h>
#include <math.h>

using namespace std;

template <typename T>
std::ostream& operator<<(std::ostream& out, vector<T> vec) {
   for (auto x:vec) {
      out << " " << x;
   }
   std::cout << endl;
   return out;
}

class Packet {
public:
   std::string src_IP;
   std::string dst_IP;
	u_int sourcePort, destPort;
   uint32_t seq, ack;
   long secs, usecs;
   int data_length;
   
   Packet(){}
   Packet(tcphdr* tcp_header, char src[INET_ADDRSTRLEN], char dst[INET_ADDRSTRLEN], int dl, timeval ts) : secs(ts.tv_sec), usecs(ts.tv_usec), data_length(dl) {
      stringstream out;
      out << src;
      src_IP = out.str();
      out.str("");
      out << dst;
      dst_IP = out.str();
      
      sourcePort = ntohs(tcp_header->th_sport);
      destPort = ntohs(tcp_header->th_dport);
      ack = ntohl(tcp_header->th_ack);
      seq = ntohl(tcp_header->th_seq);
   }
   
   void sub_rel(uint32_t src_rel_seq, uint32_t dst_rel_seq) {
      if (ack > 0) ack -= src_rel_seq;
      seq-=dst_rel_seq;
   }
   
   void print() {
      cout << src_IP << " -> " << dst_IP << endl;
      cout << "SEQ: " << seq << " ACK: " << ack << " Length: " << data_length << std::endl;
     // cout << "At: " << secs << " secs and " << usecs << " usecs" << std::endl;
      cout << "--------------------------" << endl;
   }
   
   bool operator> (Packet *pack) {
      if (secs > pack->secs) return true;
      else if (secs == pack->secs) return (usecs > pack->usecs);
      else return false;
   }
   
   bool operator< (Packet *pack) {
      if (secs < pack->secs) return true;
      else if (secs == pack->secs) return (usecs < pack->usecs);
      else return false;
   }
   
   bool operator>= (Packet* pack) {
      return !(this < pack);
   }
   
   bool operator<= (Packet* pack) {
      return !(this > pack);
   }
};

struct Comes_Before {
   bool operator() (Packet *p1, Packet *p2) {
      if (p1->secs < p2->secs) return true;
      else if (p1->secs == p2->secs) return (p1->usecs < p2->usecs);
      else return false;
   }
};

template <typename T>
void erase_vec_from_vec (const vector<T> vec, vector<T> &from_vec) {
   for (auto t:vec) {
      auto iter = find(from_vec.begin(), from_vec.end(), t);
      from_vec.erase(iter);
   }
}

string path = "/Users/devon/Documents/Courses/CS585/netstcpdumps/";
vector<Packet*> pack_list;
int pack_size;

struct Same_sequence {
   Same_sequence(string src, string dst) : src_IP(src), dst_IP(dst) {}
   bool operator() (Packet *packet) {
      bool same_endpoints = ((packet->src_IP == src_IP) && (packet->dst_IP == dst_IP)) || ((packet->src_IP == dst_IP) && (packet->dst_IP == src_IP));
      bool initial = packet->ack == 0;
      bool out = (!initial) && same_endpoints;
      
      return (out);
   }
   std::string src_IP;
   std::string dst_IP;
};

class TCPSequence {
public:
   Packet *first;
   vector<Packet*> sequence;
   uint32_t snd_rel_seq;
   uint32_t rcv_rel_seq;
   
   TCPSequence(Packet *initial) :first(initial), snd_rel_seq(initial->seq) {}
   
   void pull(vector<Packet*> packets) {
      vector<Packet*>::iterator iter = find(packets.begin(), packets.end(), first);
      sequence.clear();
      sequence.push_back(first);
      uint32_t last_ack = first->ack;
      uint32_t last_seq = first->seq;
      
      while (++iter!=packets.end()) {
         Packet *packet = *iter;
         Same_sequence ss(first->src_IP, first->dst_IP);
         if (sequence.size() == 1) {
            if (packet->ack == last_seq + 1) {
               sequence.push_back(packet);
               last_ack = packet->ack;
               last_seq = packet->seq;
            }
         }
         else if (((packet->ack == last_ack) && (packet->seq == last_seq)) ||
              (packet->seq == last_ack && packet->seq != 0) ||
              packet->ack == last_seq + 1 ||
              packet->ack == last_ack + 1)
         {
            sequence.push_back(packet);
            last_ack = packet->ack;
            last_seq = packet->seq;
         }
      }
      if (sequence.size() == 1) return;
      Packet *first_rcv = *find_if(sequence.begin(), sequence.end(), [&](Packet *pack) {
         return (pack->ack == snd_rel_seq + 1);
      });
      
      rcv_rel_seq = first_rcv->seq;
      sub_rel();
   }
   
   void sub_rel() {
      for (auto packet:sequence) {
         if (packet->src_IP == first->dst_IP) packet->sub_rel(snd_rel_seq, rcv_rel_seq);
         else packet->sub_rel(rcv_rel_seq, snd_rel_seq);
      }
   }
   
   void print() {
      for (auto packet:sequence) {
         packet->print();
      }
   }
   
   void print_stats() {
      std::cout << "Retransmits: " << calc_retransmits() << std::endl;
   }
   
   int calc_retransmits () {
      int retransmits = 0;
      uint32_t rcv_max_seq = 0, snd_max_seq = 0;
      int rcv_prev_length, snd_prev_length = 0;
      for (auto packet:sequence) {
         uint32_t max_seq;
         int prev_length;
         if (packet->src_IP == first->src_IP)   {
            max_seq = snd_max_seq;
            prev_length = snd_prev_length;
         }
         else                                   {
            max_seq = rcv_max_seq;
            prev_length = rcv_prev_length;
         }
         if (packet->seq <= max_seq && packet->data_length > 0 && prev_length > 0) retransmits += 1;
         else {
            if (packet->src_IP == first->src_IP)   {
               snd_max_seq = max_seq;
               snd_prev_length = packet->data_length;
            }
            else                                   {
               rcv_max_seq = max_seq;
               rcv_prev_length = packet->data_length;
            }
         }
      }
      return retransmits;
   }
   
};

void user_routine(u_char *user, struct pcap_pkthdr *phrd, u_char *pdata){}


void packetHandler(u_char *user, const struct pcap_pkthdr* pkthdr, const u_char* pack) {
	const struct ether_header* ethernetHeader;
	const struct ip* ipHeader;
	const struct tcphdr* tcpHeader;
   char src_IP[INET_ADDRSTRLEN];
	char dest_IP[INET_ADDRSTRLEN];
	//u_char *data;
	//string dataStr = "";
   Packet *packet;
   pack_size = pkthdr->caplen;
	ethernetHeader = (struct ether_header*)pack;
	if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
		ipHeader = (struct ip*)(pack + sizeof(struct ether_header));
		inet_ntop(AF_INET, &(ipHeader->ip_src), src_IP, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ipHeader->ip_dst), dest_IP, INET_ADDRSTRLEN);
      
		if (ipHeader->ip_p == IPPROTO_TCP) {
         tcpHeader = (tcphdr*)(pack + sizeof(struct ether_header) + sizeof(struct ip));
			int data_length = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr)) -12;
			packet = new Packet((tcphdr*)tcpHeader, src_IP, dest_IP, data_length, pkthdr->ts);
			//data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
         pack_list.push_back(packet);
			// convert non-printable characters, other than carriage return, line feed,
			// or tab into periods when displayed.
#if 0
         for (int i = 0; i < dataLength; i++) {
				if ((data[i] >= 32 && data[i] <= 126) || data[i] == 10 || data[i] == 11 || data[i] == 13) {
					dataStr += (char)data[i];
				} else {
					dataStr += ".";
				}
			}
#endif
#if 0
         if (dataLength > 0) {
				cout << dataStr << endl;
			}
#endif
		}
	}
}
#if 0
int main() {
   vector<TCPSequence> sequences;
	pcap_t *descr;
	char errbuf[PCAP_ERRBUF_SIZE];
   string filename = path + "nets31a-cubic.pcap";
   //string filename = path + "nets8b-cubic.pcap";
	// open capture file for offline processing
	descr = pcap_open_offline(filename.c_str(), errbuf);
	if (descr == NULL) {
		cout << "pcap_open_live() failed: " << errbuf << endl;
		return 1;
	}
   
	// start packet processing loop, just like live capture

	if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
		cout << "pcap_loop() failed: " << pcap_geterr(descr);
		return 1;
	}
   int pack_size = pack_list.size();
	cout << "capture finished" << endl;
   sort(pack_list.begin(), pack_list.end(), Comes_Before());

   vector<Packet*>::iterator iter = find_if(pack_list.begin(), pack_list.end(), [](Packet *pack){return pack->ack == 0;});
   int left = (int)pack_list.size();

   while (iter !=pack_list.end()) {
      Packet *first = *iter;
      TCPSequence seq = *new TCPSequence(first);
      seq.pull(pack_list);
      sequences.push_back(seq);
      erase_vec_from_vec(seq.sequence, pack_list);
      left -= seq.sequence.size();
      iter = find_if(++iter, pack_list.end(), [](Packet *pack){return pack->ack == 0;});
   }
   int ret = 0;
   for (auto seq:sequences) {ret += seq.calc_retransmits();}
   cout << (float)ret/(float)pack_size << endl;
   
	return 0;
}


#else
int main() {
   std::string filename, pathname;
   
   struct dirent *filep;
   struct stat filestat;
   DIR *dir;
   
   dir = opendir(path.c_str());
   vector<float> retrans;
   float max = 0;
   std::string max_loss;
   while ((filep = readdir(dir))){
      pack_list = *new vector<Packet*>;
      filename = filep->d_name;
      pathname = path + filep->d_name;
      
      // If the file is a directory (or is in some way invalid) we'll skip it
      if (stat( pathname.c_str(), &filestat )) continue;
      if (S_ISDIR( filestat.st_mode ))         continue;
      if (filename == ".DS_Store")             continue;
      if (filename == "nets07b-reno.pcap")     continue;
      if (filename == "nets11b-reno.pcap")     continue;
      if (filename == "nets12a-cubic.pcap")    continue;
      if (filename == "nets13b-router.pcap")   continue;
      if (filename == "nets21a-reno.pcap")     continue;
      if (filename == "nets21b-router.pcap")   continue;
      if (filename == "nets24bpart1:8.00-8.45-cubic.pcap")  continue;
      if (filename == "nets28b-reno.pcap")     continue;
      if (filename == "nets29a-reno.pcap")     continue;
      if (filename == "nets30b-cubic.pcap")    continue;
      if (filename == "nets30b-reno.pcap")     continue;
      if (filename == "nets31b-cubic.pcap")    continue;
      if (filename == "nets32a-cubic.pcap")    continue;
      if (filename == "nets4b-cubic.pcap")     continue;
      if (filename == "nets5b-router.pcap")    continue;
      if (filename == "nets6b-reno.pcap")      continue;
      
      vector<TCPSequence> sequences;
      pcap_t *descr;
      char errbuf[PCAP_ERRBUF_SIZE];
      // open capture file for offline processing
      cout << filename << endl;
      descr = pcap_open_offline((path + filename).c_str(), errbuf);
      if (descr == NULL) {
         cout << "pcap_open_live() failed: " << errbuf << endl;
         continue;
      }
      
      // start packet processing loop, just like live capture
      
      if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
         cout << "pcap_loop() failed: " << pcap_geterr(descr) << endl;
         continue;
      }
      int pack_size = pack_list.size();
      sort(pack_list.begin(), pack_list.end(), Comes_Before());
      
      vector<Packet*>::iterator iter = find_if(pack_list.begin(), pack_list.end(), [](Packet *pack){return pack->ack == 0;});
      while (iter !=pack_list.end()) {
         Packet *first = *iter;
         TCPSequence seq = *new TCPSequence(first);
         seq.pull(pack_list);
         sequences.push_back(seq);
         erase_vec_from_vec(seq.sequence, pack_list);
         
         iter = find_if(++iter, pack_list.end(), [](Packet *pack){
            return (pack->ack == 0);
         });
      }
      int ret = 0;
      for (auto seq:sequences) {ret += seq.calc_retransmits();}
      if (max < (float)ret/(float)pack_size && pack_size > 0) {
         max = (float)ret/(float)pack_size;
         max_loss = filename;
      }
      cout << (float)ret/(float)pack_size << endl;
      //cout << (float)ret/(float)packs_size << endl;
      if (pack_size > 0) retrans.push_back((float)ret/(float)pack_size);
   }
   cout << retrans << endl;
   cout << "Max: " << max_loss << " at " << max << endl;
   float mean = 0;
   for (auto x:retrans) mean += x;
   mean/=retrans.size();
   float variance = 0;
   for (auto x:retrans) variance += pow(x-mean, 2);
   variance/=retrans.size();
   cout << "Mean: " << mean << " sd: " << sqrtf(variance) << std::endl;
   
   return 0;
}
#endif

