#pragma once
#pragma pack(1)

#include <cstdint>
#include <cstring>
#include <vector>

using namespace std;

// ipTIME A2000UA-4dBi
struct Radiotap {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint32_t present;
    uint32_t present2;
    uint32_t present3;
    uint8_t flag;
    uint8_t dataRate;
    uint16_t channelFreq;
    uint16_t channelFlag;
    uint8_t anteSig;
    uint8_t pad2;
    uint16_t sigQual;
    uint16_t RXFlag;
    uint8_t anteSig0;
    uint8_t antenna0;
    uint8_t anteSig1;
    uint8_t antenna1;
};

struct TransmitRadiotap {
    uint8_t version = 0x00;
    uint8_t pad = 0x00;
    uint16_t len = 0x08;
    uint32_t present = 0x00000000;
};

struct Dot11Frame {
    uint8_t type;
    uint8_t flag;
};

struct FixedParameter {
    uint64_t timestamp;
    uint16_t beaconInterval;
    uint16_t capacityInfo;
};

struct TaggedParameter {
    uint8_t tagNumber;
    uint8_t len;
    uint8_t data[];
};

struct CSAParameter {
    // CSAParameter() : TaggedParameter{0x25, 0x03} {}

    uint8_t tagNumber = 0x25;
    uint8_t len = 0x03;
    uint8_t channelSwitchMode = 0x01;
    uint8_t newChannelNumber;
    uint8_t channelSwitchCount = 0x03;
};

struct BeaconFrame : Dot11Frame {
    uint16_t duration;
    uint8_t destAddr[6];
    uint8_t sourAddr[6];
    uint8_t BSSID[6];
    uint16_t seqControl;
    struct FixedParameter fixedParameter;
};

struct TestPacket {
    Radiotap radiotap;
    BeaconFrame beaconFrame;
    unsigned char taggedParameters[1024];
    // int packetLen;
};
