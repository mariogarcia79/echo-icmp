// ------------------------------------------------
// ICMP-IP Header File.
//
// Author: Jesus Camara (jesus.camara@infor.uva.es)
// ------------------------------------------------

// Network Libraries
#include<netinet/ip.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<arpa/inet.h>
#include<netdb.h>

#define LEN 64 // Payload Size

/* IPv4 Header Definition
 *
   |  4 bits  |  4 bits  |       8 bits        |  3 bits  |           13 bits             |
   | ======== | ======== | =================== | ======================================== |
   |  Version |    HL	 |   Type of Service   |               Total Length               |
   | ------------------------------------------------------------------------------------ |
   |                Identifier                 |   Flags  |        Fragment Offset        |
   | ------------------------------------------------------------------------------------ |
   |     Time-to-Live    |       Protocol      |              Header Checksum             |
   | ------------------------------------------------------------------------------------ |
   |                                     Source Address                                   |
   | ------------------------------------------------------------------------------------ |
   |                                  Destination Address                                 |
   | ------------------------------------------------------------------------------------ |
 */
typedef struct sIPHeader {
		uint8_t vhl;				// IP_Version + Header_Length
		uint8_t tos;				// Type of Service
		int16_t tlength;			// Total Datagram Length.
		int16_t did;				// Datagram ID.
		int16_t foffset;			// Flag + Fragment_Offset
		uint8_t ttl;				// Time-to-Live
		uint8_t hlproto;			// Higher-Level Protocol.
		uint16_t hchecksum;			// Header Checksum Value.
		struct in_addr srcAddr;		// Source IP Address
		struct in_addr dstAddr;		// Destination IP Address
} IPHeader;

/* ICMP Header Definition
 *
	|     1 byte    |     1 byte    |     		 2 bytes     	    |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|      Type	    |      Code	    |            Checksum           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct sICMPHeader {
		uint8_t type;			// Type of ICMP Message
		uint8_t code;			// Code Related to Type
		uint16_t checksum;		// Checksum of the ICMP Message
} ICMPHeader;

/*	ICMP Echo
 *
	|     1 byte    |     1 byte    |     		 2 bytes     	    |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|      Type	    |      Code	    |            Checksum           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|           Identifier          |         Sequence Number       |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                   Payload (variable length)                   |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct sEcho {
		ICMPHeader icmpHdr;		// ICMP Header
		uint16_t  id;			// Process ID.
		uint16_t  sequence;		// Sequence Number
		char  payload[LEN];		// Arbitrary String
} Echo;

/*  ICMP Echo Reply
 *
	|			   20 bytes					|				Variable				| 
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|      		   IP Header				|             ICMP Message				|
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct sEchoReply {
		IPHeader IPHdr;		// IP Header
		Echo   echoMsg;		// ICMP Message
} EchoReply;