/*
 *  HelperFunctions.h
 *  v002PacketCapture
 *
 *  Created by vade on 5/7/09.
 *  Copyright 2009 __MyCompanyName__. All rights reserved.
 *
 */

#import <Foundation/Foundation.h>
#import <Cocoa/Cocoa.h>

// for libpcap
// see http://www.tcpdump.org/pcap.htm
// and http://yuba.stanford.edu/~casado/pcap/section1.html

#import <stdio.h>
#import <stdlib.h>
#import <pcap.h>  
#import <errno.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <netinet/ip.h>
#import <netinet/ip6.h>
#import <arpa/inet.h>
#import <netinet/if_ether.h>
#import <sys/time.h>
#include <sys/_structs.h>

NSMutableDictionary* helperHandleIP (u_char *args,const struct pcap_pkthdr* pkthdr, const u_char* packet);
NSMutableDictionary* helperHandleEthernet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);

NSMutableDictionary* helperHandleEthernet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{	
	struct ether_header *eptr;  // net/ethernet.h
	
    // lets start with the ether header..
    eptr = (struct ether_header *) packet;
	
	switch (ntohs(eptr->ether_type)) 
	{
		case ETHERTYPE_IP:
//		case ETHERTYPE_IPV6:
			return helperHandleIP(args, pkthdr, packet);
			break;
		case ETHERTYPE_ARP:
		//	NSLog(@"Found ARP Packet");
			break;
		case ETHERTYPE_REVARP:
		//	NSLog(@"Found Rev ARP Packet");
			break;
		default:
			break;
	}

    return nil;
}

NSMutableDictionary* helperHandleIP (u_char *args,const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	@autoreleasepool
	{
		NSMutableDictionary * packetInfoDictionary = [NSMutableDictionary new];
	
		int len;	
		const struct ip* ip;
		u_int length = pkthdr ->len;
		u_int hlen,off,version;
	  		
		// jump pass the ethernet header
		ip = (struct ip*)(packet + sizeof(struct ether_header));
		length -= sizeof(struct ether_header); 
		
		// check to see we have a packet of valid length
		if (length < sizeof(struct ip))
		{
			[packetInfoDictionary release];
			printf("truncated ip %d",length);
			return nil;
		}
		
		len     = ntohs(ip->ip_len);
		hlen    = ip->ip_hl; // IP_HL(ip);	// header length
		version = ip->ip_v;  //IP_V(ip);		// ip version
		
		// check version
		if(version != 4)
		{
		//	fprintf(stdout,"Unknown version %d\n",version);
			[packetInfoDictionary release];
			return nil;
		}
		
		// check header length
		if(hlen < 5 )
		{
		//    fprintf(stdout,"bad-hlen %d \n",hlen);
		}
		
		// see if we have as much packet as we should
		if(length < len)
		{
		//    printf("\ntruncated IP - %d bytes missing\n",len - length);
		}
		
		// Check to see if we have the first fragment
		off = ntohs(ip->ip_off);
		if((off & 0x1fff) == 0 )	// aka no 1's in first 13 bits
		{
	//		struct timeval tv;
	//		tv = pkthdr->ts;
	//		
	//		NSTimeInterval time;
	//		
	//		time = (NSTimeInterval)tv.tv_sec;
	//		
	//		NSDate* date = [NSDate dateWithTimeIntervalSinceNow:time];
	//		
	//		[packetInfoDictionary setValue:[date description] forKey:@"TimeStamp"];
			NSString* source = [NSString stringWithCString:inet_ntoa(ip->ip_src) encoding:NSASCIIStringEncoding];
			NSString* destination = [NSString stringWithCString:inet_ntoa(ip->ip_dst) encoding:NSASCIIStringEncoding];
			
			NSData* packetData = [NSData dataWithBytes:packet length:pkthdr->caplen];
			NSString* dataString = [[NSString alloc] initWithData:packetData encoding:NSASCIIStringEncoding];

			[packetInfoDictionary setValue:source forKey:@"Source" ];
			[packetInfoDictionary setValue:destination forKey:@"Destination"];
			[packetInfoDictionary setValue:@"IPv4" forKey:@"Protocol"];
			[packetInfoDictionary setValue:dataString forKey:@"Data"];

			[dataString release];

//			NSLog(@"Source: %@, Destination: %@", source, destination);
			
			
		//	NSLog(@"%@", packetData);
			
			
			
			//print SOURCE DESTINATION hlen version len offset
		   // fprintf(stdout,"IP: ");
		   // fprintf(stdout,"%s ",
		   //         inet_ntoa(ip->ip_src));
		   // fprintf(stdout,"%s %d %d %d %d\n",
			 //       inet_ntoa(ip->ip_dst),
			   //     hlen,version,len,off);
		}
			
		return packetInfoDictionary;
	}
}