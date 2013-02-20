/*
 *  v002PacketCaptureHelperTool.h
 *  v002PacketCapture
 *
 *  Created by vade on 5/7/09.
 *  Copyright 2009 __MyCompanyName__. All rights reserved.
 *
 */

#import <Foundation/Foundation.h>
#import <SecurityFoundation/SFAuthorization.h>
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
#import <arpa/inet.h>
#import <netinet/if_ether.h>

#import "DistributedPacket.h"
#import "HelperFunctions.h"
#import "v002PacketCaptureProtocol.h"

@interface AppController : NSObject
{
	pcap_t* descr;
	
	DistributedPacket* dPacket;
	NSString* device;
}
+ (id)sharedDistributedPacket;
- (void) pcapLoopThread;

@end
