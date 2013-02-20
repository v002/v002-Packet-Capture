//
//  v002PacketCapturePlugIn.h
//  v002PacketCapture
//
//  Created by vade on 6/20/08.
//  Copyright (c) 2008 __MyCompanyName__. All rights reserved.
//

#import <Quartz/Quartz.h>

// OS X Security framework - do things the right way
#import <SecurityFoundation/SFAuthorization.h>
#import <SystemConfiguration/SystemConfiguration.h>

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

#import "v002PacketCaptureProtocol.h"
#import "DistributedPacket.h"

@interface v002PacketCapturePlugIn : QCPlugIn
{
	AuthorizationRef myAuthorizationRef;	//	for authorizing packet capturing.
	OSStatus myStatus;						//	for authorizing packet capturing.
	AuthorizationItem authItems[2];			//	requested rights. need admin/root for raw socket/promiscuous mode. sounds sexy right?
	
	id proxyObjectFromHelper;			// our packet info from helper tool
}

@property (assign) NSUInteger inputInterfaceIndex;
@property (assign) NSArray * outputPacketInfo;

/*
Declare here the Obj-C 2.0 properties to be used as input and output ports for the plug-in e.g.
@property double inputFoo;
@property(assign) NSString* outputBar;
You can access their values in the appropriate plug-in methods using self.inputFoo or self.inputBar
*/

-(BOOL) testPcap;

@end
