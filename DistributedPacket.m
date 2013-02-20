//
//  DistributedPacket.m
//  v002PacketCapture
//
//  Created by vade on 5/7/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "DistributedPacket.h"

#define v002_MAX_CAPTURED_PACKETS 50

@implementation DistributedPacket

@synthesize mutablePacketArray;

- (NSString*) description
{
	return @"distributed packet is a distributed piece of shit";
}

- (id) init
{
	if(![super init])
		return nil;
	
	[self setMutablePacketArray:[NSMutableArray array]];
	
	return self;
}

- (out bycopy NSArray*) packetArray
{
	return mutablePacketArray;
}

- (oneway void) addPacket:(in oneway NSDictionary*) packet
{
	if([mutablePacketArray count] > v002_MAX_CAPTURED_PACKETS)
	{
		[mutablePacketArray insertObject:packet atIndex:0];
	}
	else
	
		[mutablePacketArray addObject:packet];
}


- (oneway void) setInterface:(in oneway NSString*) device
{
	// set the device to be monitored by pcap
	NSLog(@"Set Device: %@", device);
}

- (oneway void) quitHelperTool
{
	[[NSApplication sharedApplication] terminate:nil];
}
- (oneway void) debug
{
	NSLog(@"Debugging");
}


@end
