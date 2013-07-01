//
//  DistributedPacket.m
//  v002PacketCapture
//
//  Created by vade on 5/7/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "DistributedPacket.h"

#define v002_MAX_CAPTURED_PACKETS 50

@interface DistributedPacket ()

@property (atomic, readwrite, retain) NSMutableArray * mutablePacketArray;
@property (atomic, readwrite, retain) NSMutableSet * mutableIPSet;

@end

@implementation DistributedPacket

@synthesize mutablePacketArray;

- (NSString*) description
{
	return @"distributed packet is a distributed piece of shit";
}

- (id) init
{
	if((self = [super init]))
	{
		self.mutablePacketArray = [NSMutableArray array];
		self.mutableIPSet = [NSMutableSet set];
	}
	return self;
}

- (void) dealloc
{
	self.mutableIPSet = nil;
	self.mutablePacketArray = nil;

	[super dealloc];
}

- (out bycopy NSArray*) packetArray
{
	return self.mutablePacketArray;
}

- (oneway void) addPacket:(in oneway NSDictionary*) packet
{
	[self addIP:[packet valueForKey:@"Source"]];
	[self addIP:[packet valueForKey:@"Destination"]];
	
	if([self.mutablePacketArray count] > v002_MAX_CAPTURED_PACKETS)
	{
		[self.mutablePacketArray removeLastObject];
	}
	else
	
		[self.mutablePacketArray insertObject:packet atIndex:0];
}

- (oneway void) addIP:(in oneway NSString*) ip
{
	if(ip)
		[self.mutableIPSet addObject:ip];
}

- (out bycopy NSArray*) ipArray
{
	return [self.mutableIPSet allObjects];
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
