//
//  DistributedPacket.h
//  v002PacketCapture
//
//  Created by vade on 5/7/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "v002PacketCaptureProtocol.h"

@interface DistributedPacket : NSObject <v002PacketCaptureProtocol>
{
	NSMutableArray * mutablePacketArray;
}

@property (retain, readwrite) NSMutableArray * mutablePacketArray;

// protocol requirements
- (out bycopy NSArray*) packetArray;
- (oneway void) setInterface:(in oneway NSString*) device;
- (oneway void) addPacket:(in oneway NSDictionary*) packet;

// custom methods
- (oneway void) quitHelperTool;
- (oneway void) debug;


@end
