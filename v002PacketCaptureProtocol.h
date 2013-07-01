/*
 *  v002PacketCaptureProtocol.h
 *  v002PacketCapture
 *
 *  Created by vade on 5/5/09.
 *  Copyright 2009 __MyCompanyName__. All rights reserved.
 *
 */

@protocol v002PacketCaptureProtocol

- (oneway void) setInterface:(in oneway NSString*) device;

// Buffer of Packets
- (oneway void) addPacket:(in oneway NSDictionary*) packet;
- (out bycopy NSArray*) packetArray;

// Array of Unique IPs
- (out bycopy NSArray*) ipArray;
//- (oneway void) addIP:(in oneway NSString*) ip;

- (oneway void) quitHelperTool;
- (oneway void) debug;

@end