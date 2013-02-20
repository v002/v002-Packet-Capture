/*
 *  v002PacketCaptureProtocol.h
 *  v002PacketCapture
 *
 *  Created by vade on 5/5/09.
 *  Copyright 2009 __MyCompanyName__. All rights reserved.
 *
 */

@protocol v002PacketCaptureProtocol

- (out bycopy NSArray*) packetArray;
- (oneway void) setInterface:(in oneway NSString*) device;
- (oneway void) addPacket:(in oneway NSDictionary*) packet;
- (oneway void) quitHelperTool;
- (oneway void) debug;

@end