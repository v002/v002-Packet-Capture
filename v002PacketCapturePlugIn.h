//
//  v002PacketCapturePlugIn.h
//  v002PacketCapture
//
//  Created by vade on 6/20/08.
//  Copyright (c) 2008 __MyCompanyName__. All rights reserved.
//

#import <Quartz/Quartz.h>

@interface v002PacketCapturePlugIn : QCPlugIn

@property (assign) NSUInteger inputInterfaceIndex;
@property (assign) NSArray * outputPacketInfo;
@property (assign) NSArray* outputIPList;

@end
