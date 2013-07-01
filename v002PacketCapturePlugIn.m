//
//  v002PacketCapturePlugIn.m
//  v002PacketCapture
//
//  Created by vade on 6/20/08.
//  Copyright (c) 2008 __MyCompanyName__. All rights reserved.
//

/* It's highly recommended to use CGL macros instead of changing the current context for plug-ins that perform OpenGL rendering */
#import <OpenGL/CGLMacro.h>

#import "v002PacketCapturePlugIn.h"


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

#define	kQCPlugIn_Name				@"v002 Packet Capture"
#define	kQCPlugIn_Description		@"v002 Packet Capture grabs IP data, source, destination, hostname info and outputs as a structure of strings"

@interface v002PacketCapturePlugIn ()

@property (atomic, readwrite, retain) id proxyObjectFromHelper;				// our packet info from helper tool
@property (atomic, readwrite, assign) AuthorizationRef myAuthorizationRef;	//	for authorizing packet capturing.
@property (atomic, readwrite, assign) AuthorizationItem* authItems;			//	requested rights. need admin/root for raw socket/promiscuous mode. sounds sexy right?

@end

@implementation v002PacketCapturePlugIn

@dynamic inputInterfaceIndex;
@dynamic outputPacketInfo;
@dynamic outputIPList;

+ (NSDictionary*) attributes
{
	
	return [NSDictionary dictionaryWithObjectsAndKeys:kQCPlugIn_Name, QCPlugInAttributeNameKey, kQCPlugIn_Description, QCPlugInAttributeDescriptionKey, nil];
}

+ (NSDictionary*) attributesForPropertyPortWithKey:(NSString*)key
{
	NSMutableArray * deviceNames = [NSMutableArray new];
		
	NSArray* devices  = (NSArray*) SCNetworkInterfaceCopyAll();
	
	for(id intefrace in devices)
	{
		[deviceNames addObject:(NSString*)SCNetworkInterfaceGetBSDName((SCNetworkInterfaceRef)intefrace)]; 
	}
	
	[devices release];
	[deviceNames autorelease];
	
	if([key isEqualToString:@"inputInterfaceIndex"])
	{
		return [NSDictionary dictionaryWithObjectsAndKeys:@"Interface Device", QCPortAttributeNameKey,
				[NSNumber numberWithUnsignedInt:0], QCPortAttributeDefaultValueKey,
				[NSNumber numberWithUnsignedInt:[deviceNames count] - 1], QCPortAttributeMaximumValueKey,
				deviceNames, QCPortAttributeMenuItemsKey,
				nil];
	}
		
	if([key isEqualToString:@"outputPacketInfo"])
	{
		return [NSDictionary dictionaryWithObjectsAndKeys:@"Captured Packet Info", QCPortAttributeNameKey, nil];
	}
	
	if([key isEqualToString:@"outputIPList"])
		return @{QCPortAttributeNameKey: @"IP List"};
	
	return nil;
}

+ (QCPlugInExecutionMode) executionMode
{
	return kQCPlugInExecutionModeProvider;
}

+ (QCPlugInTimeMode) timeMode
{
	return kQCPlugInTimeModeIdle;
}

- (id) init
{
	if(self = [super init])
	{
	}
	
	return self;
}

- (void) finalize
{
	[super finalize];
}

- (void) dealloc
{
	[super dealloc];
}

- (BOOL) testPcap
{
	// launch our background process as root somehow.
	NSString* pathToHelperTool = [[NSBundle bundleForClass:[self class]] pathForResource:@"v002PacketCaptureHelperTool" ofType:nil];
	NSLog(@"Helper tool path is: %@", pathToHelperTool);

	FILE *myCommunicationsPipe = NULL;
	char *myArguments[] = {NULL};

//	char path[[pathToHelperTool length] +1];
//	strcmp(path, [pathToHelperTool lossyCString]);
	
	// this needs to be looked at
 	OSStatus myStatus = AuthorizationExecuteWithPrivileges (self.myAuthorizationRef,"/Users/vade/Library/Graphics/Quartz Composer Plug-Ins/v002PacketCapture.plugin/Contents/Resources/v002PacketCaptureHelperTool", kAuthorizationFlagDefaults, myArguments, &myCommunicationsPipe);
	if (myStatus == errAuthorizationSuccess)	
	{
		NSLog(@"Launched helper tool - connecting to Shared Port for IPC");
				
		return YES;
	}
	else
		NSLog(@"Error: %i", myStatus);

	return NO;
}


@end

@implementation v002PacketCapturePlugIn (Execution)

- (BOOL) startExecution:(id<QCPlugInContext>)context
{
	NSError* error;
	//		SFAuthorization *auth = [SFAuthorization authorizationWithFlags:kAuthorizationFlagInteractionAllowed|kAuthorizationFlagExtendRights|kAuthorizationFlagPreAuthorize
	//																 rights:NULL
	//															environment:kAuthorizationEmptyEnvironment];
	
	SFAuthorization *auth = [SFAuthorization authorization];
	
	if(![auth obtainWithRight:"info.v002.v002PacketCapture.init"
						flags:kAuthorizationFlagDefaults|kAuthorizationFlagExtendRights//|kAuthorizationFlagInteractionAllowed//|kAuthorizationFlagPreAuthorize
						error:&error])
	{
		self.myAuthorizationRef = [auth authorizationRef];                        // 3
		AuthorizationExternalForm authExtForm;
		OSStatus status = AuthorizationMakeExternalForm(self.myAuthorizationRef, &authExtForm);    // 4
		if (errAuthorizationSuccess == status)
		{
			NSLog(@"SUCESS - we authorized some shit to do..");
			if([self testPcap])
				NSLog(@"Was able to test pcap!!!");
			else
				NSLog(@"failed testing pcap:(");
			
		}
		else
			NSLog(@"Denied!");
	}
	else
		NSLog(@"Not a fucking chance: %@", error);
		
	return YES;
}

- (void) enableExecution:(id<QCPlugInContext>)context
{	
			
}

- (BOOL) execute:(id<QCPlugInContext>)context atTime:(NSTimeInterval)time withArguments:(NSDictionary*)arguments
{
	if(!self.proxyObjectFromHelper)
	{
		NSConnection* theConnection = [NSConnection connectionWithRegisteredName:@"info.vade.packetCaptureHelperTool" host:nil];
		
		self.proxyObjectFromHelper = [[theConnection rootProxy] retain];
		
		NSLog(@"Proxy description %@", self.proxyObjectFromHelper);
		
		[self.proxyObjectFromHelper setProtocolForProxy:@protocol(v002PacketCaptureProtocol)];
	
	}
	
	self.outputPacketInfo = [self.proxyObjectFromHelper packetArray];
	self.outputIPList = [self.proxyObjectFromHelper ipArray];
	
	return YES;
}

- (void) disableExecution:(id<QCPlugInContext>)context
{
}

- (void) stopExecution:(id<QCPlugInContext>)context
{
	[self.proxyObjectFromHelper quitHelperTool];
}

@end
