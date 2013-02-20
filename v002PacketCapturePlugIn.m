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

#define	kQCPlugIn_Name				@"v002 Packet Capture"
#define	kQCPlugIn_Description		@"v002 Packet Capture grabs IP data, source, destination, hostname info and outputs as a structure of strings"

@implementation v002PacketCapturePlugIn

/*
Here you need to declare the input / output properties as dynamic as Quartz Composer will handle their implementation
@dynamic inputFoo, outputBar;
*/

@dynamic inputInterfaceIndex, outputPacketInfo;

+ (NSDictionary*) attributes
{
	/*
	Return a dictionary of attributes describing the plug-in (QCPlugInAttributeNameKey, QCPlugInAttributeDescriptionKey...).
	*/
	
	return [NSDictionary dictionaryWithObjectsAndKeys:kQCPlugIn_Name, QCPlugInAttributeNameKey, kQCPlugIn_Description, QCPlugInAttributeDescriptionKey, nil];
}

+ (NSDictionary*) attributesForPropertyPortWithKey:(NSString*)key
{
	/*
	Specify the optional attributes for property based ports (QCPortAttributeNameKey, QCPortAttributeDefaultValueKey...).
	*/	
	NSMutableArray * deviceNames = [NSMutableArray new];
		
	NSArray* devices  = (NSArray*) SCNetworkInterfaceCopyAll();
	
	for(id intefrace in devices)
	{
		[deviceNames addObject:(NSString*)SCNetworkInterfaceGetBSDName((SCNetworkInterfaceRef)intefrace)]; 
	}
	
	if([key isEqualToString:@"inputInterfaceIndex"])
	{
		return [NSDictionary dictionaryWithObjectsAndKeys:@"Interface Device", QCPortAttributeNameKey,
				[NSNumber numberWithUnsignedInt:0], QCPortAttributeDefaultValueKey,
				[NSNumber numberWithUnsignedInt:[deviceNames count] - 1], QCPortAttributeMaximumValueKey,
				[[deviceNames retain] autorelease], QCPortAttributeMenuItemsKey,
				nil];
	}
	
	if([key isEqualToString:@"outputPacketInfo"])
	{
		return [NSDictionary dictionaryWithObjectsAndKeys:@"Captured Packet Info", QCPortAttributeNameKey, nil];
            
	}
	
	return nil;
}

+ (QCPlugInExecutionMode) executionMode
{
	/*
	Return the execution mode of the plug-in: kQCPlugInExecutionModeProvider, kQCPlugInExecutionModeProcessor, or kQCPlugInExecutionModeConsumer.
	*/
	
	return kQCPlugInExecutionModeProcessor;
}

+ (QCPlugInTimeMode) timeMode
{
	/*
	Return the time dependency mode of the plug-in: kQCPlugInTimeModeNone, kQCPlugInTimeModeIdle or kQCPlugInTimeModeTimeBase.
	*/
	
	return kQCPlugInTimeModeNone;
}

- (id) init
{
	if(self = [super init])
	{
		/*
		Allocate any permanent resource required by the plug-in.
		*/
	
		SFAuthorization *auth = [SFAuthorization authorization];
		if (![auth permitWithRight:"info.v002.v002PacketCapture.init" flags:kAuthorizationFlagDefaults|kAuthorizationFlagInteractionAllowed|kAuthorizationFlagExtendRights|kAuthorizationFlagPreAuthorize])    // 2
		//if (![auth permitWithRight:"info.v002.v002PacketCapture2.init" flags:kAuthorizationFlagDefaults|kAuthorizationFlagInteractionAllowed|kAuthorizationFlagExtendRights])    // 2
		{
			myAuthorizationRef = [auth authorizationRef];                        // 3
			AuthorizationExternalForm authExtForm;
			OSStatus status = AuthorizationMakeExternalForm(myAuthorizationRef, &authExtForm);    // 4
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
	
	}
	
	
	return self;
}

- (void) finalize
{
	/*
	Release any non garbage collected resources created in -init.
	*/
	
	[super finalize];
}

- (void) dealloc
{
	/*
	Release any resources created in -init.
	*/
	
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
 	myStatus = AuthorizationExecuteWithPrivileges (myAuthorizationRef,"/Users/vade/Library/Graphics/Quartz Composer Plug-Ins/v002PacketCapture.plugin/Contents/Resources/v002PacketCaptureHelperTool", kAuthorizationFlagDefaults, myArguments, &myCommunicationsPipe);
	if (myStatus == errAuthorizationSuccess)	
	{
		NSLog(@"Launched helper tool - connecting to Shared Port for IPC");
				
		return YES;
	}
	else
		NSLog(@"Error: %ld", myStatus);

	return NO;
}


@end

@implementation v002PacketCapturePlugIn (Execution)

- (BOOL) startExecution:(id<QCPlugInContext>)context
{
	/*
	Called by Quartz Composer when rendering of the composition starts: perform any required setup for the plug-in.
	Return NO in case of fatal failure (this will prevent rendering of the composition to start).
	*/
	return YES;
}

- (void) enableExecution:(id<QCPlugInContext>)context
{	
	NSConnection* theConnection = [NSConnection connectionWithRegisteredName:@"info.vade.packetCaptureHelperTool" host:nil];
	
	proxyObjectFromHelper = [[theConnection rootProxy] retain];
	
	NSLog(@"Proxy description %@", proxyObjectFromHelper);
	
	[proxyObjectFromHelper setProtocolForProxy:@protocol(v002PacketCaptureProtocol)];
		
}

- (BOOL) execute:(id<QCPlugInContext>)context atTime:(NSTimeInterval)time withArguments:(NSDictionary*)arguments
{	

	//[proxyObjectFromHelper debug];
	
	@synchronized(proxyObjectFromHelper)
	{
		self.outputPacketInfo = [proxyObjectFromHelper packetArray]; //[NSArray arrayWithObjects:testPacket1, testPacket2, testPacket3, nil];
	}
	return YES;
}

- (void) disableExecution:(id<QCPlugInContext>)context
{
	/*
	Called by Quartz Composer when the plug-in instance stops being used by Quartz Composer.
	*/
}

- (void) stopExecution:(id<QCPlugInContext>)context
{
	[proxyObjectFromHelper quitHelperTool];
	
	/*
	Called by Quartz Composer when rendering of the composition stops: perform any required cleanup for the plug-in.
	*/
}

@end
