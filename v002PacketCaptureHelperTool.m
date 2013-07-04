
#import "v002PacketCaptureHelperTool.h"



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

@interface AppController ()
{
	pcap_t* descr;
}

@property (atomic, readwrite, retain) NSConnection* connection;

@property (atomic, readwrite, copy) NSString* device;
@property (atomic, readwrite, retain) DistributedPacket* dPacket;

- (void) pcapLoopThread;

@end

@implementation AppController

static DistributedPacket *sharedDistributedPacket;

- (void) applicationDidFinishLaunching:(NSNotification *)aNotification
{
	NSLog(@"Helper Tool Finished Launching");
	
	self.dPacket = [[DistributedPacket alloc] init];

	sharedDistributedPacket = self.dPacket;
	
	// publish our distributed object
	self.connection = [NSConnection new];
	[self.connection setRootObject:self.dPacket];
	
	if ([self.connection registerName:@"info.vade.packetCaptureHelperTool"] == NO) 
	{
		NSLog(@"Error opening NSConnection - exiting");
	}
	else
		NSLog(@"NSConnection Open");	
	
	char dev[] = "en0"; // name of the device to use
	
	char errbuf[PCAP_ERRBUF_SIZE];
	
	bpf_u_int32 netp;	// ip
	bpf_u_int32 maskp;	// subnet mask
/*	char* net;
	char* mask;
	struct in_addr addr;
*/
	
	if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1)
	{
		NSLog(@"Can't get netmask for device %s", dev);
		//	return NO;
	}

	// open our device
	descr = pcap_open_live(dev, BUFSIZ/*65535*/ /*BUFSIZ*/,1,0,errbuf);
	if(descr == NULL)
    {
        NSLog(@"pcap_open_live(): %s",errbuf);
    }

	// start a packet capture thread
	[NSThread detachNewThreadSelector:@selector(pcapLoopThread) toTarget:self withObject:nil];
}
	
// this function handles our dictionary vending and packet inspection.
void v002_PacketHandlerCallback(u_char *useless, const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
//    struct ether_header *eptr;  /* net/ethernet.h */
	
	if(packet == NULL)
    {
		// dinna work *sob*
        NSLog(@"Didn't grab packet");
		return;
	}
		
	NSMutableDictionary* packetDictionary = nil;
	
	packetDictionary = helperHandleEthernet(useless, pkthdr, packet);
	
	/*
	// lets start with the ether header...
    eptr = (struct ether_header *) packet;
	
    // Do a couple of checks to see what packet type we have...
    if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
    {
		// [packetDictionary setValue:@"IP Packet" forKey:@"PacketType"];
		NSLog(@"Ethernet type hex:%x dec:%d is an IP packet", ntohs(eptr->ether_type), ntohs(eptr->ether_type));
    }
	else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
    {
		// [packetDictionary setValue:@"ARP Packet" forKey:@"PacketType"];
		NSLog(@"Ethernet type hex:%x dec:%d is an ARP packet", ntohs(eptr->ether_type),ntohs(eptr->ether_type));
    }
	else
	{
		NSLog(@"Ethernet type %x not IP", ntohs(eptr->ether_type));
    }
	*/

	if(packetDictionary)
	{
		[packetDictionary retain];
		dispatch_async(dispatch_get_main_queue(), ^
		{
			[sharedDistributedPacket addPacket:packetDictionary];
			[packetDictionary release];
		});
		
		[packetDictionary release];
	}
}

- (void) pcapLoopThread
{
	@autoreleasepool
	{
		pcap_loop(descr, -1, v002_PacketHandlerCallback, NULL);
		
		pcap_close(descr);
	}
}

- (void) debug
{
	NSLog(@"Debugging");
}

- (void) quitHelperTool
{
	[[NSApplication sharedApplication] terminate:nil];
}
	

@end

// main run loop.
int main (int argc, const char * argv[])
{
	@autoreleasepool
	{
		NSApplication *app = [NSApplication sharedApplication];
		
		AppController *myAppController = [[AppController alloc] init];

		[app setDelegate:myAppController];
		[app run];
		[app release];
	}
	return 0;
}

