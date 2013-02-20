
#import "v002PacketCaptureHelperTool.h"

@implementation AppController

static DistributedPacket *sharedDistributedPacket;

+ (id)sharedDistributedPacket
{
	if (!sharedDistributedPacket)
		sharedDistributedPacket = [[DistributedPacket alloc] init];
	
	return sharedDistributedPacket;
}

- (void) applicationDidFinishLaunching:(NSNotification *)aNotification
{
	NSLog(@"Helper Tool Finished Launching");
	
	dPacket = [AppController  sharedDistributedPacket];

	// publish our distributed object
	NSConnection* connection = [NSConnection defaultConnection];
	[connection setRootObject:dPacket];
	if ([connection registerName:@"info.vade.packetCaptureHelperTool"] == NO) 
	{
		NSLog(@"Error opening NSConnection - exiting");
	}
	else
		NSLog(@"NSConnection Open");	
	
	char dev[] = "en1"; // name of the device to use
	
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
	descr = pcap_open_live(dev,BUFSIZ,1,0,errbuf);
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
	
	@synchronized(sharedDistributedPacket)
	{
		[sharedDistributedPacket addPacket:packetDictionary];
	}
}

- (void) pcapLoopThread
{
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	
//	[NSThread setThreadPriority:1.0];
	
	pcap_loop(descr, 0, v002_PacketHandlerCallback,NULL);
	
	pcap_close(descr);
	
	[pool release];
}

- (void) debugRootObject
{
	[[dPacket mutablePacketArray] addObject:@"This is a test"];
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
int main (int argc, const char * argv[]) {
    NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	
	NSApplication *app = [NSApplication sharedApplication];
	
	AppController *myAppController = [[AppController alloc] init];
	[app setDelegate:myAppController];
	
	[app run];	
	
    [pool release];
	[app release];
	
	return 0;
}

/*	
	// test some pcap functions here.
	char dev[] = "en1"; // name of the device to use
	
	char errbuf[PCAP_ERRBUF_SIZE];
	
	bpf_u_int32 netp;	// ip
	bpf_u_int32 maskp;	// subnet mask
	char* net;
	char* mask;
	struct in_addr addr;
	
	if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1)
	{
		NSLog(@"Can't get netmask for device %s", dev);
	//	return NO;
	}
	
	// get the network address in a human readable form 
	addr.s_addr = netp;
	net = inet_ntoa(addr);
	NSLog(@"Discovered IP is: %s", net);
	
	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	
	NSLog(@"Discovered Netmask is: %s", mask);
	
	
	// try some capturing...
	pcap_t* descr;
		
	descr = pcap_open_live(dev,BUFSIZ,1,0,errbuf);
	if(descr == NULL)
    {
        NSLog(@"pcap_open_live(): %s",errbuf);
		return 0;
    }
	
	// loop to our callback
	pcap_loop(descr, 1000, v002_PacketHandlerCallback,NULL);
	
	*/

// get the network address in a human readable form 
/*	addr.s_addr = netp;
 net = inet_ntoa(addr);
 NSLog(@"Discovered IP is: %s", net);
 
 NSString* hostString = [NSString stringWithCString:net];
 
 addr.s_addr = maskp;
 mask = inet_ntoa(addr);
 
 NSLog(@"Discovered Netmask is: %s", mask);
 NSString* maskString = [NSString stringWithCString:mask];
 
 */
