package macapp

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa
#include <stdlib.h>
#import <Cocoa/Cocoa.h>

static char *pnURL = NULL;
static int pnOpened = 0;

@interface PNLaunchHandler : NSObject
@end

@implementation PNLaunchHandler
- (void)getURL:(NSAppleEventDescriptor *)event withReplyEvent:(NSAppleEventDescriptor *)reply {
	NSString *url = [[event paramDescriptorForKeyword:keyDirectObject] stringValue];
	if (url != nil && pnURL == NULL) {
		pnURL = strdup([url UTF8String]);
	}
}
- (void)openApp:(NSAppleEventDescriptor *)event withReplyEvent:(NSAppleEventDescriptor *)reply {
	pnOpened = 1;
}
@end

// pnWaitLaunch pumps the event loop until the launch Apple Event (open application, or get URL) arrives or the
// timeout passes. It returns the URL, to be freed, or NULL.
static char *pnWaitLaunch(double timeout) {
	@autoreleasepool {
		[NSApplication sharedApplication];
		[NSApp setActivationPolicy:NSApplicationActivationPolicyProhibited];
		[NSApp finishLaunching];
		static PNLaunchHandler *handler;
		handler = [PNLaunchHandler new];
		NSAppleEventManager *m = [NSAppleEventManager sharedAppleEventManager];
		[m setEventHandler:handler andSelector:@selector(getURL:withReplyEvent:) forEventClass:kInternetEventClass andEventID:kAEGetURL];
		[m setEventHandler:handler andSelector:@selector(openApp:withReplyEvent:) forEventClass:kCoreEventClass andEventID:kAEOpenApplication];
		[m setEventHandler:handler andSelector:@selector(openApp:withReplyEvent:) forEventClass:kCoreEventClass andEventID:kAEReopenApplication];
		NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
		while (pnURL == NULL && !pnOpened && [deadline timeIntervalSinceNow] > 0) {
			NSEvent *e = [NSApp nextEventMatchingMask:NSEventMaskAny
			                                untilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]
			                                   inMode:NSDefaultRunLoopMode
			                                  dequeue:YES];
			if (e != nil) {
				[NSApp sendEvent:e];
			}
		}
		char *url = pnURL;
		pnURL = NULL;
		return url;
	}
}
*/
import "C"

import (
	"runtime"
	"time"
	"unsafe"
)

// Wait returns how the app was launched. It must run on the main thread, before anything else uses AppKit; after the
// timeout, a launch without a link is assumed.
func Wait(timeout time.Duration) Launch {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	url := C.pnWaitLaunch(C.double(timeout.Seconds()))
	if url == nil {
		return Launch{}
	}
	defer C.free(unsafe.Pointer(url))
	return Launch{URL: C.GoString(url)}
}
