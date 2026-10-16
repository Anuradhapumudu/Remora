// Creates a temporary virtual display for N seconds, then removes it — a stand-in
// for plugging/unplugging a monitor on a single-display Mac (Phase 2 Q4).
//
// Uses Apple's PRIVATE CGVirtualDisplay class (the same one the open-source DeskPad
// app uses). Nothing is installed; the display exists only while this process runs.
//
//   clang -fobjc-arc -framework Foundation -framework CoreGraphics \
//         scripts/macos/virtual-display.m -o target/virtual-display
//   target/virtual-display 20        # prints the new display ID, removes it after 20 s
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

// Private interfaces (declarations only; classes are looked up at runtime).
@interface CGVirtualDisplayDescriptor : NSObject
@property(retain, nonatomic) dispatch_queue_t queue;
@property(retain, nonatomic) NSString *name;
@property(nonatomic) unsigned int maxPixelsHigh;
@property(nonatomic) unsigned int maxPixelsWide;
@property(nonatomic) CGSize sizeInMillimeters;
@property(nonatomic) unsigned int serialNum;
@property(nonatomic) unsigned int productID;
@property(nonatomic) unsigned int vendorID;
@end
@interface CGVirtualDisplayMode : NSObject
- (instancetype)initWithWidth:(unsigned int)w height:(unsigned int)h refreshRate:(double)r;
@end
@interface CGVirtualDisplaySettings : NSObject
@property(retain, nonatomic) NSArray *modes;
@property(nonatomic) unsigned int hiDPI;
@end
@interface CGVirtualDisplay : NSObject
- (instancetype)initWithDescriptor:(CGVirtualDisplayDescriptor *)descriptor;
- (BOOL)applySettings:(CGVirtualDisplaySettings *)settings;
@property(readonly, nonatomic) unsigned int displayID;
@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        int seconds = argc > 1 ? atoi(argv[1]) : 20;
        Class D = NSClassFromString(@"CGVirtualDisplayDescriptor");
        Class M = NSClassFromString(@"CGVirtualDisplayMode");
        Class S = NSClassFromString(@"CGVirtualDisplaySettings");
        Class V = NSClassFromString(@"CGVirtualDisplay");
        if (!D || !M || !S || !V) {
            fprintf(stderr, "CGVirtualDisplay is not available on this macOS\n");
            return 1;
        }
        CGVirtualDisplayDescriptor *desc = [[D alloc] init];
        desc.queue = dispatch_get_main_queue();
        desc.name = @"Remora Test Display";
        desc.maxPixelsWide = 1920;
        desc.maxPixelsHigh = 1080;
        desc.sizeInMillimeters = CGSizeMake(530, 300);
        desc.serialNum = 0x5245;   // arbitrary test IDs
        desc.productID = 0x4D4F;
        desc.vendorID = 0x5241;
        CGVirtualDisplay *display = [[V alloc] initWithDescriptor:desc];
        CGVirtualDisplaySettings *settings = [[S alloc] init];
        settings.hiDPI = 0;
        settings.modes = @[ [[M alloc] initWithWidth:1920 height:1080 refreshRate:60] ];
        if (!display || ![display applySettings:settings]) {
            fprintf(stderr, "could not create the virtual display\n");
            return 1;
        }
        printf("created virtual display %u; removing it in %d s\n", display.displayID, seconds);
        fflush(stdout);
        [[NSRunLoop mainRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:seconds]];
        display = nil;  // releasing the object removes the display
        [[NSRunLoop mainRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1]];
        printf("removed\n");
    }
    return 0;
}
