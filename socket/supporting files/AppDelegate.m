//
//  AppDelegate.m
//  socket
//
//  Created by staturnz on 1/24/23.
//

#import "AppDelegate.h"
#import <sys/sysctl.h>

@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    [[NSUserDefaults standardUserDefaults] setObject:@"yes" forKey:@"tweaks"];
    [[NSUserDefaults standardUserDefaults] setObject:@"no" forKey:@"restrap"];
    [[NSUserDefaults standardUserDefaults] setObject:@"no" forKey:@"untether_alert"];

    char version_str[64] = {0};
    
    uint32_t version[3] = {0};
    CFDictionaryRef dict = _CFCopySystemVersionDictionary();
    CFStringRef cf_version = CFDictionaryGetValue(dict, CFSTR("ProductVersion"));
    CFStringGetCString(cf_version, version_str, 32, kCFStringEncodingUTF8);
    sscanf(version_str, "%d.%d.%d", &version[0], &version[1], &version[2]);

    if (version[1] < 3) {
        [[NSUserDefaults standardUserDefaults] setObject:@"yes" forKey:@"untether"];
    } else {
        char model[128] = {0};
        size_t size = sizeof(model)-1;
        sysctlbyname("hw.machine", model, &size, NULL, 0);

        if (strstr(model, "iPad") != NULL && version[2] >= 2) {
            [[NSUserDefaults standardUserDefaults] setObject:@"no" forKey:@"untether"];
            [[NSUserDefaults standardUserDefaults] setObject:@"yes" forKey:@"untether_alert"];
        } else {
            [[NSUserDefaults standardUserDefaults] setObject:@"yes" forKey:@"untether"];
            
        }
    }

    [[NSUserDefaults standardUserDefaults] synchronize];
    return YES;
}


- (void)applicationWillResignActive:(UIApplication *)application {
    // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
    // Use this method to pause ongoing tasks, disable timers, and invalidate graphics rendering callbacks. Games should use this method to pause the game.
}


- (void)applicationDidEnterBackground:(UIApplication *)application {
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}


- (void)applicationWillEnterForeground:(UIApplication *)application {
    // Called as part of the transition from the background to the active state; here you can undo many of the changes made on entering the background.
}


- (void)applicationDidBecomeActive:(UIApplication *)application {
    // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}


- (void)applicationWillTerminate:(UIApplication *)application {
    // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}


@end
