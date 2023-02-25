//
//  main.m
//  socket
//
//  Created by staturnz on 1/24/23.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#include <dlfcn.h>
int (*dsystem)(const char *) = 0;

int main(int argc, char * argv[]) {
    dsystem = dlsym(RTLD_DEFAULT,"system");
    NSString * appDelegateClassName;
    @autoreleasepool {
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
