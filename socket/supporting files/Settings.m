//
//  Settings.m
//  socket
//
//  Created by staturnz on 1/24/23.
//

// cog icons by Icons8 https://icons8.com/icons/ios-glyphs

#import <Foundation/Foundation.h>
#import "Settings.h"
#include <pthread.h>
#include <copyfile.h>
#include <spawn.h>
#include "../util.h"

@interface Settings ()
@property (weak, nonatomic) IBOutlet UINavigationItem *nav_out;
@property (weak, nonatomic) IBOutlet UISwitch *load_tweaks_out;
@property (weak, nonatomic) IBOutlet UISwitch *reinstall_bootstrap_out;
@property (weak, nonatomic) IBOutlet UISwitch *install_untether_out;
@end

@implementation Settings

- (IBAction)load_tweaks:(id)sender {
    if (_load_tweaks_out.on) {
        [[NSUserDefaults standardUserDefaults] setObject:@"yes" forKey:@"tweaks"];
    } else {
        [[NSUserDefaults standardUserDefaults] setObject:@"no" forKey:@"tweaks"];
    }
    [[NSUserDefaults standardUserDefaults] synchronize];
}

- (IBAction)reinstall_bootstrap:(id)sender {
    if (_reinstall_bootstrap_out.on) {
        [[NSUserDefaults standardUserDefaults] setObject:@"yes" forKey:@"restrap"];
    } else {
        [[NSUserDefaults standardUserDefaults] setObject:@"no" forKey:@"restrap"];
    }
    [[NSUserDefaults standardUserDefaults] synchronize];
}

- (IBAction)install_untether:(id)sender {
    if (_install_untether_out.on) {
        if ([[[NSUserDefaults standardUserDefaults] stringForKey:@"untether_alert"] isEqual:@"yes"]) {
            UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Notice"
                message:@"The untether for this device has a base success rate of 93%, meaning ~7% of the time it will not boot to SpringBoard (stuck on Apple logo) and you will need to perform a manual reboot."
                delegate:self cancelButtonTitle:@"Okay" otherButtonTitles:nil];
            [alert show];
        }
        [[NSUserDefaults standardUserDefaults] setObject:@"yes" forKey:@"untether"];
    } else {
        [[NSUserDefaults standardUserDefaults] setObject:@"no" forKey:@"untether"];
    }
    [[NSUserDefaults standardUserDefaults] synchronize];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    NSString *tweaks = [[NSUserDefaults standardUserDefaults] stringForKey:@"tweaks"];
    NSString *restrap = [[NSUserDefaults standardUserDefaults] stringForKey:@"restrap"];
    NSString *untether = [[NSUserDefaults standardUserDefaults] stringForKey:@"untether"];
    
    if ([tweaks isEqual:@"yes"]) [_load_tweaks_out setOn:YES animated:YES];
    if ([restrap isEqual:@"yes"]) [_reinstall_bootstrap_out setOn:YES animated:YES];
    if ([untether isEqual:@"yes"]) [_install_untether_out setOn:YES animated:YES];
    
    UIColor *color = UIColorFromRGB(0x305256);
    [[UIView appearance] setTintColor:color];
    [[UILabel appearance] setTextColor:color];
    [[UISwitch appearance] setTintColor:color];
    [[UISwitch appearance] setOnTintColor:color];
    [self.navigationController.navigationBar setTitleTextAttributes: @{NSForegroundColorAttributeName:color}];
}


@end
