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


@interface Settings ()
@property (weak, nonatomic) IBOutlet UISwitch *load_tweaks_out;
@property (weak, nonatomic) IBOutlet UISwitch *reinstall_bootstrap_out;
@end

@implementation Settings


#pragma mark - [*]--   Setting Toggles   --[*]

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


#pragma mark - [*]--   Common Stuff   --[*]

extern char* const* environ;
int p_spawn_custom(NSString *path, NSArray *arg){
    NSURL *bin = [NSURL fileURLWithPath:path];
    NSMutableArray *p_spawn_arg = [arg mutableCopy];
    [p_spawn_arg insertObject:[bin lastPathComponent] atIndex:0];
    int argc = (int)p_spawn_arg.count +1 ;
    char **args = (char**)calloc(argc, sizeof(char *));
    for (int i = 0; i < p_spawn_arg.count; i++)
        args[i]= (char *)[p_spawn_arg[i] UTF8String];

    posix_spawn_file_actions_t action;
    posix_spawn_file_actions_init(&action);
    pid_t pid = 0;
    int ret = posix_spawn(&pid, bin.path.UTF8String, &action, NULL, args, environ);

    if (ret == 0) if (waitpid(pid, &ret, 0) != -1) {}
    posix_spawn_file_actions_destroy(&action);
    return ret;
}


#pragma mark - [*]--   Theme Stuff   --[*]

NSString *set_theme = @"";
- (void)viewDidLoad {
    [super viewDidLoad];
    NSString *theme = [[NSUserDefaults standardUserDefaults] stringForKey:@"theme"];
    NSLog(@"%@", theme);
    if ([theme isEqual:@"aura"]) {
        [[UIView appearance] setTintColor:UIColorFromRGB(0x92B4A7)];
        [[UILabel appearance] setTextColor:UIColorFromRGB(0x92B4A7)];
        [[UISwitch appearance] setTintColor:UIColorFromRGB(0x92B4A7)];
        [[UISwitch appearance] setOnTintColor:UIColorFromRGB(0x92B4A7)];
        [self.navigationController.navigationBar setTitleTextAttributes:
           @{NSForegroundColorAttributeName:UIColorFromRGB(0x92B4A7)}];
    } else if ([theme isEqual:@"ocean"]) {
        [[UIView appearance] setTintColor:UIColorFromRGB(0x0081A7)];
        [[UILabel appearance] setTextColor:UIColorFromRGB(0x0081A7)];
        [[UISwitch appearance] setTintColor:UIColorFromRGB(0x0081A7)];
        [[UISwitch appearance] setOnTintColor:UIColorFromRGB(0x0081A7)];
        [self.navigationController.navigationBar setTitleTextAttributes:
           @{NSForegroundColorAttributeName:UIColorFromRGB(0x0081A7)}];
    } else if ([theme isEqual:@"geometric"]) {
        [[UIView appearance] setTintColor:UIColorFromRGB(0x71A0F6)];
        [[UILabel appearance] setTextColor:UIColorFromRGB(0x71A0F6)];
        [[UISwitch appearance] setTintColor:UIColorFromRGB(0x71A0F6)];
        [[UISwitch appearance] setOnTintColor:UIColorFromRGB(0x71A0F6)];
        [self.navigationController.navigationBar setTitleTextAttributes:
           @{NSForegroundColorAttributeName:UIColorFromRGB(0x71A0F6)}];
    } else if ([theme isEqual:@"pink"]) {
        [[UIView appearance] setTintColor:UIColorFromRGB(0xB3679B)];
        [[UILabel appearance] setTextColor:UIColorFromRGB(0xB3679B)];
        [[UISwitch appearance] setTintColor:UIColorFromRGB(0xB3679B)];
        [[UISwitch appearance] setOnTintColor:UIColorFromRGB(0xB3679B)];
        [self.navigationController.navigationBar setTitleTextAttributes:
           @{NSForegroundColorAttributeName:UIColorFromRGB(0xB3679B)}];
    }
    
    NSString *tweaks = [[NSUserDefaults standardUserDefaults] stringForKey:@"tweaks"];
    NSString *restrap = [[NSUserDefaults standardUserDefaults] stringForKey:@"restrap"];
    if ([tweaks isEqual:@"yes"]) [_load_tweaks_out setOn:YES animated:YES];
    if ([restrap isEqual:@"yes"]) [_reinstall_bootstrap_out setOn:YES animated:YES];
}


#pragma mark - [*]--   Changes our Theme   --[*]

- (IBAction)theme_swap:(id)sender {

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Title" message:@"Alert Message" preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *theme1 = [UIAlertAction actionWithTitle:@"aurora" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action){
        set_theme = @"aurora";
        [[NSUserDefaults standardUserDefaults] setObject:set_theme forKey:@"theme"];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }];
    UIAlertAction *theme2 = [UIAlertAction actionWithTitle:@"ocean" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action){
        set_theme = @"ocean";
        [[NSUserDefaults standardUserDefaults] setObject:set_theme forKey:@"theme"];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }];
    UIAlertAction *theme3 = [UIAlertAction actionWithTitle:@"geometric" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action){
        set_theme = @"geometric";
        [[NSUserDefaults standardUserDefaults] setObject:set_theme forKey:@"theme"];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }];
    UIAlertAction *theme4 = [UIAlertAction actionWithTitle:@"pink" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action){
        set_theme = @"pink";
        [[NSUserDefaults standardUserDefaults] setObject:set_theme forKey:@"theme"];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }];
    UIAlertAction *cancel = [UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action){
    }];
    
    [alert addAction:theme1];
    [alert addAction:theme2];
    [alert addAction:theme3];
    [alert addAction:theme4];
    [alert addAction:cancel];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
