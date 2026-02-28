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


#pragma mark - [*]--   Outlets  --[*]

@interface Settings ()
@property (weak, nonatomic) IBOutlet UINavigationItem *nav_out;
@property (weak, nonatomic) IBOutlet UISwitch *dark_mode_out;
@property (weak, nonatomic) IBOutlet UISwitch *random_theme_out;
@property (weak, nonatomic) IBOutlet UISwitch *auto_respring_out;
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
    }[[NSUserDefaults standardUserDefaults] synchronize];
}

- (IBAction)reinstall_bootstrap:(id)sender {
    if (_reinstall_bootstrap_out.on) {
        [[NSUserDefaults standardUserDefaults] setObject:@"yes" forKey:@"restrap"];
    } else {
        [[NSUserDefaults standardUserDefaults] setObject:@"no" forKey:@"restrap"];
    }[[NSUserDefaults standardUserDefaults] synchronize];
}

- (IBAction)dark_mode:(id)sender {
    if (_dark_mode_out.on) {
        [[NSUserDefaults standardUserDefaults] setObject:@"yes" forKey:@"darkmode"];
        [[UINavigationBar appearance] setBarTintColor:UIColorFromRGB(0x2C2C2E)];
        [[UITableViewCell appearance] setBackgroundColor:UIColorFromRGB(0x2C2C2E)];
        self.tableView.backgroundColor = UIColorFromRGB(0x1C1C1E);
        self.navigationController.navigationBar.barTintColor = UIColorFromRGB(0x2C2C2E);
    } else {
        [[NSUserDefaults standardUserDefaults] setObject:@"no" forKey:@"darkmode"];
        [[UINavigationBar appearance] setBarTintColor:UIColorFromRGB(0xF0E4E9)];
        [[UITableViewCell appearance] setBackgroundColor:UIColorFromRGB(0xF0E4E9)];
        self.tableView.backgroundColor = UIColorFromRGB(0xF7EBE8);
        self.navigationController.navigationBar.barTintColor = UIColorFromRGB(0xF0E4E9);
    }
    self.navigationController.navigationBar.translucent = NO;
    [[UINavigationBar appearance] setTranslucent:NO];
    [self.tableView reloadData];
    [self.view setNeedsDisplay];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

- (IBAction)random_theme:(id)sender {
    if (_random_theme_out.on) {
        [[NSUserDefaults standardUserDefaults] setObject:@"yes" forKey:@"random"];
    } else {
        [[NSUserDefaults standardUserDefaults] setObject:@"no" forKey:@"random"];
    }[[NSUserDefaults standardUserDefaults] synchronize];
}

- (IBAction)auto_respring:(id)sender {
    if (_auto_respring_out.on) {
        [[NSUserDefaults standardUserDefaults] setObject:@"yes" forKey:@"autorespring"];
    } else {
        [[NSUserDefaults standardUserDefaults] setObject:@"no" forKey:@"autorespring"];
    }[[NSUserDefaults standardUserDefaults] synchronize];
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

-(void)set_default:(NSString *)str {
    [[NSUserDefaults standardUserDefaults] setObject:str forKey:@"theme"];
    [[NSUserDefaults standardUserDefaults] synchronize];
}


#pragma mark - [*]--   Theme & Icon Stuff   --[*]

-(void)setIconWithName:(NSString *)name {
   if (@available(iOS 10.3, *)) {
       if ([[UIApplication sharedApplication] supportsAlternateIcons]) {
           NSString *currentIcon = [UIApplication sharedApplication].alternateIconName ?: @"AppIcon";
           if ([currentIcon isEqualToString:name]) {return;}
           if ([name isEqualToString:@"AppIcon"]) name = nil;
           [[UIApplication sharedApplication] setAlternateIconName:name completionHandler:^(NSError * _Nullable error) {
               if (error) {
                   UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Unable to set application icon" message:error.localizedDescription preferredStyle:UIAlertControllerStyleAlert];
                   UIAlertAction *ok = [UIAlertAction actionWithTitle:NSLocalizedString(@"OK", @"") style:UIAlertActionStyleDefault handler:nil];
                   [alert addAction:ok];[self.navigationController presentViewController:alert animated:YES completion:nil];}}];[self.tableView reloadData];
       }
   } else {
       UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Cannot set icon" message:@"Icon changing only works on iOS 10.3+" preferredStyle:UIAlertControllerStyleAlert];
       UIAlertAction *ok = [UIAlertAction actionWithTitle:NSLocalizedString(@"OK", @"") style:UIAlertActionStyleDefault handler:nil];
       [alert addAction:ok];
       [self.navigationController presentViewController:alert animated:YES completion:nil];
   }
}

-(void)change_theme {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Themes" message:@"Please select a theme to use." preferredStyle:UIAlertControllerStyleAlert];
    
    UIAlertAction *aurora = [UIAlertAction actionWithTitle:@"aurora" style:uistyle{[self set_default:@"aurora"];}];
    UIAlertAction *ocean = [UIAlertAction actionWithTitle:@"ocean" style:uistyle{[self set_default:@"ocean"];}];
    UIAlertAction *geometric = [UIAlertAction actionWithTitle:@"geometric" style:uistyle{[self set_default:@"geometric"];}];
    UIAlertAction *pink = [UIAlertAction actionWithTitle:@"pink" style:uistyle{[self set_default:@"pink"];}];
    UIAlertAction *bands = [UIAlertAction actionWithTitle:@"bands" style:uistyle{[self set_default:@"bands"];}];
    UIAlertAction *twist = [UIAlertAction actionWithTitle:@"twist" style:uistyle{[self set_default:@"twist"];}];
    UIAlertAction *cancel = [UIAlertAction actionWithTitle:@"Cancel" style:uistyle{}];
    
    [alert addAction:aurora];[alert addAction:ocean];[alert addAction:geometric];
    [alert addAction:pink];[alert addAction:bands];[alert addAction:twist];
    [alert addAction:cancel];[self presentViewController:alert animated:YES completion:nil];
}

-(void)change_icon {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"App Icon" message:@"Please select an app icon to use." preferredStyle:UIAlertControllerStyleAlert];
    
    UIAlertAction *stock = [UIAlertAction actionWithTitle:@"default" style:uistyle{[self setIconWithName:@"AppIcon"];}];
    UIAlertAction *mint = [UIAlertAction actionWithTitle:@"mint" style:uistyle{[self setIconWithName:@"mint-icon"];}];
    UIAlertAction *legacy = [UIAlertAction actionWithTitle:@"legacy" style:uistyle{[self setIconWithName:@"legacy-icon"];}];
    UIAlertAction *cherry = [UIAlertAction actionWithTitle:@"cherry" style:uistyle{[self setIconWithName:@"cherry-icon"];}];
    UIAlertAction *cancel = [UIAlertAction actionWithTitle:@"Cancel" style:uistyle{}];
    
    [alert addAction:stock];[alert addAction:mint];[alert addAction:legacy];
    [alert addAction:cherry];[alert addAction:cancel];
    [self presentViewController:alert animated:YES completion:nil];
}

-(void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == 1)
        switch(indexPath.row) {case 0:[self change_theme];break;case 1:[self change_icon];break;}
}

-(void)set_theme:(UIColor*)color {
    [[UIView appearance] setTintColor:color];
    [[UILabel appearance] setTextColor:color];
    [[UISwitch appearance] setTintColor:color];
    [[UISwitch appearance] setOnTintColor:color];
    [self.navigationController.navigationBar setTitleTextAttributes:
       @{NSForegroundColorAttributeName:color}];
}


#pragma mark - [*]--   View Stuff   --[*]

- (void)viewDidLoad {
    [super viewDidLoad];
    
    NSString *theme = [[NSUserDefaults standardUserDefaults] stringForKey:@"theme"];
    NSString *darkmode = [[NSUserDefaults standardUserDefaults] stringForKey:@"darkmode"];
    NSString *random = [[NSUserDefaults standardUserDefaults] stringForKey:@"random"];
    NSString *tweaks = [[NSUserDefaults standardUserDefaults] stringForKey:@"tweaks"];
    NSString *restrap = [[NSUserDefaults standardUserDefaults] stringForKey:@"restrap"];
    NSString *autorespring = [[NSUserDefaults standardUserDefaults] stringForKey:@"autorespring"];

    if ([random isEqual:@"yes"]) [_random_theme_out setOn:YES animated:YES];
    if ([tweaks isEqual:@"yes"]) [_load_tweaks_out setOn:YES animated:YES];
    if ([restrap isEqual:@"yes"]) [_reinstall_bootstrap_out setOn:YES animated:YES];
    if ([darkmode isEqual:@"yes"]) [_dark_mode_out setOn:YES animated:YES];
    if ([autorespring isEqual:@"yes"]) [_auto_respring_out setOn:YES animated:YES];

    if ([theme isEqual:@"aura"]) [self set_theme:UIColorFromRGB(0x92B4A7)];
    else if ([theme isEqual:@"ocean"]) [self set_theme:UIColorFromRGB(0x0081A7)];
    else if ([theme isEqual:@"geometric"]) [self set_theme:UIColorFromRGB(0x71A0F6)];
    else if ([theme isEqual:@"pink"]) [self set_theme:UIColorFromRGB(0xB3679B)];
    else if ([theme isEqual:@"bands"]) [self set_theme:UIColorFromRGB(0x82A7A6)];
    else if ([theme isEqual:@"twist"]) [self set_theme:UIColorFromRGB(0x67597A)];
    
    if ([darkmode isEqual:@"yes"]) {
        self.tableView.backgroundColor = UIColorFromRGB(0x1C1C1E);
        [[UITableViewCell appearance] setBackgroundColor:UIColorFromRGB(0x2C2C2E)];
    }
}


@end
