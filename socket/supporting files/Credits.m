//
//  Credits.m
//  socket
//
//  Created by staturnz on 1/24/23.
//

#import <Foundation/Foundation.h>
#import "Credits.h"

@interface Credits ()
@end

@implementation Credits


#pragma mark - [*]--   Theme Stuff  --[*]

- (void)viewDidLoad {
    [super viewDidLoad];
    NSString *theme = [[NSUserDefaults standardUserDefaults] stringForKey:@"theme"];
    NSLog(@"%@", theme);
    if ([theme isEqual:@"aurora"]) {
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
}


#pragma mark - [*]--   Credit Links  --[*]

-(void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    
    if (indexPath.section == 0) {
        switch(indexPath.row) {
            case 0  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/staturnzz/socket/"]];
                break;
            case 1  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/staturnzz/"]];
                break;
            case 2  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://twitter.com/0x7FF7/"]];
                break;
        }
    }
    
    if (indexPath.section == 2) {
        switch(indexPath.row) {
            case 0  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://twitter.com/_bazad/"]];
                break;
            case 1  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://twitter.com/dora2ios/"]];
                break;
            case 2  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://twitter.com/Jakeashacks/"]];
                break;
            case 3  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://twitter.com/NedWilliamson/"]];
                break;
            case 4  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://twitter.com/planetbeing/"]];
                break;
            case 5  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://twitter.com/REALKJCMEMBER/"]];
                break;
            case 6  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/SongXiaoXi/"]];
                break;
            case 7  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/tihmstar/"]];
                break;
            case 8  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://twitter.com/getZebra/"]];
                break;
        }
    }
}

@end