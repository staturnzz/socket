//
//  Credits.m
//  socket
//
//  Created by staturnz on 1/24/23.
//

#import <Foundation/Foundation.h>
#import "Credits.h"

// news icons by Icons8 https://icons8.com/icons/ios-glyphs
@interface Credits ()
@end
@implementation Credits


#pragma mark - [*]--   Theme Stuff  --[*]

-(void)set_theme:(UIColor*)color {
    [[UIView appearance] setTintColor:color];
    [[UILabel appearance] setTextColor:color];
    [[UISwitch appearance] setTintColor:color];
    [[UISwitch appearance] setOnTintColor:color];
    [self.navigationController.navigationBar setTitleTextAttributes:
       @{NSForegroundColorAttributeName:color}];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    NSString *theme = [[NSUserDefaults standardUserDefaults] stringForKey:@"theme"];
    NSString *darkmode = [[NSUserDefaults standardUserDefaults] stringForKey:@"darkmode"];
    
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
