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

- (void)viewDidLoad {
    [super viewDidLoad];
    UIColor *color = UIColorFromRGB(0x305256);
    [[UIView appearance] setTintColor:color];
    [[UILabel appearance] setTextColor:color];
    [[UISwitch appearance] setTintColor:color];
    [[UISwitch appearance] setOnTintColor:color];
    [self.navigationController.navigationBar setTitleTextAttributes: @{NSForegroundColorAttributeName:color}];
}

-(void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == 0) {
        switch(indexPath.row) {
            case 0  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/staturnzz/socket"]];
                break;
            case 1  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/staturnzz"]];
                break;
            case 2  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://x.com/staturnzdev"]];
                break;
        }
    }
    
    if (indexPath.section == 2) {
        switch(indexPath.row) {
            case 0  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/staturnzz"]];
                break;
            case 1  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/kok3shidoll"]];
                break;
            case 2  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/planetbeing"]];
                break;
            case 3  :
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/zbrateam"]];
                break;
        }
    }
}

@end
