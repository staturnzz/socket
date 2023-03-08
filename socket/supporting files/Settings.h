//
//  Settings.h
//  socket
//
//  Created by staturnz on 1/24/23.
//

#import <UIKit/UIKit.h>

@interface Settings : UITableViewController
#define UIColorFromRGB(rgbValue) [UIColor colorWithRed:((float)((rgbValue & 0xFF0000) >> 16))/255.0 green:((float)((rgbValue & 0xFF00) >> 8))/255.0 blue:((float)(rgbValue & 0xFF))/255.0 alpha:1.0]
#define uistyle UIAlertActionStyleDefault handler:^(UIAlertAction *action)
@end

