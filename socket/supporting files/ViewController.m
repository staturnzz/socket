//
//  ViewController.m
//  socket
//
//  Created by staturnz on 1/24/23.
//

#import "ViewController.h"
#include "jailbreak.h"
#include <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#define nc [NSNotificationCenter defaultCenter]
#define concat(a,b) [NSString stringWithFormat:a, b]

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UILabel *title_label;
@property (weak, nonatomic) IBOutlet UITextView *log;
@property (weak, nonatomic) IBOutlet UIButton *button;
@property (weak, nonatomic) IBOutlet UIImageView *backgroud;
@property (weak, nonatomic) IBOutlet UIButton *credits;
@property (weak, nonatomic) IBOutlet UIButton *settings;
@end

@implementation ViewController

- (void) viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    
    
#pragma mark - [*]--   Theme Stuff   --[*]
    
    NSString *theme = [[NSUserDefaults standardUserDefaults] stringForKey:@"theme"];
    if ([theme isEqual:@"aurora"]) {
        [[UIView appearance] setTintColor:UIColorFromRGB(0x92B4A7)];
        self.log.layer.borderColor = [UIColorFromRGB(0x92B4A7) CGColor];
        self.backgroud.image = [UIImage imageNamed:@"aurora"];
        self.log.textColor = UIColorFromRGB(0x395756);
    } else if ([theme isEqual:@"ocean"]) {
        [[UIView appearance] setTintColor:UIColorFromRGB(0x0081A7)];
        self.log.layer.borderColor = [UIColorFromRGB(0x0081A7) CGColor];
        self.backgroud.image = [UIImage imageNamed:@"ocean"];
        self.log.textColor = UIColorFromRGB(0xFAFAFF);
    } else if ([theme isEqual:@"geometric"]) {
        [[UIView appearance] setTintColor:UIColorFromRGB(0x71A0F6)];
        self.log.layer.borderColor = [UIColorFromRGB(0x71A0F6) CGColor];
        self.backgroud.image = [UIImage imageNamed:@"geometric"];
        self.log.textColor = UIColorFromRGB(0x273469);
    } else if ([theme isEqual:@"pink"]) {
        [[UIView appearance] setTintColor:UIColorFromRGB(0xB3679B)];
        self.log.layer.borderColor = [UIColorFromRGB(0xB3679B) CGColor];
        self.backgroud.image = [UIImage imageNamed:@"pink"];
        self.log.textColor = UIColorFromRGB(0xFAFAFF);
    }
    
    self.title_label.textColor = UIColorFromRGB(0xF7EBE8);
    self.button.backgroundColor = UIColorFromRGB(0xF7EBE8);
    self.credits.backgroundColor = UIColorFromRGB(0xF7EBE8);
    self.settings.backgroundColor = UIColorFromRGB(0xF7EBE8);
    self.button.titleLabel.textColor = UIColorFromRGB(0x1E1E24);
    [self.navigationController setNavigationBarHidden:YES animated:animated];
}

#pragma mark - [*]--   Basic Stuff   --[*]

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    self.title_label.textColor = UIColorFromRGB(0xF7EBE8);
    [self.navigationController setNavigationBarHidden:NO animated:animated];
}

- (void)logText:(NSNotification *)noti {
    NSString *str = [NSString stringWithFormat: @"%@%@",  self.log.text, noti.userInfo[@"msg"][0]];
    dispatch_async(dispatch_get_main_queue(), ^{
        self.log.text = str;
        NSRange lastLine = NSMakeRange(self.log.text.length - 1, 1);
        [self.log scrollRangeToVisible:lastLine];
    });
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.log.backgroundColor = [UIColor clearColor];

    [nc addObserver:self selector:@selector(logText:) name:@"status" object:nil];
    self.log.text = @"[*] socket jailbreak ios 10 (32bit)\n";

    UIBlurEffect *blurEffect = [UIBlurEffect effectWithStyle:UIBlurEffectStyleLight];
    UIVisualEffectView *blurEffectView = [[UIVisualEffectView alloc] initWithEffect:blurEffect];
    blurEffectView.frame = self.view.bounds;
    blurEffectView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self.log insertSubview:blurEffectView atIndex:0];
    NSDictionary* infoDict = [[NSBundle mainBundle] infoDictionary];
    NSString* version = [infoDict objectForKey:@"CFBundleVersion"];
    status(concat(@"[*] made by staturnz @0x7FF7\n[*] version: %@\n", version));
    

#pragma mark - [*]--   Label & Button UI Stuff   --[*]
    
    self.button.layer.shadowColor = [UIColor blackColor].CGColor;
    self.button.layer.shadowOffset = CGSizeMake(0, 0);
    self.button.layer.shadowOpacity = 0.5;
    self.button.layer.shadowRadius = 2.0;
    
    self.credits.layer.shadowColor = [UIColor blackColor].CGColor;
    self.credits.layer.shadowOffset = CGSizeMake(0, 0);
    self.credits.layer.shadowOpacity = 0.5;
    self.credits.layer.shadowRadius = 2.0;
    
    self.settings.layer.shadowColor = [UIColor blackColor].CGColor;
    self.settings.layer.shadowOffset = CGSizeMake(0, 0);
    self.settings.layer.shadowOpacity = 0.5;
    self.settings.layer.shadowRadius = 2.0;
    
    self.title_label.layer.shadowColor = [UIColor blackColor].CGColor;
    self.title_label.layer.shadowOffset = CGSizeMake(0, 0);
    self.title_label.layer.shadowOpacity = 0.7;
    self.title_label.layer.shadowRadius = 2.0;
    
    self.log.layer.borderWidth = 2.0;
    self.log.layer.cornerRadius = 8;
    
    
#pragma mark - [*]--   First Use Alert   --[*]

    NSString *first_use = [[NSUserDefaults standardUserDefaults] stringForKey:@"first_use"];
    if (![first_use isEqual:@"yes"]) {
        [[NSUserDefaults standardUserDefaults] setObject: @"yes" forKey:@"first_use"];
        [[NSUserDefaults standardUserDefaults] synchronize];
        
        UIAlertController *alertController = [UIAlertController alertControllerWithTitle:@"Welcome"
                                              message:@"It seems this is your first time using Socket.\
                                              Please note this this is currently in beta, so there may be issues.\
                                              If you need help or want to report an issue, feel free to message me\
                                              on twitter @0x7FF7 or github @staturnzz. Enjoy!"
                                              preferredStyle:UIAlertControllerStyleAlert];
        
        UIAlertAction *okayAction = [UIAlertAction actionWithTitle:@"Okay" style:UIAlertActionStyleCancel handler:^(UIAlertAction * _Nonnull action) {}];
        [alertController addAction:okayAction];
        [self presentViewController:alertController animated:YES completion:nil];
    }
}


#pragma mark - [*]--   Do the Jailbreak Button   --[*]

- (IBAction)jb:(id)sender {
    if ([self.button.currentTitle  isEqual: @"respring"]) {
        p_spawn(@"/usr/bin/killall", @[@"backboardd"]);
    } else {
    self.button.enabled = false;
    [self.button setTitle:@"jailbreaking..." forState:normal];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int ret = start_jailbreak();
        dispatch_async(dispatch_get_main_queue(), ^{
            self.button.enabled = true;
            if (ret != 0) [self.button setTitle:@"retry" forState:normal];
            else [self.button setTitle:@"respring" forState:normal];
        });
    });
    }
}


@end
