//
//  ViewController.m
//  socket
//
//  Created by staturnz on 1/24/23.
//

#import "ViewController.h"
#include "../jailbreak.h"
#include "../util.h"

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
    [[UIView appearance] setTintColor:UIColorFromRGB(0x437774)];
    self.log.layer.borderColor = [UIColorFromRGB(0x305256) CGColor];
    self.log.layer.borderWidth = 0.5f;
    self.backgroud.image = [UIImage imageNamed:@"background"];
    self.log.textColor = UIColorFromRGB(0x1d3133);
    
    self.title_label.textColor = UIColorFromRGB(0xF7EBE8);
    self.button.backgroundColor = UIColorFromRGB(0xF7EBE8);
    self.credits.backgroundColor = UIColorFromRGB(0xF7EBE8);
    self.settings.backgroundColor = UIColorFromRGB(0xF7EBE8);
    self.button.titleLabel.textColor = UIColorFromRGB(0x305256);
    
    self.credits.imageView.image = [[UIImage imageNamed:@"news"] imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
    self.settings.imageView.image = [[UIImage imageNamed:@"cog"] imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
    self.credits.imageView.tintColor = UIColorFromRGB(0x305256);
    self.settings.imageView.tintColor = UIColorFromRGB(0x305256);

    [self.navigationController setNavigationBarHidden:YES animated:animated];
    self.backgroud.alpha = 1.0;
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [self.navigationController setNavigationBarHidden:NO animated:animated];
}

- (void)logText:(NSNotification *)noti {
    NSString *str = [NSString stringWithFormat: @"%@%@",  self.log.text, noti.userInfo[@"msg"][0]];
    dispatch_async(dispatch_get_main_queue(), ^{
        self.log.text = str;
        NSRange lastLine = NSMakeRange(self.log.text.length - 2, 1);
        [self.log scrollRangeToVisible:lastLine];
    });
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.log.backgroundColor = [UIColor clearColor];
    self.backgroud.alpha = 1.0;
    
    [nc addObserver:self selector:@selector(logText:) name:@"status" object:nil];
    self.log.text = @"[*] ios 10.x jailbreak (32bit)\n";
    UIBlurEffect *blurEffect = [UIBlurEffect effectWithStyle:UIBlurEffectStyleLight];
    UIVisualEffectView *blurEffectView = [[UIVisualEffectView alloc] initWithEffect:blurEffect];
    blurEffectView.frame = self.view.bounds;
    blurEffectView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self.log insertSubview:blurEffectView atIndex:0];
    NSDictionary* infoDict = [[NSBundle mainBundle] infoDictionary];
    NSString* version = [infoDict objectForKey:@"CFBundleVersion"];
    print_log("[*] made by @staturnzdev\n[*] version: %s\n", version.UTF8String);
        
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
}

- (IBAction)jb:(id)sender {
    self.button.enabled = false;
    [self.button setTitle:@"jailbreaking..." forState:normal];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        uint32_t flags = JB_FLAG_RESPRING;
        if ([[[NSUserDefaults standardUserDefaults] stringForKey:@"tweaks"] isEqual:@"yes"]) flags |= JB_FLAG_TWEAKS;
        if ([[[NSUserDefaults standardUserDefaults] stringForKey:@"restrap"] isEqual:@"yes"]) flags |= JB_FLAG_BOOTSTRAP;
        int ret = run_jailbreak(flags);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            self.button.enabled = true;
            if (ret != 0) [self.button setTitle:@"retry" forState:normal];
            else [self.button setTitle:@"jailbreak" forState:normal];
        });
    });
}


@end
