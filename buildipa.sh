#!/bin/bash
xcodebuild clean build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO -sdk iphoneos
strip build/Release-iphoneos/socket.app/socket
mkdir build/Release-iphoneos/Payload
mv build/Release-iphoneos/socket.app build/Release-iphoneos/Payload
ditto -c -k --sequesterRsrc --keepParent build/Release-iphoneos/Payload socket.ipa

