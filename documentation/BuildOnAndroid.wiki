# mongoose on Android

## Introduction 

This is a small guide to help you run mongoose on Android. Currently it is tested on the HTC Wildfire. If you have managed to run it on other devices as well, please comment or drop an email in the mailing list.

Note : You dont need root access to run mongoose on Android.

## Steps 

  * Download the source from the Downloads page.
  * Download the Android NDK from [http://developer.android.com/sdk/ndk/index.html here]
  * Make a folder (e.g. mongoose) and inside that make a folder named "jni".
  * Add mongoose.h, mongoose.c and main.c from the source to the jni folder.
  * Make a new file in the jni folder named "Android.mk". This is the make file for ndk-build.

*Android.mk*
{{{
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE    := mongoose
LOCAL_SRC_FILES := main.c mongoose.c

include $(BUILD_EXECUTABLE)
}}}

  * Run `./ndk-build -C /path/to/mongoose/'

This should generate mongoose/lib/armeabi/mongoose

  * Using the adb tool, push the generated mongoose binary to /data/local folder on device. 
  * From adb shell, navigate to /data/local and execute ./mongoose. 

To test if the server is running fine, visit your web-browser and navigate to 127.0.0.1:8080 You should see the Index of / page.

Here's a screenshot

http://i.imgur.com/bgokp.png

*Notes*
  * jni stands for Java Native Interface. Read up on Android NDK if you want to know how to interact with the native C functions of mongoose in Android Java applications.
  * Download android-sdk for the adb tool.
  * TODO: A Java application that interacts with the native binary or a shared library.
  * There is a [http://code.google.com/p/mongoose/issues/detail?id=217 known issue] with CGI on Android 
