android_run_root_shell
======================

This code is still ugly, please re-write it and send pull-requests, if you want to use this.


Building
========

* Download the Android Native Development Kit (NDK): http://developer.android.com/tools/sdk/ndk/index.html#Downloads

* Extract into some directory and put that in your path: 
	`export PATH=ANDK_DIR:$PATH`

* In another directory clone this repo: 
	`git clone --recursive https://github.com/android-rooting-tools/android_run_root_shell`

* Change to the directory where the repo was cloned
	`cd android_run_root_shell`

* To start build process use the following
	`ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk`

* If all goes well you will get the compiled binary at:
	`./libs/armeabi/run_root_shell`


Running
=======

* Download the Android Software Development Kit (SDK) ADT Bundle: http://developer.android.com/sdk/index.html

* Extract into some directory and put the platform-tools folder in your path:
	`export PATH=SDK_DIR/sdk/platform-tools/:$PATH`

* Change to the directory with the compiled run_root_shell binary (see above)

* Connect your Android device through USB (click Cancel if it asks to enable USB storage; charging only is the correct mode) and enable USB debugging on the device.

* Start the adb server on your computer:
	`sudo adb start-server`

* Transfer run_root_shell to a temporary directory on the phone:
	`adb push run_root_shell /data/local`

* Ensure that run_root_shell has execute permissions:
	`adb shell chmod 777 /data/local/run_root_shell`

* Run the command on the phone:
	`adb shell /data/local/run_root_shell`
