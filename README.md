android_run_root_shell
======================

This code is still ugly, please re-write it and send pull-requests, if you want to use this.

Building
========

* Download Android Native Development Kit (NDK): http://developer.android.com/tools/sdk/ndk/index.html#Downloads
* Extract into some directory and put that in your path: export PATH=ANDK_DIR:$PATH
* In another directory: git clone --recursive https://github.com/android-rooting-tools/android_run_root_shell
* cd android_run_root_shell
* ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk
