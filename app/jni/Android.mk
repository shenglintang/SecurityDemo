LOCAL_PATH:= $(call my-dir)

#清除之前的一些系统变量
include $(CLEAR_VARS)
LOCAL_LDLIBS    := -lm -llog
# 编译的源文件
LOCAL_SRC_FILES:=native-lib.cpp

# 编译生成的目标对象  用来给java调用的模块名，
LOCAL_MODULE := native-lib

#指明要编译成动态库
include $(BUILD_SHARED_LIBRARY)