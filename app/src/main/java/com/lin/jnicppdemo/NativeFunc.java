package com.lin.jnicppdemo;

import android.content.Context;

/**
 * Created by lin on 2017/12/16.
 */

public class NativeFunc {

    public static void init(Context context)
    {
        System.loadLibrary("native-lib");
        native_init(context);
    }


    public static native void native_init(Context context);
}
