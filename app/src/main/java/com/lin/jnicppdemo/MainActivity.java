package com.lin.jnicppdemo;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Log;

import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.util.Locale;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Log.e("lin", "isWifiProxy(this)= " + isWifiProxy(this));
        //release模式下验证签名
        if (BuildConfig.CHECK_SINATURE) {
        }
        NativeFunc.init(this);
        //设置绕过代理防止被抓包
        OkHttpClient httpClient = new OkHttpClient().newBuilder().proxy(java.net.Proxy.NO_PROXY).build();
        Request req = new Request.Builder().url("https://www.baidu.com").build();
        Response response = null;
        CombatDecompile();

    }

    private void CombatDecompile() {
        //检测是否开启debug
        Log.e("lin", "android.os.Debug.isDebuggerConnected() = " + android.os.Debug.isDebuggerConnected() );
        if (android.os.Debug.isDebuggerConnected()){
//            System.exit(0);
        }
    }

    public static String getProp(Context context, String property) {
        try {
            ClassLoader cl = context.getClassLoader();
            Class SystemProperties = cl.loadClass("android.os.SystemProperties");
            Method method = SystemProperties.getMethod("get", String.class);
            Object[] params = new Object[1];
            params[0] = new String(property);
            return (String)method.invoke(SystemProperties, params);
        } catch (Exception e) {
            return null;
        }
    }
    /**
     * 获取应用的sha1值
     *
     * @param context
     * @return
     */
    public String getSha1Value(Context context) {
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), PackageManager.GET_SIGNATURES);
            byte[] cert = info.signatures[0].toByteArray();
            MessageDigest md = MessageDigest.getInstance("SHA1");
            byte[] publicKey = md.digest(cert);
            StringBuffer hexString = new StringBuffer();
            for (int i = 0; i < publicKey.length; i++) {
                String appendString = Integer.toHexString(0xFF & publicKey[i])
                        .toUpperCase(Locale.US);
                if (appendString.length() == 1)
                    hexString.append("0");
                hexString.append(appendString);
            }
            String result = hexString.toString();
            return result.substring(0, result.length());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 判断设备 是否使用代理上网
     *
     * @param context
     * @return
     */
    private boolean isWifiProxy(Context context) {
        // 是否大于等于4.0
        final boolean IS_ICS_OR_LATER = Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH;
        String proxyAddress;
        int proxyPort;
        if (IS_ICS_OR_LATER) {
            proxyAddress = System.getProperty("http.proxyHost");
            String portStr = System.getProperty("http.proxyPort");
            proxyPort = Integer.parseInt((portStr != null ? portStr : "-1"));
        } else {
            proxyAddress = android.net.Proxy.getHost(context);
            proxyPort = android.net.Proxy.getPort(context);
        }
        return (!TextUtils.isEmpty(proxyAddress)) && (proxyPort != -1);
    }

}
