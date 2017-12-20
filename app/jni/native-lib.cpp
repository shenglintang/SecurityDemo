
#include "jni.h"
#include "com_lin_jnicppdemo_NativeFunc.h"
#include "string.h"
#include "stddef.h"
#include "stdio.h"
#include "Log.h"

#include "unistd.h"
#include "sys/ptrace.h"
#include "sys/types.h"
#include "dirent.h"
#include "stdlib.h"
#include "elf.h"
#include "sys/inotify.h"

const char *app_signature_sha1="C33D9C9F6A6354F4E30A4D5274FC1AF227EC0104";
const char HexCode[]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

JNIEXPORT void JNICALL
Java_com_lin_jnicppdemo_NativeFunc_native_1init
  (JNIEnv *env, jclass clz, jobject context_object){

   jclass context_class = env->GetObjectClass(context_object);
    //context.getPackageManager()
    jmethodID methodId = env->GetMethodID(context_class, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject package_manager_object = env->CallObjectMethod(context_object, methodId);
    if (package_manager_object == NULL) {
        return;
    }
       LOGE("getPackageManager() success!");

    //context.getPackageName()
    methodId = env->GetMethodID(context_class, "getPackageName", "()Ljava/lang/String;");
    jstring package_name_string = (jstring)env->CallObjectMethod(context_object, methodId);
    if (package_name_string == NULL) {
        return ;
    }
       LOGE("getPackageName() success!");
    env->DeleteLocalRef(context_class);

    //PackageManager.getPackageInfo(Sting, int)
    //public static final int GET_SIGNATURES= 0x00000040;
    jclass pack_manager_class = env->GetObjectClass(package_manager_object);
    methodId = env->GetMethodID(pack_manager_class, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    env->DeleteLocalRef(pack_manager_class);
    jobject package_info_object = env->CallObjectMethod(package_manager_object, methodId, package_name_string, 0x40);
    if (package_info_object == NULL) {
        return ;
    }
        LOGE("getPackageInfo() success!");
    env->DeleteLocalRef(package_manager_object);

    //PackageInfo.signatures[0]
        jclass package_info_class = env->GetObjectClass(package_info_object);
        jfieldID fieldId = env->GetFieldID(package_info_class, "signatures", "[Landroid/content/pm/Signature;");
        env->DeleteLocalRef(package_info_class);
        jobjectArray signature_object_array = (jobjectArray)env->GetObjectField(package_info_object, fieldId);
        if (signature_object_array == NULL) {
            return ;
        }
             LOGE("getsignatures() success!");
        jobject signature_object = env->GetObjectArrayElement(signature_object_array, 0);
        env->DeleteLocalRef(package_info_object);

        //Signature.toByteArray()
        jclass signature_class = env->GetObjectClass(signature_object);
        methodId = env->GetMethodID(signature_class, "toByteArray", "()[B");
        env->DeleteLocalRef(signature_class);
        jbyteArray signature_byte = (jbyteArray) env->CallObjectMethod(signature_object, methodId);


        //new ByteArrayInputStream
        jclass byte_array_input_class=env->FindClass("java/io/ByteArrayInputStream");
        methodId=env->GetMethodID(byte_array_input_class,"<init>","([B)V");
        jobject byte_array_input=env->NewObject(byte_array_input_class,methodId,signature_byte);
        env->DeleteLocalRef(byte_array_input_class);
        //CertificateFactory.getInstance("X.509")
        jclass certificate_factory_class=env->FindClass("java/security/cert/CertificateFactory");
        methodId=env->GetStaticMethodID(certificate_factory_class,"getInstance","(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
        jstring x_509_jstring=env->NewStringUTF("X.509");
        jobject cert_factory=env->CallStaticObjectMethod(certificate_factory_class,methodId,x_509_jstring);

        //certFactory.generateCertificate(byteIn);
        methodId=env->GetMethodID(certificate_factory_class,"generateCertificate",("(Ljava/io/InputStream;)Ljava/security/cert/Certificate;"));
        jobject x509_cert=env->CallObjectMethod(cert_factory,methodId,byte_array_input);
        env->DeleteLocalRef(certificate_factory_class);
        //cert.getEncoded()
        jclass x509_cert_class=env->GetObjectClass(x509_cert);
        methodId=env->GetMethodID(x509_cert_class,"getEncoded","()[B");
        jbyteArray cert_byte=(jbyteArray)env->CallObjectMethod(x509_cert,methodId);
        env->DeleteLocalRef(x509_cert_class);
        //MessageDigest.getInstance("SHA1")
        jclass message_digest_class=env->FindClass("java/security/MessageDigest");
        methodId=env->GetStaticMethodID(message_digest_class,"getInstance","(Ljava/lang/String;)Ljava/security/MessageDigest;");
        jstring sha1_jstring=env->NewStringUTF("SHA1");
        jobject sha1_digest=env->CallStaticObjectMethod(message_digest_class,methodId,sha1_jstring);

        //sha1.digest (certByte)
        methodId=env->GetMethodID(message_digest_class,"digest","([B)[B");
        jbyteArray sha1_byte=(jbyteArray)env->CallObjectMethod(sha1_digest,methodId,cert_byte);
        env->DeleteLocalRef(message_digest_class);

        //toHexString
        jsize array_size=env->GetArrayLength(sha1_byte);
        jbyte* sha1 =env->GetByteArrayElements(sha1_byte,NULL);
        char *hex_sha=new char[array_size*2+1];
        for (int i = 0; i <array_size ; ++i) {
            hex_sha[2*i]=HexCode[((unsigned char)sha1[i])/16];
            hex_sha[2*i+1]=HexCode[((unsigned char)sha1[i])%16];
        }
        hex_sha[array_size*2]='\0';
        //比较签名
        if (strcmp(hex_sha,app_signature_sha1)==0)
        {
           LOGE("验证通过");
        } else{
//            ThrowRuntimeExcption(env,"验证失败");
        }
        return ;
  };

//方法一：附加到自身 让ida附加不上 无法实现调试
void anti_debug01(){
    ptrace(PTRACE_TRACEME,0,0,0);
    LOGE("%s","antidebug01 run");
}
//方法三：检测常用的端口
void anti_debug03(){
    const int bufsize=1024;
    char filename[bufsize];
    char line [bufsize];
    int pid=getpid();
    FILE *fp;
    sprintf(filename,"proc/net/tcp");//C语言sprintf()函数：将格式化的数据写入字符串
    fp=fopen(filename,"r");//
    if (fp!= NULL){
        while(fgets(line,bufsize,fp)){
            if(strncmp(line,"5D8A",4)==0){
                int ret=kill(pid,SIGKILL);
                }
        }
    }
    fclose(fp);//关闭流
}


//方法六：inotify检测
void anti_debug06(){
    const int MAXLEN = 2048;
    int ppid =getpid();
    char buf[1024],readbuf[MAXLEN];
    int pid, wd, ret,len,i;
    int fd;
    fd_set readfds;
    //防止调试子进程
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    fd =  inotify_init();
    sprintf(buf, "/proc/%d/maps",ppid);

    //wd = inotify_add_watch(fd, "/proc/self/mem", IN_ALL_EVENTS);
    wd = inotify_add_watch(fd, buf, IN_ALL_EVENTS);
      LOGE("wd = %d",wd);
    if (wd < 0) {
        LOGE("can't watch %s",buf);
        return;
    }
    while (true) {
        i = 0;
        //注意要对fd_set进行初始化
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        //第一个参数固定要+1，第二个参数是读的fdset，第三个是写的fdset，最后一个是等待的时间
        //最后一个为NULL则为阻塞
        //select系统调用是用来让我们的程序监视多个文件句柄的状态变化
        ret = select(fd + 1, &readfds, 0, 0, 0);
        LOGE("ret = %d",ret);
        if (ret == -1)
            break;
        if (ret) {
            len = read(fd,readbuf,MAXLEN);
            while(i < len){
                //返回的buf中可能存了多个inotify_event
                struct inotify_event *event = (struct inotify_event*)&readbuf[i];
                LOGE("event mask %d\n",(event->mask&IN_ACCESS) || (event->mask&IN_OPEN));
                //这里监控读和打开事件
                if((event->mask&IN_ACCESS) || (event->mask&IN_OPEN)){
                    LOGE("kill!!!!!\n");
                    //事件出现则杀死父进程
                    int ret = kill(ppid,SIGKILL);
                    LOGE("ret = %d",ret);
                    return;
                }
                i+=sizeof (struct inotify_event) + event->len;
            }
        }
    }
    inotify_rm_watch(fd,wd);
    close(fd);
}

//jni 初始化的时候调用
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    if (vm->GetEnv((void **) (&env), JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    return JNI_VERSION_1_6;
}


