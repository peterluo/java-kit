package com.galaxy.tech.utils;

/**
 * Created by Galaxy on 2017/9/18.
 */
public class Base64Utils {
    public static String encode(byte[] bytes) {
//        return java.util.Base64.getEncoder().encodeToString(bytes);
        return org.apache.commons.codec.binary.Base64.encodeBase64String(bytes);
    }

    public static byte[] decode(String str) {
//        return java.util.Base64.getDecoder().decode(str);
        return org.apache.commons.codec.binary.Base64.decodeBase64(str);
    }
}
