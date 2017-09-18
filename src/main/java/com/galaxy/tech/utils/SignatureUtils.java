package com.galaxy.tech.utils;

import org.apache.commons.lang3.StringUtils;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Created by  Galaxy on 2017/9/18.
 */
public class SignatureUtils {
    /**
     * 入参的编码
     */
    public final static String CHARSET = "UTF-8";

    /**
     * 出参的签名算法
     */
    public final static String RSA2 = "RSA2";


    public final static String PARAMETER_NAME_SIGN = "sign";
    public final static String PARAMETER_NAME_SIGN_TYPE = "sign_type";

    /**
     * 从参数构造签名或者验证签名的明文字符串
     *
     * @param parameters 商户请求参数
     * @return
     */

    public static String buildStringForSignature(Map<String, String> parameters, String[] parametersToSkip) {
        // 获取所有的参数名称，然后剔除不参与签名的参数的名称
        List<String> parameterNames = new ArrayList<String>(parameters.keySet());
        for (String parameterToSkip : parametersToSkip) {
            parameterNames.remove(parameterToSkip);
        }

        // 字典序排序所有需要参与签名的参数的名称
        Collections.sort(parameterNames);

        // 拼接参数信息字符串作为签名的输入，格式 : n1=v1&n2=v2&n3=v3
        // 边界情况1: 举例描述,如果 v2 为 null 或者 0长度字符串， 则格式为 : n1=v1&n2=&n3=v3
        final int parameter_count = parameterNames.size();
        final boolean url_encoding = false;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i <= parameter_count - 1; i++) {
            String name = parameterNames.get(i);
            String value = StringUtils.defaultString(parameters.get(name));
            sb.append(buildKeyValue(name, value, url_encoding));
            if (i != (parameter_count - 1))
                // 如果是最后一个键值对，后面不添加 &, 否则添加 &
                sb.append("&");
        }

        return sb.toString();
    }

    /**
     * 拼接键值对
     *
     * @param key
     * @param value
     * @param url_encoding
     * @return
     */
    private static String buildKeyValue(String key, String value, boolean url_encoding) {
        StringBuilder sb = new StringBuilder();
        sb.append(key);
        sb.append("=");
        if (url_encoding) {
            try {
                sb.append(URLEncoder.encode(value, CHARSET));
            } catch (UnsupportedEncodingException e) {
                sb.append(value);
            }
        } else {
            sb.append(value);
        }
        return sb.toString();
    }


    /**
     * 对参数信息进行签名
     *
     * @param parameters 待签名授权信息
     * @return
     */
    public static String sign(Map<String, String> parameters, String[] parametersToSkip, String rsaPrivateKey) {
        final String sign_type = StringUtils.defaultString(parameters.get(PARAMETER_NAME_SIGN_TYPE));
        final boolean rsa2 = RSA2.equals(sign_type);
        final String stringForSignature = buildStringForSignature(parameters, parametersToSkip);
        String sign = RSAUtils.sign(stringForSignature, rsaPrivateKey, rsa2);

        return sign;
    }

    /**
     * 对参数进行签名认证
     *
     * @param parameters
     * @param parametersToSkip
     * @param rsaPublicKey
     * @return
     */
    public static boolean verifySign(Map<String, String> parameters, String[] parametersToSkip, String rsaPublicKey) {
        final String sign_type = StringUtils.defaultString(parameters.get(PARAMETER_NAME_SIGN_TYPE));
        final boolean rsa2 = RSA2.equals(sign_type);
        final String sign = StringUtils.defaultString(parameters.get(PARAMETER_NAME_SIGN));
        final String stringForSignature = buildStringForSignature(parameters, parametersToSkip);
        final boolean match = RSAUtils.verify(stringForSignature, sign, rsaPublicKey, rsa2);
        return match;
    }
}
