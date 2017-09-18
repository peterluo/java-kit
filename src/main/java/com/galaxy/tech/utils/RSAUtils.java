package com.galaxy.tech.utils;



import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.SystemUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


/**
 * Created by Galaxy on 2017/9/18.
 */
public class RSAUtils {
    // 定义数据
    private static final String DEFAULT_CHARSET = "UTF-8";

    // 生成密钥的长度
    private static final int KEY_SIZE = 2048;

    private static final String ALGORITHM = "RSA";

    private static final String SIGN_ALGORITHMS = "SHA1WithRSA";

    private static final String SIGN_SHA256RSA_ALGORITHMS = "SHA256WithRSA";

    // 生成的密钥保存位置
    private static final String OUT_FILE = SystemUtils.JAVA_IO_TMPDIR + File.separator + "2048";


    private static String getAlgorithms(boolean rsa2) {
        return rsa2 ? SIGN_SHA256RSA_ALGORITHMS : SIGN_ALGORITHMS;
    }


    /**
     * 使用base 64 编码然后输出
     *
     * @param out
     * @param key
     * @throws IOException
     */
    private static void writeBase64(Writer out, Key key) throws IOException {
        byte[] buf = key.getEncoded();
        out.write(Base64Utils.encode(buf));
    }

    /**
     * 生成私钥公钥对，key size 2048 位,base64 编码后保存到文件
     *
     * @param folder             输出目标目录
     * @param fileNameWithoutExt 输出目标文件的文件名，不包括扩展名部分
     * @return Pair<私钥绝对路径，公钥绝对路径>
     * @throws Exception
     */
    public static Pair<String, String> generateKeyPair(String folder, String fileNameWithoutExt) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
        /* initialize with keySize: typically 2048 for RSA */
        kpg.initialize(KEY_SIZE);
        KeyPair keyPair = kpg.generateKeyPair();

        Writer out = null;
        try {
            File private_key_file = new File(folder, fileNameWithoutExt + ".key");
            if (!private_key_file.exists()) {
                private_key_file.createNewFile();
            }
            out = new FileWriter(private_key_file);
            writeBase64(new FileWriter(private_key_file), keyPair.getPrivate());
            out.close();

            File public_key_file = new File(folder, fileNameWithoutExt + ".pub");
            if (!public_key_file.exists()) {
                public_key_file.createNewFile();
            }

            out = new FileWriter(public_key_file);
            writeBase64(out, keyPair.getPublic());
            out.close();

            return ImmutablePair.of(private_key_file.getAbsolutePath(), public_key_file.getAbsolutePath());
        } finally {
            if (out != null) out.close();
        }
    }


    /**
     * 生成私钥公钥对
     *
     * @throws Exception
     */
    public static void generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
        /* initialize with keySize: typically 2048 for RSA */
        kpg.initialize(KEY_SIZE);
        KeyPair kp = kpg.generateKeyPair();

        Writer out = null;
        try {
            File private_key_file = new File(OUT_FILE + ".key");
            if (!private_key_file.exists()) {
                private_key_file.createNewFile();
            }

            if (OUT_FILE != null) out = new FileWriter(OUT_FILE + ".key");
            else out = new OutputStreamWriter(System.out);

            // System.err.println("Private key format: " + kp.getPrivate().getFormat());
            writeBase64(out, kp.getPrivate());

            if (OUT_FILE != null) {
                out.close();

                File public_key_file = new File(OUT_FILE + ".pub");
                if (!public_key_file.exists()) {
                    public_key_file.createNewFile();
                }

                out = new FileWriter(OUT_FILE + ".pub");
            }

            //System.err.println("Public key format: " + kp.getPublic().getFormat());
            writeBase64(out, kp.getPublic());
        } finally {
            if (out != null) out.close();
        }


    }


    public static PrivateKey loadPrivateKey(File file) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        /* Read all bytes from the private key file */
        String private_key_from_file = FileUtils.readFileToString(file, DEFAULT_CHARSET);
        byte[] bytes = Base64Utils.decode(private_key_from_file);

        /* Generate private key. */
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        PrivateKey pvt = kf.generatePrivate(ks);

        return pvt;
    }


    public static PrivateKey loadPrivateKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        /* Read all bytes from the private key file */
        File file = new File(OUT_FILE + ".key");

        PrivateKey pvt = loadPrivateKey(file);

        return pvt;
    }


    public static PublicKey loadPublicKey(File file) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
       /* Read all the public key bytes */
        String public_key_from_file = FileUtils.readFileToString(file, DEFAULT_CHARSET);
        byte[] bytes = Base64Utils.decode(public_key_from_file);

        /* Generate public key. */
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        PublicKey pub = kf.generatePublic(ks);

        return pub;
    }

    public static PublicKey loadPublicKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
       /* Read all the public key bytes */
        File file = new File(OUT_FILE + ".pub");

        PublicKey pub = loadPublicKey(file);

        return pub;
    }

    /**
     * 按照一个 base64 编码的公钥来理解
     *
     * @param public_key_str
     * @return
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    private static PublicKey asPublicKey(String public_key_str) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
       /* Read all the public key bytes */
        byte[] bytes = Base64Utils.decode(public_key_str);

        /* Generate public key. */
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        PublicKey pub = kf.generatePublic(ks);

        return pub;
    }

    public static byte[] sign(String source_data, PrivateKey private_key) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(private_key);

        // 定义数据
        final byte[] data = source_data.getBytes(DEFAULT_CHARSET);

        signature.update(data);

        byte[] sign = signature.sign();

        //System.out.println(toHexString(sign));

        return sign;

    }

    public static String sign(String content, String private_key, boolean rsa2) {
        try {
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(
                    Base64Utils.decode(private_key));
            KeyFactory keyf = KeyFactory.getInstance(ALGORITHM);
            PrivateKey priKey = keyf.generatePrivate(priPKCS8);

            java.security.Signature signature = java.security.Signature
                    .getInstance(getAlgorithms(rsa2));

            signature.initSign(priKey);
            signature.update(content.getBytes(DEFAULT_CHARSET));

            byte[] signed = signature.sign();
            System.out.println("Sign "+Base64Utils.encode(signed));
            return Base64Utils.encode(signed);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;

    }

    public static boolean verify(String source_data, byte[] sign, PublicKey public_key) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(public_key);

            // 定义数据
            final byte[] data = source_data.getBytes(DEFAULT_CHARSET);

            signature.update(data);
            boolean verify = signature.verify(sign);

            return verify;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    /**
     * 验证签名
     *
     * @param content
     * @param sign
     * @param public_key_str
     * @param rsa2
     * @return
     */
    public static boolean verify(String content, String sign, String public_key_str, boolean rsa2) {
        try {
            PublicKey public_key = asPublicKey(public_key_str);
            Signature signature = Signature.getInstance(getAlgorithms(rsa2));
            signature.initVerify(public_key);

            // 定义数据
            final byte[] data = content.getBytes(DEFAULT_CHARSET);
            System.out.println("Verify "+sign);
            signature.update(data);
            boolean verify = signature.verify(Base64Utils.decode(sign));

            return verify;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }


    private static String toHexString(byte[] data) {
        String table = "0123456789abcdef";
        StringBuilder sb = new StringBuilder();
        final int l = data.length;
        for (int i = 0; i < l; i++) {
            sb.append(table.charAt((0xF0 & data[i]) >>> 4));
            sb.append(table.charAt(0x0F & data[i]));
        }
        return sb.toString();
    }


    public static void main(String[] args) throws Exception {
        generateKeyPair();

        String source_data = "hello";

        PrivateKey private_key = loadPrivateKey();
        PublicKey public_key = loadPublicKey();
        byte[] sign = sign(source_data, private_key);
        boolean result = verify(source_data, sign, public_key);

        System.out.println(result);
    }
}
