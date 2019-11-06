package com.justinsoft.encrypt;

import org.apache.commons.codec.Charsets;
import org.junit.Test;

import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class RSAEncryptTest
{
    @Test
    public void createKey() throws Exception
    {
        String initKeyFactor = "com.justinsoft";
        KeyPair keyPair = RSAEncrypt.createKey(initKeyFactor.getBytes(Charsets.UTF_8));
        //1.生成公秘钥
        byte[] privateKey = keyPair.getPrivate().getEncoded();
        byte[] publicKey = keyPair.getPublic().getEncoded();
        System.out.println("privateKey=" + Arrays.toString(privateKey) + ",len=" + privateKey.length);
        System.out.println("publicKey=" + Arrays.toString(publicKey) + ",len=" + publicKey.length);
        assertTrue(privateKey.length > 12 && privateKey.length <= 1024);
        assertTrue(publicKey.length > 12 && publicKey.length < privateKey.length);
    }

    /**
     * 私钥加密，公钥解密
     */
    @Test
    public void decrypt()
    {
        String testText1 = "我们都是好孩子啊好孩子!我们都是好孩子啊好孩子!我们都是好孩子啊好孩子!我们都是好";
        byte[] testByte1 = testText1.getBytes(Charsets.UTF_8);
        System.out.println("encryptByte1=" + Arrays.toString(testByte1) + ",len=" + testByte1.length);
        byte[] encryptByte1= RSAEncrypt.encrypt(testByte1,EncryptKey.RSA_PRI_KEY);
        System.out.println("encryptText1=" + Arrays.toString(encryptByte1) + ",len=" + encryptByte1.length);
        byte[] decryptByte1 = RSAEncrypt.decrypt(encryptByte1,EncryptKey.RSA_PUB_KEY);
        System.out.println("decryptText1=" + Arrays.toString(encryptByte1) + ",len=" + encryptByte1.length);
        //1、私钥加密公钥解密，验证117字节的单次RSA加密
        assertTrue(testText1.equals(new String(decryptByte1)));
    }

    /**
     * 公钥加密，私钥解密
     */
    @Test
    public void decrypt2()
    {
        String testText1 = "我们都是好孩子啊好孩子!我们都是好孩子啊好孩子!我们都是好孩子啊好孩子!我们都是好";
        byte[] testByte1 = testText1.getBytes(Charsets.UTF_8);
        System.out.println("encryptByte2=" + Arrays.toString(testByte1) + ",len=" + testByte1.length);
        byte[] encryptByte1= RSAEncrypt.encrypt(testByte1,EncryptKey.RSA_PUB_KEY);
        System.out.println("encryptText2=" + Arrays.toString(encryptByte1) + ",len=" + encryptByte1.length);
        byte[] decryptByte1 = RSAEncrypt.decrypt(encryptByte1,EncryptKey.RSA_PRI_KEY);
        System.out.println("decryptText2=" + Arrays.toString(encryptByte1) + ",len=" + encryptByte1.length);
        //1、公钥加密，私钥解密，验证117字节明文的单次RSA加密
        assertTrue(testText1.equals(new String(decryptByte1)));
    }

    @Test
    public void decrypt3()
    {
        String testText1 = "我们都是好孩子啊好孩子!我们都是好孩子啊好孩子!我们都是好孩子啊好孩子!我们都是好孩";
        byte[] testByte1 = testText1.getBytes(Charsets.UTF_8);
        System.out.println("encryptByte3=" + Arrays.toString(testByte1) + ",len=" + testByte1.length);
        byte[] encryptByte1= RSAEncrypt.encrypt(testByte1,EncryptKey.RSA_PUB_KEY);
        System.out.println("encryptText3=" + Arrays.toString(encryptByte1) + ",len=" + encryptByte1.length);
        assertTrue(encryptByte1.length==256);
        byte[] decryptByte1 = RSAEncrypt.decrypt(encryptByte1,EncryptKey.RSA_PRI_KEY);
        System.out.println("decryptText3=" + Arrays.toString(encryptByte1) + ",len=" + encryptByte1.length);
        //1、公钥加密，私钥解密，验证120字节的多次循环RSA加密
        assertTrue(testText1.equals(new String(decryptByte1)));
    }

    @Test
    public void verify()
    {
        String testText1 = "我们都是好孩子啊好孩子!我们都是好孩子啊好孩子!我们都是好孩子啊好孩子!我们都是好孩";
        byte[] testByte1 = testText1.getBytes(Charsets.UTF_8);
        System.out.println("encryptByte4=" + Arrays.toString(testByte1) + ",len=" + testByte1.length);
        byte[] signByte = RSAEncrypt.sign(testByte1,EncryptKey.RSA_PRI_KEY);
        boolean isVerify = RSAEncrypt.verify(testByte1,EncryptKey.RSA_PUB_KEY,signByte);
        assertTrue(isVerify);
    }
}