package com.justinsoft.encrypt;

import org.apache.commons.codec.Charsets;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class AESEncryptTest
{
    @Test
    public void createKey() throws Exception
    {
        String initKeyFactor = "com.justinsoft";
        byte[] secretKey = AESEncrypt.createKey(initKeyFactor.getBytes(Charsets.UTF_8));
        //1.生成秘钥
        System.out.println("secretKey=" + Arrays.toString(secretKey));
        assertTrue(secretKey.length == 32);
    }

    @Test
    public void encrypt()
    {
        // 验证明文字符串长度较短的加密情况：
        // 明文长度58byte，每16byte为一个分组，密文应该是分成4组，每组16字节，所以密文一共64字节
        String testText1 = "1234567890987654321abcdefghijklmnopqrstuvwxyz~!@#$%^&*()_+";
        byte[] testByte1 = testText1.getBytes(Charsets.UTF_8);
        byte[] encryptText1 = AESEncrypt.encrypt(testByte1, EncryptKey.AES_KEY);
        System.out.println("srcLen1=" + testByte1.length + ",encryptText1=" + Arrays.toString(encryptText1) + ",len="
            + encryptText1.length);
        assertTrue(encryptText1.length == 64);

        // 验证明文字符串长度较长的加密情况：
        // 明文长度65byte，每16byte为一个分组，密文应该是分成5组，每组16字节，所以密文一共80字节
        String testText2 = "1234567890987654321abcdefghijklmnopqrstuvwxyz~!@#$%^&*()_+!@#$%^h";
        byte[] testByte2 = testText2.getBytes(Charsets.UTF_8);
        byte[] encryptText2 = AESEncrypt.encrypt(testByte2, EncryptKey.AES_KEY);
        System.out.println("srcLen2=" + testByte2.length + ",encryptText2=" + Arrays.toString(encryptText2) + ",len="
            + encryptText2.length);
        assertTrue(encryptText2.length == 80);
    }

    @Test
    public void decrypt()
    {
        // 验证明文字符串长度较短的加密情况：
        // 明文长度58byte，每16byte为一个分组，密文应该是分成4组，每组16字节，所以密文一共64字节
        String testText1 = "1234567890987654321abcdefghijklmnopqrstuvwxyz~!@#$%^&*()_+";
        byte[] testByte1 = testText1.getBytes(Charsets.UTF_8);
        byte[] encryptText1 = AESEncrypt.encrypt(testByte1, EncryptKey.AES_KEY);
        System.out.println("srcLen1=" + testByte1.length + ",encryptText1=" + Arrays.toString(encryptText1) + ",len="
            + encryptText1.length);
        assertTrue(encryptText1.length == 64);
        byte[] decryptByte1 = AESEncrypt.decrypt(encryptText1,EncryptKey.AES_KEY);
        assertTrue(decryptByte1.length == 58);
        String decryptText1 = new String(decryptByte1);
        assertTrue(decryptText1.equals(testText1));


        // 验证明文字符串长度较长的加密情况：
        // 明文长度65byte，每16byte为一个分组，密文应该是分成5组，每组16字节，所以密文一共80字节
        String testText2 = "1234567890987654321abcdefghijklmnopqrstuvwxyz~!@#$%^&*()_+!@#$%^h";
        byte[] testByte2 = testText2.getBytes(Charsets.UTF_8);
        byte[] encryptText2 = AESEncrypt.encrypt(testByte2, EncryptKey.AES_KEY);
        System.out.println("srcLen2=" + testByte2.length + ",encryptText2=" + Arrays.toString(encryptText2) + ",len="
            + encryptText2.length);
        assertTrue(encryptText2.length == 80);
        byte[] decryptByte2 = AESEncrypt.decrypt(encryptText2,EncryptKey.AES_KEY);
        assertTrue(decryptByte2.length == 65);
        String decryptText2 = new String(decryptByte2);
        assertTrue(decryptText2.equals(testText2));
    }
}