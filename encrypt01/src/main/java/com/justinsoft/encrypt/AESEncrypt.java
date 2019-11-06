package com.justinsoft.encrypt;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

/**
 * AES加解密算法
 * @since: JDK 1.8
 */
public final class AESEncrypt
{
    /**
     * 加密
     *
     * @param data   待加密数据
     * @param aesKey AES秘钥
     * @return
     */
    public static byte[] encrypt(byte[] data, byte[] aesKey)
    {
        return doCipher(data, aesKey, Cipher.ENCRYPT_MODE);
    }

    /**
     * 解密
     *
     * @param data   加密数据
     * @param aesKey AES秘钥
     * @return
     */
    public static byte[] decrypt(byte[] data, byte[] aesKey)
    {
        return doCipher(data, aesKey, Cipher.DECRYPT_MODE);
    }

    /**
     * 生成秘钥
     *
     * @param initKey 初始key值，不完全使用系统的随机函数
     * @return
     * @throws Exception
     */
    public static byte[] createKey(byte[] initKey) throws Exception
    {
        //1.添加BC算法支持
        //Security.addProvider(new BouncyCastleProvider());

        //2.使用BC算法生成秘钥（添加用户的初始秘钥，不完全使用系统的随机生成秘钥的方法，可以避免系统漏洞）
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM, BC_PROVIDER);
        SecureRandom secureRandom = SecureRandom.getInstance(RANDOM_ALGORITHM);
        secureRandom.setSeed(initKey);

        //3.秘钥的长度为256(32字节)
        keyGenerator.init(ALGORITHM_LEN, secureRandom);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }

    static
    {
        //1.添加BC算法支持
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 转换aesKey为SecretKey对象
     *
     * @param aesKey
     * @return
     */
    private static SecretKey toKey(byte[] aesKey)
    {
        SecretKey key = new SecretKeySpec(aesKey, PADDING_ALGORITHM);
        return key;
    }

    /**
     * 加解密
     *
     * @param data       密文/明文
     * @param aesKey     AES秘钥
     * @param cipherMode 算法模式：加密{@link Cipher#ENCRYPT_MODE},加密{@link Cipher#DECRYPT_MODE}
     * @return
     */
    private static byte[] doCipher(byte[] data, byte[] aesKey, int cipherMode)
    {
        try
        {
            //1.获取AES Key对象
            Key key = toKey(aesKey);

            //2.使用BC填充算法
            Cipher cipher = Cipher.getInstance(PADDING_ALGORITHM, BC_PROVIDER);

            //3.初始化，设置为加密/解密模式
            cipher.init(cipherMode, key);

            //4.加密/解密
            return cipher.doFinal(data);
        }
        catch (Exception e)
        {
            LOGGER.error("Failed to encrypt/decrypt data.", e);
            throw new RuntimeException("Failed to encrypt/decrypt data.");
        }
    }

    /**
     * 私有化构造方法
     */
    private AESEncrypt()
    {
    }

    //日志
    private static final Logger LOGGER = LogManager.getLogger(AESEncrypt.class);

    /**
     * 密钥算法
     */
    private static final String ALGORITHM = "AES";

    /**
     * 加密算法的长度 AES256
     */
    private static final int ALGORITHM_LEN = 256;

    /**
     * 使用BC作为算法提供者
     */
    private static final String BC_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    /**
     * 加密/解密算法的填充方式
     * <p>
     * JAVA6支持PKCS5Padding填充方式
     * BC支持PKCS7Padding填充方式
     */
    private static final String PADDING_ALGORITHM = "AES/ECB/PKCS7Padding";

    /**
     * 随机算法
     */
    private static final String RANDOM_ALGORITHM = "SHA1PRNG";
}