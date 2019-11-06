package com.justinsoft.encrypt;

import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA非对称加密算法
 * <br>
 * @since: JDK 1.8
 */
public final class RSAEncrypt
{
    /**
     * 加密，支持公钥和私钥
     *
     * @param data
     * @param key
     * @return
     */
    public static byte[] encrypt(byte[] data, byte[] key)
    {
        try
        {
            Key curKey = getKey(key);
            return doCipher(curKey, data, Cipher.ENCRYPT_MODE, MAX_ENCRYPT_BLOCK);
        }
        catch (Exception e)
        {
            LOGGER.error("Failed to encrypt data.", e);
            throw new RuntimeException("Failed to encrypt data.");
        }
    }

    /**
     * 解密，支持公钥和私钥
     *
     * @param data
     * @param key
     * @return
     */
    public static byte[] decrypt(byte[] data, byte[] key)
    {
        try
        {
            Key curKey = getKey(key);
            return doCipher(curKey, data, Cipher.DECRYPT_MODE, MAX_DECRYPT_BLOCK);
        }
        catch (Exception e)
        {
            LOGGER.error("Failed to decrypt data.", e);
            throw new RuntimeException("Failed to decrypt data.");
        }
    }

    /**
     * 获取签名
     *
     * @param data
     * @param privateKey
     * @return
     */
    public static byte[] sign(byte[] data, byte[] privateKey)
    {
        try
        {
            PrivateKey key = getPrivateKey(privateKey);
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(key);
            signature.update(data);
            return signature.sign();
        }
        catch (Exception e)
        {
            LOGGER.error("Failed to sign data.", e);
            throw new RuntimeException("Failed to sign data.");
        }
    }

    /**
     * 校验数字签名
     *
     * @param data
     * @param publicKey
     * @param sign
     * @return
     */
    public static boolean verify(byte[] data, byte[] publicKey, byte[] sign)
    {
        try
        {
            PublicKey key = getPublicKey(publicKey);
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(key);
            signature.update(data);
            return signature.verify(sign);
        }
        catch (Exception e)
        {
            LOGGER.error("Failed to verify signature data.", e);
            throw new RuntimeException("Failed to verify signature data.");
        }
    }

    /**
     * 创建KeyPair
     * <br>
     * 目的是生成公钥和私钥
     *
     * @param initKey
     * @return
     * @throws Exception
     */
    public static KeyPair createKey(byte[] initKey) throws Exception
    {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(ALGORITHM, BC_PROVIDER);

        SecureRandom secureRandom = SecureRandom.getInstance(RANDOM_ALGORITHM);
        secureRandom.setSeed(initKey);

        keyGenerator.initialize(ALGORITHM_LEN, secureRandom);
        return keyGenerator.generateKeyPair();
    }

    static
    {
        //1.添加BC算法支持
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 获取key对象(公钥)
     *
     * @param key
     * @return
     * @throws Exception
     */
    private static PublicKey getPublicKey(byte[] key) throws Exception
    {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 获取key对象(私钥)
     *
     * @param key
     * @return
     * @throws Exception
     */
    private static PrivateKey getPrivateKey(byte[] key) throws Exception
    {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    /**
     * 加解密
     * 1.私钥加密，公钥解密；
     * 2.公钥加密，私钥解密；
     *
     * @param key        私钥/公钥
     * @param data       密文/明文
     * @param cipherMode 算法模式：加密{@link Cipher#ENCRYPT_MODE},加密{@link Cipher#DECRYPT_MODE}
     * @param maxLen     最大长度
     * @return
     */
    private static byte[] doCipher(Key key, byte[] data, int cipherMode, int maxLen) throws Exception
    {
        //1.使用BC填充算法
        Cipher cipher = Cipher.getInstance(PADDING_ALGORITHM, BC_PROVIDER);
        //2.初始化，设置为加密/解密模式
        cipher.init(cipherMode, key);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int start = 0;
        try
        {
            while (start < data.length)
            {
                //3. 判定一次加解密的最大长度，不能超过data的总长度
                int limit = start + maxLen;
                limit = Math.min(limit, data.length);

                //4.分段加解密，并写入字节流
                byte[] cacheByte = cipher.doFinal(data, start, limit - start);
                out.write(cacheByte, 0, cacheByte.length);

                //5.把起始位置移至上一次的结束位置
                start = limit;
            }
            //6.把字节流中的字节全部获取出来
            byte[] resultData = out.toByteArray();
            return resultData;
        }
        finally
        {
            IOUtils.closeQuietly(out);
        }
    }

    /**
     * 获取key
     *
     * @param keyByte
     * @return
     * @throws Exception
     */
    private static Key getKey(byte[] keyByte) throws Exception
    {
        Key key;
        if (keyByte.length == EncryptKey.RSA_PRI_KEY.length)
        {
            key = getPrivateKey(keyByte);
        }
        else
        {
            key = getPublicKey(keyByte);
        }
        return key;
    }

    /**
     * 私有化构造方法
     */
    private RSAEncrypt()
    {
    }

    //日志
    private static final Logger LOGGER = LogManager.getLogger(RSAEncrypt.class);

    /**
     * 加密算法
     */
    private static final String ALGORITHM = "RSA";

    /**
     * 签名算法
     */
    private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";

    /**
     * 加密算法的长度 RSA1024
     */
    private static final int ALGORITHM_LEN = 1024;

    /**
     * RSA 1024最大的明文长度（非固定值）
     * 计算公式：
     * 1.1024bit=128byte
     * 2.128byte-11byte(PKCS1填充算法填充位)=117byte
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA 1024最大的密文长度(固定值)
     * 计算公式：
     * 1.1024bit=128byte
     */
    private static final int MAX_DECRYPT_BLOCK = 128;

    /**
     * 使用BC作为算法提供者
     */
    private static final String BC_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    /**
     * 加密/解密算法的填充算法
     * <p>
     */
    private static final String PADDING_ALGORITHM = "RSA/ECB/PKCS1Padding";

    /**
     * 随机算法
     */
    private static final String RANDOM_ALGORITHM = "SHA1PRNG";
}