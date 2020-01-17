# 一、背景
>1. 加解密是程序猿无法绕过的必备技能，但不少人都对加解密存在误解：比如经常会有人把MD5这种Hash算法也当成加密算法；
>2. 加解密算法众多，但是我们实际应用的却只有那么2-3种，下面着重讲下对称加密算法和非对称加密算法，以及对应的业务场景；
# 二、目标
1. 借助第三方基础库（BCP），完成常用的对称加密算法AES256和非对称加密算法RSA1024的开发及验证；
2. 分析关键代码和业务场景，加深理解；
# 三、步骤
1. Maven配置文件pom.xml中引入BCP依赖（完整源码见[woollay/springboot-shiro](https://github.com/woollay/springboot-shiro/tree/master/encrypt01)）：
```xml
<!-- 加密组件包 -->
<dependency>
   <groupId>org.bouncycastle</groupId>
   <artifactId>bcprov-jdk15on</artifactId>
   <version>1.62</version>
</dependency>
```
2. 编写AES256加解密代码：
```java
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
```
3. AES256算法是对称加密算法，对称加密算法就是说加密和解密的密钥对是相同的，即：用什么秘钥加密，就得用该秘钥去解密。
>特点：加解密效率比较高。
>场景：需要频繁加解密的业务场景。比如：数据库登录密码的加密。
4. AES256的验证UT代码：
```java
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
```
5. AES256异常处理。在运行过程中，有概率会出现如下异常：
> java.security.InvalidKeyException: Illegal key size or default parameters
该问题的解决方案见网友总结的[博客](https://blog.csdn.net/dafeige8/article/details/76019911)。简单来说安装版的jdk6/jdk7/jdk8中默认只支持AES128，如果要支持AES256，需要升级官方补丁。一般解压版可以直接支持AES256。
6. 编写RSA1024加解密代码：
```java
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
```
7. RSA1024算法是非对称加密算法，就是说加密和解密的密钥对是不同的。
>特点：相比对称加密算法来说更安全，因为加解密秘钥完全分离，加密方无须告知解密方自己的秘钥；解密方也无须告知加密方自己的秘钥。加密的效率较低。
>场景：签名、证书等。如：https里面就使用的是RSA加密算法生成的证书；github上的ssh公私钥也是RSA加密算法生成的。
8. RSA1024的验证UT代码：
```java
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
```
9. RSA1024算法需要注意的是一次只能加解密117个字节（原因见代码中的注释），所以，如果报文过长，需要进行分段加解密，核心代码见RSA1024代码。

# 四、总结
1. AES256和RSA1024的使用方式差不多，都是要传入要加密的内容和秘钥，只不过AES256加解密的秘钥是同一个，而RSA1024是不同的2个值，观察完整的源码就会发现公钥和私钥的长度都完全不同；RSA1024算法还可用于验证签名；需要特别强调的是：RSA1024每次加密同一份内容的密文也不相同；
2. AES256用于数据库登录密码或者部分C/S结构的客户端密码的加解密，效率也高；RSA1024主要用于https,github的ssh连接的加解密，加解密效率偏低；

# 五、参考
[1][开发中的几种加密算法的使用场景](https://blog.csdn.net/gulang03/article/details/81176593)
[2][AES的256位密钥加解密报 java.security.InvalidKeyException: Illegal key size or default parameters 异常的处理及处理工具](https://blog.csdn.net/dafeige8/article/details/76019911)

