package com.cmsz;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;

public class CertificateCoder {

	public static final String CERT_TYPE = "X.509";

	/**
	 * 获取私匙
	 * 
	 * @param keyStorePath
	 * @param pwd
	 * @param alias
	 * @return PrivateKey 私匙
	 * @throws Exception
	 */
	private static PrivateKey getPrivateKey(String keyStorePath, String pwd, String alias) throws Exception {
		KeyStore ks = getKeyStore(keyStorePath, pwd);
		return (PrivateKey) ks.getKey(alias, pwd.toCharArray());

	}

	/**
	 * 
	 * @param keyStorePath
	 * @param pwd
	 * @return keyStore 密匙库
	 * @throws Exception
	 */
	private static KeyStore getKeyStore(String keyStorePath, String pwd) throws Exception {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		FileInputStream in = new FileInputStream(keyStorePath);
		ks.load(in, pwd.toCharArray());
		in.close();
		return ks;
	}

	/**
	 * 
	 * @param certificatePath
	 * @return Certificate 证书
	 * @throws Exception
	 */
	private static Certificate getCertificate(String certificatePath) throws Exception {
		CertificateFactory factory = CertificateFactory.getInstance(CERT_TYPE);
		FileInputStream in = new FileInputStream(certificatePath);
		Certificate certificate = factory.generateCertificate(in);
		in.close();
		return certificate;

	}

	/**
	 * 通过证书返回公匙
	 * 
	 * @param certificatePath
	 * @return Publickey 返回公匙
	 * @throws Exception
	 */
	private static PublicKey getPublicKeyByCertificate(String certificatePath) throws Exception {
		Certificate certificate = getCertificate(certificatePath);
		return certificate.getPublicKey();
	}

	/**
	 * 
	 * @param keyStorePath
	 * @param alias
	 * @param pwd
	 * @return Certificate 证书
	 * @throws Exception
	 */
	private static Certificate getCertificate(String keyStorePath, String alias, String pwd) throws Exception {
		KeyStore ks = getKeyStore(keyStorePath, pwd);
		// 获取证书
		return ks.getCertificate(alias);
	}

	/**
	 * 私匙加密
	 * 
	 * @param data
	 * @param keyStorePath
	 * @param alias
	 * @param pwd
	 * @return byte[] 被私匙加密的数据
	 * @throws Exception
	 */
	public static byte[] encryptByPrivateKey(byte[] data, String keyStorePath, String alias, String pwd)
			throws Exception {
		PrivateKey privateKey = getPrivateKey(keyStorePath, pwd, alias);
		// 对数据进行加密
		Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		return cipher.doFinal(data);

	}

	/**
	 * 私匙解密
	 * 
	 * @param data
	 * @param keyStorePath
	 * @param alias
	 * @param pwd
	 * @return byte[] 私匙解密的数据
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] data, String keyStorePath, String alias, String pwd)
			throws Exception {
		PrivateKey privateKey = getPrivateKey(keyStorePath, pwd, alias);
		Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(data);
	}

	/**
	 * 公匙加密
	 * 
	 * @param data
	 * @param cerPath
	 * @return byte[] 被公匙加密的数据
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data, String cerPath) throws Exception {
		// 获取公匙
		PublicKey publicKey = getPublicKeyByCertificate(cerPath);
		System.out.println(publicKey.getAlgorithm());
		Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(data);
	}

	/**
	 * 公匙解密
	 * 
	 * @param data
	 * @param cerPath
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPublicKey(byte[] data, String cerPath) throws Exception {
		PublicKey publicKey = getPublicKeyByCertificate(cerPath);
		Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(data);
	}

	/**
	 * 签名
	 * 
	 * @param sign
	 * @param keyStorePath
	 * @param pwd
	 * @param alias
	 * @return
	 * @throws Exception
	 */
	public static byte[] sign(byte[] sign, String keyStorePath, String pwd, String alias) throws Exception {
		// 获取证书
		X509Certificate x509 = (X509Certificate) getCertificate(keyStorePath, alias, pwd);
		// 构建签名,由证书指定签名算法
		Signature sa = Signature.getInstance(x509.getSigAlgName());
		// 获取私匙
		PrivateKey privateKey = getPrivateKey(keyStorePath, pwd, alias);
		sa.initSign(privateKey);
		sa.update(sign);
		return sa.sign();
	}

	/**
	 * 验证签名
	 * 
	 * @param data
	 * @param sign
	 * @param cerPath
	 * @return
	 * @throws Exception
	 */
	public static boolean verify(byte[] data, byte[] sign, String cerPath) throws Exception {
		X509Certificate x509 = (X509Certificate) getCertificate(cerPath);
		// 最好写死"SHA1withRSA"而不是用x509.getSigAlgName()
		Signature sa = Signature.getInstance("SHA1withRSA");
		sa.initVerify(x509.getPublicKey());
		sa.update(data);
		return sa.verify(sign);

	}

}