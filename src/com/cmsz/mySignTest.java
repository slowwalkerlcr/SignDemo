package com.cmsz;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import static com.cmsz.CertificateCoder.CERT_TYPE;
import static com.cmsz.KeyValueSign.keyValueStringToMap;

/**
 * @author Edison_lv  lvchangrong
 * @create 2017/6/18  22:39
 */
public class mySignTest {
    private final static String KEYSTORE_PATH="resources/myKeystore.keystore";
    private static final String CER_PATH = "resources/myCer2.cer";
    private static final String KEY_PASSWORD = "123456";
    private static final String PRI_PASSWORD="654321";
    private static final String ALIAS = "myCertificate";


    public static void main(String[] args) {
        //Key-Value签名验签
        String signStr = "{ReqReserved=2&bizType=000201&accessType=&currencyCode=156&encoding=UTF-8&issuerIdentifyMode=0&merId=777290058110048&orderId=20160317150838&origRespCode=00&origRespMsg=成功[0000000]&payCardType=01&queryId=201603171508382661928&respCode=00&respMsg=成功[0000000]&settleAmt=10000&settleCurrencyCode=156&settleDate=0317&signMethod=01&traceNo=266192&traceTime=0317150838&txnAmt=10000&txnSubType=01&txnTime=20160317150838&txnType=01&version=5.0.0}";
        System.out.println("KeyValue原始报文：" + signStr);
        System.out.println("-----KeyValue签名-----");
        byte[] signByte = null;
        signStr = signStr.trim();
        Map<String, String> reqDatamap = keyValueStringToMap(signStr);
        reqDatamap.remove("CertID");
        reqDatamap.remove("SignValue");
        reqDatamap.remove("signature");
        signStr = mapToString(reqDatamap);
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            FileInputStream in = new FileInputStream(KEYSTORE_PATH);
            ks.load(in, KEY_PASSWORD.toCharArray());
            in.close();
            X509Certificate x509 = (X509Certificate)ks.getCertificate(ALIAS);
           // String cerId =x509.getSerialNumber().toString(16).toUpperCase();
            // 构建签名,由证书指定签名算法
            Signature sa = Signature.getInstance(x509.getSigAlgName());
            // 获取私匙
            PrivateKey privateKey = (PrivateKey)ks.getKey(ALIAS,PRI_PASSWORD.toCharArray());
            sa.initSign(privateKey);
            sa.update(signStr.toString().getBytes());
            signByte = sa.sign();
            System.out.print("RSA加密：");
            for(byte b:signByte) {
                System.out.print(" " + b);
            }
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        String signReturn = Base64Util.encode(signByte);
        System.out.println("\nBase64编码转换：" + signReturn);
        String appendStr = "&SignValue=" + signReturn;
        signStr = signStr + appendStr;
        System.out.println("字符串拼接：" + signStr);


      //验签
        boolean checkSign = false;
        System.out.println("-----KeyValue验签-----");
        signStr = signStr.trim();
        Map<String, String> checkDatamap = keyValueStringToMap(signStr);
        String signValue = checkDatamap.remove("SignValue");
        checkDatamap.remove("CertID");
        checkDatamap.remove("SignValue");
        checkDatamap.remove("signature");
        String s = mapToString(checkDatamap);
//        boolean isValid = false;
        try {
            byte[] sign = Base64Util.decode(signValue);
            System.out.print("逆Base64编码：");
            for(byte i: sign) {
                System.out.print(i + " ");
            }
            //isValid = CertificateCoder.verify(s.toString().getBytes(), sign, CER_PATH);
            CertificateFactory factory = CertificateFactory.getInstance(CERT_TYPE);
            FileInputStream in = new FileInputStream(CER_PATH);
            Certificate certificate = factory.generateCertificate(in);
            in.close();
            X509Certificate x509 = (X509Certificate)certificate;
            // 最好写死"SHA1withRSA"而不是用x509.getSigAlgName()
            Signature sa = Signature.getInstance("SHA1withRSA");
            sa.initVerify(x509.getPublicKey());
            sa.update(s.getBytes());
            checkSign =  sa.verify(sign);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        System.out.println("\n验签结果：" + checkSign);


    }


    /**
     * 将Map中的数据转换成按照Key的ascii码排序后的key1=value1&key2=value2的形式
     *
     * @param data
     * @return
     */
    public static String mapToString(Map<String, String> map) {
        SortedMap<String, String> sortedMap = new TreeMap<String, String>(map);

        StringBuilder sb = new StringBuilder();

        for (Map.Entry<String, String> entry : sortedMap.entrySet()) {
            if (entry.getValue()==null || entry.getValue().equals("")) {
                continue;
            }

            sb.append(entry.getKey()).append('=').append(entry.getValue()).append('&');
        }
        if (sb.length()>0) {
            sb.deleteCharAt(sb.length() - 1);
        }
        return sb.length() == 0 ? "" : sb.toString();
    }
}
