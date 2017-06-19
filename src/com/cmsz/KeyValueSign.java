package com.cmsz;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

public class KeyValueSign {
	
	/**
	 * 识别字符串状态机转换：<br>
	 * STATUS_KEY --[=]--> STATUS_SIMPLEVALUE STATUS_SIMPLEVALUE --[&]-->
	 * STATUS_KEY STATUS_SIMPLEVALUE --[{]--> STATUS_COMPLEXVALUE
	 * STATUS_COMPLEXVALUE --[}]--> STATUS_SIMPLEVALUE STATUS_COMPLEXVALUE
	 * --[=]--> STATUS_COMPLEXVALUE STATUS_COMPLEXVALUE --[&]-->
	 * STATUS_COMPLEXVALUE
	 */
	private static int STATUS_KEY = 1;
	private static int STATUS_SIMPLEVALUE = 2;
	private static int STATUS_COMPLEXVALUE = 4;
	
	private static final String CER_PATH = "resources/cer0069.cer";
	private static final String KEYSTORE_PATH = "resources/0069.keystore";
	private static final String PASSWORD = "000000";
	private static final String ALIAS = "cer0069";
	
	public static final String DEFAULT_ENCODE = "utf-8";
	
	/**
	 * 将key1=value1&key2=value2形式的字符串转转换为一个排序的map<br>
	 * 此方法忽略字符串前后可能存在的"{}"字符<br>
	 * 
	 * @param keyValueString
	 * @return
	 */
	public static SortedMap<String, String> keyValueStringToMap(String keyValueString) {
		if (keyValueString==null || keyValueString.equals("")) {
			return null;
		}
		StringBuilder sb = new StringBuilder(keyValueString);
		if (sb.charAt(0) == '{') {
			sb.deleteCharAt(0);
		}
		if (sb.charAt(sb.length() - 1) == '}') {
			sb.deleteCharAt(sb.length() - 1);
		}

		SortedMap<String, String> map = new TreeMap<String, String>();

		int currentIndex = 0;
		String key = null;
		String value = null;

		int status = STATUS_KEY;

		for (int i = 0; i < sb.length(); ++i) {
			char c = sb.charAt(i);
			// 状态转换
			if (status == STATUS_KEY && c == '=') {
				status = STATUS_SIMPLEVALUE;
				key = sb.substring(currentIndex, i);
				currentIndex = i + 1;
			} else if (status == STATUS_SIMPLEVALUE && c == '&') {
				status = STATUS_KEY;
				value = sb.substring(currentIndex, i);
				map.put(key, value);
				currentIndex = i + 1;
			} else if (status == STATUS_SIMPLEVALUE && c == '{') {
				status = STATUS_COMPLEXVALUE;
			} else if (status == STATUS_COMPLEXVALUE && c == '}') {
				status = STATUS_SIMPLEVALUE;
			}
		}
		value = sb.substring(currentIndex, sb.length());
		map.put(key, value);
		
		return map;
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
	
	/**
	 * 签名
	 * 获取签名并拼装字符串
	 * @param signStr
	 * @return
	 */
	public static String sign(String signStr) {
		if (signStr.isEmpty()) {
			throw new RuntimeException("不支持空串签名");
		}
		
		byte[] signByte = null;
		signStr = signStr.trim();
		Map<String, String> reqDatamap = keyValueStringToMap(signStr);
		reqDatamap.remove("CertID");
		reqDatamap.remove("SignValue");
		reqDatamap.remove("signature");
		signStr = mapToString(reqDatamap);
		try {
			signByte = CertificateCoder.sign(signStr.toString().getBytes(), KEYSTORE_PATH, PASSWORD, ALIAS);
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
		//String cerId = CertificateCoder.getSignCerId();
		String appendStr = "&SignValue=" + signReturn;
		signStr = signStr + appendStr;
		
		return signStr;
	}
	
	// 验签
	public static boolean checkSign(String checkValue) {
		checkValue = checkValue.trim();
		Map<String, String> checkDatamap = keyValueStringToMap(checkValue);
		String signValue = checkDatamap.remove("SignValue");
		checkDatamap.remove("CertID");
		checkDatamap.remove("SignValue");
		checkDatamap.remove("signature");
		String s = mapToString(checkDatamap);
		boolean isValid = false;
		try {
			byte[] sign = Base64Util.decode(signValue);
			System.out.print("逆Base64编码：");
			for(byte i: sign) {
				System.out.print(i + " ");
			}
			isValid = CertificateCoder.verify(s.toString().getBytes(), sign, CER_PATH);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return isValid;
	}

}
