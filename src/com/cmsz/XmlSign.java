package com.cmsz;

public class XmlSign {
	
	private static final String CER_PATH = "resources/cer0069.cer";
	private static final String KEYSTORE_PATH = "resources/0069.keystore";
	private static final String PASSWORD = "000000";
	private static final String ALIAS = "cer0069";
	
	/**
	 * 验签
	 * 
	 * @param xmldata
	 */
	public static boolean checkSign(String xmldata) throws Exception {
		String signValue = parseNodeValueFromXml("<SignValue>", "</SignValue>", xmldata);
		String actionCode = parseNodeValueFromXml("<ActionCode>", "</ActionCode>", xmldata);
		String bankId = parseNodeValueFromXml("<ReqSys>", "</ReqSys>", xmldata);
		// 如果是返回报文机构取RcvSys
		if ("RSP".equals(actionCode)) {
			bankId = parseNodeValueFromXml("<RcvSys>", "</RcvSys>", xmldata);
		}

		String cerId = parseNodeValueFromXml("<CerID>", "</CerID>", xmldata);
		int headerIndex = xmldata.indexOf("<Header>");
		int headerLast = xmldata.indexOf("</Header>");
		String headers = xmldata.substring(headerIndex, headerLast + 9);

		String body = parseNodeValueFromXml("<Body>", "</Body>", xmldata);
		StringBuffer sb = new StringBuffer();
		sb.append(headers).append("|").append("<Body>" + body + "</Body>");
		// 验签
		//boolean isValid = CertificateCoder.verify(sb.toString().getBytes(), new BASE64Decoder().decodeBuffer(signValue), CER_PATH);
		byte[] sign = Base64Util.decode(signValue);
		System.out.print("逆Base64编码：");
		for(byte i: sign) {
			System.out.print(i + " ");
		}
		boolean isValid = CertificateCoder.verify(sb.toString().getBytes(), sign, CER_PATH);
		return isValid;

	}

	/**
	 * 获取签名
	 * 
	 * @author zmh
	 */
	public static String getSignature(String xmldata) throws Exception {
		int headerIndex = xmldata.indexOf("<Header>");
		int headerLast = xmldata.indexOf("</Header>");
		String headers = xmldata.substring(headerIndex, headerLast + 9);
		String body = parseNodeValueFromXml("<Body>", "</Body>", xmldata);
		StringBuffer sb = new StringBuffer();
		sb.append(headers).append("|").append("<Body>" + body + "</Body>");
		// 获取签名
		
		byte[] signByte = CertificateCoder.sign(sb.toString().getBytes(), KEYSTORE_PATH, PASSWORD, ALIAS);
		//String signReturn = new BASE64Encoder().encode(signByte).replaceAll("\r|\n", "");
		System.out.print("RSA加密：");
		for(byte b:signByte) {
			System.out.print(" " + b);
		}
		
		String signReturn = Base64Util.encode(signByte);
		System.out.println("\n签名Base64编码转换：" + signReturn);
		String replaceXml = relaceNodeContent("<SignValue>", "</SignValue>", signReturn, xmldata);
		xmldata = relaceNodeContent("<CerID>", "</CerID>", "", replaceXml);
		return xmldata;
	}
	
	/**
	 * 以字符串查找的试获取xml文本中节点的值
	 * @param nodeStart 节点开始标签 eg :&lt;TransactionID&gt;
	 * @param nodeEnd 节点结束标签 eg :&lt;/TransactionID&gt;
	 * @param src 原字符串
	 * @return
	 */
	public static String parseNodeValueFromXml(String nodeStart, String nodeEnd, String src) {
		int nodeStartLength = nodeStart.length();
		int start = src.indexOf(nodeStart);
		int end = src.indexOf(nodeEnd);
		if (start > -1 && end > -1) {
			return src.substring(start + nodeStartLength, end);
		}
		return "";
	}
	
	/**
	 * 替换xml中节点的值，只适合替换报文中只有一个指定名字的节点
	 * 
	 * @param nodeStart 节点开始标签 eg :&lt;TransactionID>
	 * @param nodeEnd 节点结束标签 eg :&lt;/TransactionID>
	 * @param relacement 节点替换的内容
	 * @param xml 原字符串
	 * @return
	 */
	public static String relaceNodeContent(String nodeStart, String nodeEnd, String relacement, String xml) {
		int nodeStartLength = nodeStart.length();
		int start = xml.indexOf(nodeStart);
		int end = xml.indexOf(nodeEnd);

		if (start > -1 && end > -1) {
			String segStart = xml.substring(0, start + nodeStartLength);
			String segEnd = xml.substring(end, xml.length());
			return segStart + relacement + segEnd;
		}
		return xml;
	}

}
