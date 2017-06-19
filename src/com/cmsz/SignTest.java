package com.cmsz;

public class SignTest {

	public static void main(String[] args) {

		 //Key-Value签名验签
		 String keyValue = "{ReqReserved=2&bizType=000201&accessType=&currencyCode=156&encoding=UTF-8&issuerIdentifyMode=0&merId=777290058110048&orderId=20160317150838&origRespCode=00&origRespMsg=成功[0000000]&payCardType=01&queryId=201603171508382661928&respCode=00&respMsg=成功[0000000]&settleAmt=10000&settleCurrencyCode=156&settleDate=0317&signMethod=01&traceNo=266192&traceTime=0317150838&txnAmt=10000&txnSubType=01&txnTime=20160317150838&txnType=01&version=5.0.0}";
		 System.out.println("KeyValue原始报文：" + keyValue);
		 System.out.println("-----KeyValue签名-----");
		 String signValue = KeyValueSign.sign(keyValue);
		 System.out.println("字符串拼接：" + signValue);
		
		 boolean checkSign = false;
		 System.out.println("-----KeyValue验签-----");
		 checkSign = KeyValueSign.checkSign(signValue);
		 System.out.println("\n验签结果：" + checkSign);
		
		 //XmlData签名验签
		 String xmlData = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><GPay><Header><ActivityCode>U101_001</ActivityCode><ReqSys>0069</ReqSys><ReqDate>20170213</ReqDate><ReqTransID>53560353361066575763979965259591</ReqTransID><ReqDateTime>20170213113303</ReqDateTime><ActionCode>REQ</ActionCode><RcvSys>0001</RcvSys></Header><Body><OrderNo>00691989134902005465665114724919</OrderNo><BuyerID>buyerID</BuyerID><IDType>01</IDType><IDValue>13510434519</IDValue><OrderMoney>1</OrderMoney><Payment>1</Payment><Gift>0</Gift><MerActivityID></MerActivityID><PaymentLimit>DirectPay</PaymentLimit><ProductID>123456</ProductID><ProductName>充值</ProductName><ProductDesc>在线支付充值</ProductDesc><ProductURL>http://127.0.0.1:8086/ProductShow</ProductURL><NotifyURL>http://127.0.0.1:8086/payprod-sinmulator/merchantPayNotify.action</NotifyURL><ReturnURL>http://127.0.0.1:8086</ReturnURL><ClientIP>127.0.0.1</ClientIP><CustomParam>key=valuue|key2=value2</CustomParam><PaymentType>ALIPAY-BANK</PaymentType><DefaultBank>WZCBB2C-DEBIT</DefaultBank></Body><Sign><CerID>56445F07</CerID><SignValue></SignValue></Sign></GPay>";
		 System.out.println("\nXMLData原始报文：" + xmlData);
		 System.out.println("-----XMLData签名-----");
		 try {
		 signValue = XmlSign.getSignature(xmlData);
		 System.out.println("字符串拼接：" + signValue);
		 } catch (Exception e1) {
		 e1.printStackTrace();
		 }
		 System.out.println("-----XMLData验签-----");
		 try {
		 checkSign = XmlSign.checkSign(signValue);
		 System.out.println("\n验签结果：" + checkSign);
		 } catch (Exception e) {
		 e.printStackTrace();
		 }

	}

}
