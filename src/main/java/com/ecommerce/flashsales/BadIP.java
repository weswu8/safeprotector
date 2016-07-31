package com.ecommerce.flashsales;
/***
 * 
 * @author wuwesley
 * the class for bad IP info
 */

public class BadIP {
	public String clientIP;
	public Boolean isBadIP = false;
	
	public String getClientIP() {
		return clientIP;
	}
	public void setClientIP(String clientIP) {
		this.clientIP = clientIP;
	}
	public Boolean getIsBadIP() {
		return isBadIP;
	}
	public void setIsBadIP(Boolean isBadIP) {
		this.isBadIP = isBadIP;
	}

}
