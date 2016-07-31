package com.ecommerce.flashsales;
/***
 * 
 * @author wuwesley
 * the class for bad guy info
 */

public class BadGuy {
	public String userID;
	public Boolean isBadGuy = false;
	
	public String getUserID() {
		return userID;
	}
	public void setUserID(String userID) {
		this.userID = userID;
	}
	public Boolean getIsBadGuy() {
		return isBadGuy;
	}
	public void setIsBadGuy(Boolean isBadGuy) {
		this.isBadGuy = isBadGuy;
	}

}
