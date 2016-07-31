package com.ecommerce.flashsales;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;

import ch.qos.logback.core.net.SyslogOutputStream;
import net.rubyeye.xmemcached.MemcachedClient;
import net.rubyeye.xmemcached.exception.MemcachedException;

/***
 * 
 * @author wuwesley
 * The inventory management service for the whole system.
 */
@RestController
@RequestMapping("/")
public class  SafeProtector {	
    @Autowired
    private MemcachedClient memcachedClient;
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final String allBadGuysKey = "xAllBadGuysKey";
    private final String allBadIPsKey = "xAllBadIPsKey";
    private final String xNameSpace = "SafeProtector";
	FlashSalesAccessLogger fsAccessLogger = new FlashSalesAccessLogger();
	
	/*** rate limiter setting ***/
    @Value("${ratelimiter.consumeCount}")
	public double consumeCount;
    
    /***
     * Generate the md5 value for the pair of clientIP and userID
     * @param badguy
     * @return
     * @throws NoSuchAlgorithmException 
     */
    public String md5Hashing (String xNameSpace,String uniqueValue) throws NoSuchAlgorithmException{
		String md5String = null;
		String clientPair = null;
		
		clientPair = uniqueValue + ":" + xNameSpace;
		
		MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(clientPair.toString().getBytes());
        
        byte byteData[] = md.digest();
 
        //convert the byte to hex format method 1
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
         sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
        }
        //System.out.println("Digest(in hex format):: " + sb.toString());
        md5String = sb.toString();
		return md5String;
	}
    /***
	 * Create a new the badguy record
	 * Request sample : {"userID":"FS00000001", "isBadGuy":true} and need set the customer header -H 'Content-Type:application/json'
	 * Response sample : {"userID":"FS00000001", "isBadGuy":true} 
     * @throws NoSuchAlgorithmException 
     * @throws ParseException 
	 */
    @SuppressWarnings("unchecked")
	@RequestMapping(method=RequestMethod.POST, value = "/badguy/add", headers = "Accept=application/json")
	public BadGuy addBadGuy(@RequestBody BadGuy badGuy) throws NoSuchAlgorithmException, ParseException{
		long timeMillis = System.currentTimeMillis();
		long timeSeconds = TimeUnit.MILLISECONDS.toSeconds(timeMillis);
		int expirationValue = (int) (timeSeconds + 24*60*60*365);
		JSONObject jObj = new JSONObject();
		if (badGuy.getUserID().length() > 0){
 			try {
				badGuy.setIsBadGuy(true);
 				jObj.put("userID",badGuy.getUserID());
 				jObj.put("isBadGuy",badGuy.getIsBadGuy());
 				memcachedClient.set(md5Hashing(xNameSpace,badGuy.getUserID()), expirationValue, jObj.toString());
 				// 10.0.0.1@UserID
 				updateAllItemsKey(allBadGuysKey,badGuy.getUserID(),"ADD");
			} catch (TimeoutException e) {
				logger.error("TimeoutException");
			} catch (InterruptedException e) {
				logger.error("InterruptedException");
			} catch (MemcachedException e) {
				logger.error("MemcachedException");
			}
 		}
		return badGuy;
	}
    /***
	 * Create a new the bad ip record
	 * Request sample : {"clientIP":"202.100.100.1", "isBadIP":true} and need set the customer header -H 'Content-Type:application/json'
	 * Response sample : {"clientIP":"202.100.100.1", "isBadIP":true} 
     * @throws NoSuchAlgorithmException 
     * @throws ParseException 
	 */
    @SuppressWarnings("unchecked")
	@RequestMapping(method=RequestMethod.POST, value = "/badip/add", headers = "Accept=application/json")
	public BadIP addBadIP(@RequestBody BadIP badIP) throws NoSuchAlgorithmException, ParseException{
		long timeMillis = System.currentTimeMillis();
		long timeSeconds = TimeUnit.MILLISECONDS.toSeconds(timeMillis);
		int expirationValue = (int) (timeSeconds + 24*60*60*365);
		JSONObject jObj = new JSONObject();
		if (badIP.getClientIP().length() > 0){
 			try {
				badIP.setIsBadIP(true);
 				jObj.put("clientIP",badIP.getClientIP());
 				jObj.put("isBadIP",badIP.getIsBadIP());
 				memcachedClient.set(md5Hashing(xNameSpace,badIP.getClientIP()), expirationValue, jObj.toString());
 				// 10.0.0.1@UserID
 				updateAllItemsKey(allBadIPsKey,badIP.getClientIP(),"ADD");
			} catch (TimeoutException e) {
				logger.error("TimeoutException");
			} catch (InterruptedException e) {
				logger.error("InterruptedException");
			} catch (MemcachedException e) {
				logger.error("MemcachedException");
			}
 		}
		return badIP;
	}
	/***
	 * Get the bad guy info.
	 * Request sample : http://localhost:8080/badguy/userid/{userid}
	 * Response sample :{"userID":"FS00000001", "isBadGuy":true} 
	 * @throws NoSuchAlgorithmException 
	 * @throws ParseException 
	 */
	@RequestMapping(method = RequestMethod.GET, value = "/badguy/userid/{userid}")	
	public BadGuy getBadGuy(@PathVariable("userid") String userid) throws NoSuchAlgorithmException, ParseException {
		Object mObject = null;
		BadGuy badGuy = new BadGuy() ;
		if (userid.length() > 0){
 			try {
 				badGuy.setUserID(userid);
 				badGuy.setIsBadGuy(false);
 				mObject = memcachedClient.get(md5Hashing(xNameSpace,badGuy.getUserID()));
 				if (mObject != null){
 					JSONParser parser = new JSONParser();
 					JSONObject json = (JSONObject) parser.parse(mObject.toString());
 					badGuy.setUserID(json.get("userID").toString());
 					badGuy.setIsBadGuy(Boolean.parseBoolean(json.get("isBadGuy").toString()));
 				}				
			} catch (TimeoutException e) {
				logger.error("TimeoutException");
			} catch (InterruptedException e) {
				logger.error("InterruptedException");
			} catch (MemcachedException e) {
				logger.error("MemcachedException");
			}
 		}
		return badGuy;
	}
	
	/***
	 * Get the bad IP info.
	 * Request sample : http://localhost:8080/badip/clientip/{clientip}
	 * Response sample :{"clientIP":"202.100.100.1", "isBadIP":true} 
	 * @throws NoSuchAlgorithmException 
	 * @throws ParseException
	 */
	@RequestMapping(method = RequestMethod.GET, value = "/badip/clientip/{clientip:.+}")
	public BadIP getBadIP(@PathVariable("clientip") String clientip) throws NoSuchAlgorithmException, ParseException {
		Object mObject = null;
		BadIP badIP = new BadIP() ;
		if (clientip.length() > 0 ){
 			try {
 				badIP.setClientIP(clientip);
 				badIP.setIsBadIP(false);
 				mObject = memcachedClient.get(md5Hashing(xNameSpace,badIP.getClientIP()));
 				if (mObject != null){
 					JSONParser parser = new JSONParser();
 					JSONObject json = (JSONObject) parser.parse(mObject.toString());
 					badIP.setClientIP(json.get("clientIP").toString());
 					badIP.setIsBadIP(Boolean.parseBoolean(json.get("isBadIP").toString()));
 				}				
			} catch (TimeoutException e) {
				logger.error("TimeoutException");
			} catch (InterruptedException e) {
				logger.error("InterruptedException");
			} catch (MemcachedException e) {
				logger.error("MemcachedException");
			}
 		}
		return badIP;
	}

	/***
	 * Delete the bad guy's info
	 * Request sample : http://localhost:8080/badguy/delete/userid/{userid}
	 * Response sample : {"userID":"FS00000001", "isBadGuy":false} 
	 * @throws ParseException 
	 */
	@RequestMapping(method=RequestMethod.DELETE, value = "/badguy/delete/userid/{userid}")
	public BadGuy removeBadGuy(@PathVariable("userid") String userid) throws NoSuchAlgorithmException, ParseException {
		BadGuy badGuy = new BadGuy() ;
		if (userid.length() >0){
 			try {
 				badGuy.setUserID(userid);
 				badGuy.setIsBadGuy(false);
 				memcachedClient.delete(md5Hashing(xNameSpace,badGuy.getUserID()));
 				updateAllItemsKey(allBadGuysKey, badGuy.getUserID(), "DELETE");
			} catch (TimeoutException e) {
				logger.error("TimeoutException");
			} catch (InterruptedException e) {
				logger.error("InterruptedException");
			} catch (MemcachedException e) {
				logger.error("MemcachedException");
			}
 		}
		return badGuy;
	}
	/***
	 * Delete the bad ip info
	 * Request sample : http://localhost:8080/badip/delete/clientip/{clientip}
	 * Response sample : {"clientIP":"202.100.100.1","isBadIP":false} 
	 * @throws ParseException 
	 */
	@RequestMapping(method=RequestMethod.DELETE, value = "/badip/delete/clientip/{clientip:.+}")
	public BadIP removeBadIP(@PathVariable("clientip") String clientip) throws NoSuchAlgorithmException, ParseException {
		BadIP badIP = new BadIP() ;
		if (clientip.length() > 0){
 			try {
 				badIP.setClientIP(clientip);
 				badIP.setIsBadIP(false);
 				memcachedClient.delete(md5Hashing(xNameSpace,badIP.getClientIP()));
 				updateAllItemsKey(allBadIPsKey,badIP.getClientIP(),"DELETE");
			} catch (TimeoutException e) {
				logger.error("TimeoutException");
			} catch (InterruptedException e) {
				logger.error("InterruptedException");
			} catch (MemcachedException e) {
				logger.error("MemcachedException");
			}
 		}
		return badIP;
	}
	/***
	 * find all bad guys list
	 * @throws ParseException 
	 * @throws NoSuchAlgorithmException 
	 */
	@RequestMapping(method = RequestMethod.GET,value="/badguy/all")
	public List<BadGuy> findAllBadGuys() throws ParseException, NoSuchAlgorithmException{
		List<BadGuy> glist = new ArrayList<>();
		List<String> mlist = null;
		Object mObject = null;
		try {
			mObject = memcachedClient.get(allBadGuysKey);
			if (mObject != null){
				mlist = new ArrayList<String>(Arrays.asList(mObject.toString().split(",")));
				for(String mSku:mlist){
					if (mSku.trim().length() > 0) {
						glist.add(getBadGuy(mSku));
					}
				}
			}else{
				glist.add(new BadGuy());
			}
		} catch (TimeoutException e) {
			logger.error("TimeoutException");
		} catch (InterruptedException e) {
			logger.error("InterruptedException");
		} catch (MemcachedException e) {
			logger.error("MemcachedException");
		}
		return glist;
		
	}
	/***
	 * find all bad ips info
	 * @throws ParseException 
	 * @throws NoSuchAlgorithmException 
	 */
	@RequestMapping(method = RequestMethod.GET,value="/badip/all")
	public List<BadIP> findAllBadIPs() throws ParseException, NoSuchAlgorithmException{
		List<BadIP> glist = new ArrayList<>();
		List<String> mlist = null;
		Object mObject = null;
		try {
			mObject = memcachedClient.get(allBadIPsKey);
			if (mObject != null){
				mlist = new ArrayList<String>(Arrays.asList(mObject.toString().split(",")));
				for(String mSku:mlist){
					if (mSku.trim().length() > 0) {
						glist.add(getBadIP(mSku));
					}
				}
			}else{
				glist.add(new BadIP());
			}
		} catch (TimeoutException e) {
			logger.error("TimeoutException");
		} catch (InterruptedException e) {
			logger.error("InterruptedException");
		} catch (MemcachedException e) {
			logger.error("MemcachedException");
		}
		return glist;
		
	}
	/***
	 * store the key index for the whole inventory system
	 * allItemsKey(xAllItemsKey):xxx,xxxx,xxxx
	 * @throws ParseException 
	 */
	public void updateAllItemsKey(String allItemsKey,String theItemKey,String mode) throws ParseException {
		Object mObject = null;
		List<String> mlist = null;
		String tmpItemsKey = null;
		long timeMillis = System.currentTimeMillis();
		long timeSeconds = TimeUnit.MILLISECONDS.toSeconds(timeMillis);
		int expirationValue = (int) (timeSeconds + 24*60*60*365);
		try {
			mObject = memcachedClient.get(allItemsKey);
			if (mObject != null){
				mlist = new ArrayList<String>(Arrays.asList(mObject.toString().split(",")));
				if (mode == "ADD"){
					//avoid the duplicated key issue
					if (mlist.contains(new String(theItemKey)) == false){mlist.add(theItemKey);}
				}else{
					mlist.remove(theItemKey);
				}
				tmpItemsKey = mlist.toString().replace("[", "").replace("]", "").replace(" ", "").trim() + ",";
				memcachedClient.replace(allItemsKey, expirationValue, tmpItemsKey);
			}else{
				tmpItemsKey = theItemKey + ",";
				memcachedClient.add(allItemsKey, expirationValue, tmpItemsKey);
			}
		} catch (TimeoutException e) {
			logger.error("TimeoutException");
		} catch (InterruptedException e) {
			logger.error("InterruptedException");
		} catch (MemcachedException e) {
			logger.error("MemcachedException");
		}
	}
	/***
	 * validate the client ip and userid.
	 * Request sample : http://localhost:8080/validate/sid/{sid}/userid/{userid/clientip/{clientip}}
	 * Response sample :{"userID":"FS00000001", "isBadGuy":true,"clientIP":"202.100.100.1","isBadIP":false,"isAllowed":true} 
	 * @throws NoSuchAlgorithmException 
	 * @throws ParseException 
	 * @throws JsonProcessingException 
	 */
	@SuppressWarnings("unchecked")
	@RequestMapping(method = RequestMethod.GET ,value = "/validate/sid/{sid}/userid/{userid}/clientip/{clientip:.+}")	
	public SafeValidationR doSafeValidtion(HttpServletRequest httpRequest, HttpServletResponse httpResponse, @PathVariable("sid") String sid, @PathVariable("clientip") String clientip, @PathVariable("userid") String userid) throws NoSuchAlgorithmException, ParseException, JsonProcessingException {
		Object mObject = null;
		SafeValidationR safeValidationR = new SafeValidationR();
		long startTime = System.currentTimeMillis();
		/*** generate request parameters */
		JSONObject paramsJSON = new JSONObject();
		paramsJSON.put("sid", sid);
		paramsJSON.put("clientip", clientip);
		paramsJSON.put("userid", userid);

		if (sid.length() > 0 && userid.length() > 0 && clientip.length() > 0){
 			try {
 				safeValidationR.setSessionID(sid);
 				safeValidationR.setUserID(userid);
 				safeValidationR.setIsBadGuy(false);
 				/*** rate limiter checking ***/
 				if (SafeProtectorApplication.rateLimiter.consume(consumeCount) == false){
 					safeValidationR.setIsThrottled(true);
 					long endTime = System.currentTimeMillis();
 					fsAccessLogger.doAccessLog(httpRequest, httpResponse, safeValidationR.getSessionID(), CurrentStep.SAFEPROTECTOR.msgBody(), paramsJSON.toString(), endTime-startTime, safeValidationR);
 					return safeValidationR;
 				}
 				mObject = memcachedClient.get(md5Hashing(xNameSpace,safeValidationR.getUserID()));
 				if (mObject != null){
 					JSONParser parser = new JSONParser();
 					JSONObject json = (JSONObject) parser.parse(mObject.toString());
 					safeValidationR.setIsBadGuy(Boolean.parseBoolean(json.get("isBadGuy").toString()));
 				}
 				safeValidationR.setClientIP(clientip);
 				safeValidationR.setIsBadIP(false);
 				mObject = memcachedClient.get(md5Hashing(xNameSpace,safeValidationR.getClientIP()));
 				if (mObject != null){
 					JSONParser parser = new JSONParser();
 					JSONObject json = (JSONObject) parser.parse(mObject.toString());
 					safeValidationR.setIsBadIP(Boolean.parseBoolean(json.get("isBadIP").toString()));
 				}
 				safeValidationR.doSafeValidation();

			} catch (TimeoutException e) {
				logger.error("TimeoutException:"+ safeValidationR.getSessionID());
			} catch (InterruptedException e) {
				logger.error("InterruptedException:"+ safeValidationR.getSessionID());
			} catch (MemcachedException e) {
				logger.error("MemcachedException:"+ safeValidationR.getSessionID());
			} finally{
				long endTime = System.currentTimeMillis();
				fsAccessLogger.doAccessLog(httpRequest, httpResponse, safeValidationR.getSessionID(), CurrentStep.SAFEPROTECTOR.msgBody(), paramsJSON.toString(), endTime-startTime, safeValidationR);
			}
 		}else{
 			long endTime = System.currentTimeMillis();
			fsAccessLogger.doAccessLog(httpRequest, httpResponse, safeValidationR.getSessionID(), CurrentStep.SAFEPROTECTOR.msgBody(), paramsJSON.toString(), endTime-startTime, safeValidationR);
 		}
		return safeValidationR;
	}
}
