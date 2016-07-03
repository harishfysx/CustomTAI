package com.tets.tai;


import java.util.Enumeration;
import java.util.HashMap;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.ibm.websphere.security.WebTrustAssociationException;
import com.ibm.websphere.security.WebTrustAssociationFailedException;
import com.ibm.wsspi.security.tai.TAIResult;
import com.ibm.wsspi.security.tai.TrustAssociationInterceptor;

/**
* Custom Login Module
*
* Project imports the jar wssec.jar for development purposes.
* Found in the server runtime lib directory ($irad_home$\runtimes\base_v6\)
*
*
**/
public class CustomPortalTAI implements TrustAssociationInterceptor
{
 private static final String VERSION = "Custom TAI version 1.0 \n Author: SirCrofty \n " + "Last Updated: March 1, 2008";

 private static final String TYPE = "--- Custom TAI --- \n Custom Trust Assocation Interceptor for WebSphere Portal Application";
 
 //String propVal = System.getProperty("my.custom.property");

 HashMap sharedState = null;

 /**
 * Constructor
 *
 **/
 public CustomPortalTAI()
 {
  sharedState = new HashMap();
 }

 /**
 * (non-Javadoc)
 * @see com.ibm.wsspi.security.tai.TrustAssociationInterceptor#initialize(java.util.Properties)
 * @param arg0
 * @return
 * @throws com.ibm.websphere.security.WebTrustAssociationFailedException
 *
 **/
 public int initialize(Properties props) throws WebTrustAssociationFailedException

 {
	 String propVal = props.getProperty("my.custom.property");
	 System.out.println("Priting custom property from websphere"+propVal);
  return 0;
 }


 /**
 * (non-Javadoc)
 * @see com.ibm.wsspi.security.tai.TrustAssociationInterceptor#isTargetInterceptor(javax.servlet.http.HttpServletRequest)
 * @param arg0
 * @return
 * @throws com.ibm.websphere.security.WebTrustAssociationException
 *
 **/
 public boolean isTargetInterceptor(HttpServletRequest req) throws WebTrustAssociationException
 {
       System.out.println("*********** Custom TAI ******************");
  System.out.println("Determining if this TAI should handle the incoming request...");
  Enumeration e = req.getHeaderNames();
  while (e.hasMoreElements()) {
      String name = (String)e.nextElement();
      String value = req.getHeader(name);
      System.out.println(name + " = " + value);
  }
  String userId=req.getHeader("SM_USER");
  if (userId!=null && !userId.trim().isEmpty())
  {
    System.out.println("Custom TAI is being used to establish trust for user"+req.getHeader("SM_USER"));
  
    return true;
  }


  System.out.println("Bypassing Custom TAI, did not find a user ID in the request");
  return false;
 }
 /**
 * (non-Javadoc)
 * @see com.ibm.wsspi.security.tai.TrustAssociationInterceptor#negotiateValidateandEstablishTrust(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
 * @param arg0
 * @param arg1
 * @return
 * @throws com.ibm.websphere.security.WebTrustAssociationFailedException
 *
 **/
 public TAIResult negotiateValidateandEstablishTrust(HttpServletRequest req, HttpServletResponse resp)
 throws WebTrustAssociationFailedException
 {
  String smrealm= req.getHeader("SM_REALM");
  String userId= req.getHeader("SM_USER");
  if (userId!=null)
  {
    System.out.println("*********** CustomTAI *****************");
    System.out.println("smrealm= " + smrealm);

    return TAIResult.create(HttpServletResponse.SC_OK, userId);
  }
  else
  {
    return TAIResult.create(HttpServletResponse.SC_FORBIDDEN, userId);
  }
 }

 /**
 * @see com.ibm.wsspi.security.tai.TrustAssociationInterceptor#cleanup()
 *
 *
 **/
 public void cleanup()
 {
  sharedState = null;
 }


 /**
 * @see com.ibm.wsspi.security.tai.TrustAssociationInterceptor#getType()
 * @return
 *
 **/
 public String getType()
 {
  return TYPE + " \n " + this.getClass().getName();
 }

 /**
 *
 * @see com.ibm.wsspi.security.tai.TrustAssociationInterceptor#getVersion()
 * @return
 *
 **/
 public String getVersion()
 {
  return VERSION;
 }
}