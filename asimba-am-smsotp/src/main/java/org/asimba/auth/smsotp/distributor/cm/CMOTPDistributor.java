/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see www.gnu.org/licenses
 * 
 * Asimba - Serious Open Source SSO - More information on www.asimba.org
 * 
 */
/**
 * CM Otp Distributor
 * 
 * Implementation for OpenASelect OTP Distributor using 
 * Corporate Mobile Messaging services
 * 
 * More information http://www.cm.nl
 * 
 * (c) Cozmanova bv
 * 
 * @author mdobrinic
 * @author Cozmanova bv
 *  
 */
package org.asimba.auth.smsotp.distributor.cm;


import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.log4j.Logger;
import org.asimba.auth.smsotp.OTP;
import org.asimba.auth.smsotp.distributor.IOTPDistributor;
import org.asimba.auth.smsotp.distributor.OTPDistributorException;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.Engine;

public class CMOTPDistributor implements IOTPDistributor {
	
	protected IConfigurationManager _oConfigManager;
	private Logger _oLogger = Logger.getLogger(CMOTPDistributor.class);

	/**
	 * Internal status: is Distributor component started?
	 */
	protected boolean _bStarted;
	
    /**
     * Configurable URL of the CM service
     */
    protected String _sUrl;
    protected URL _oURL;

    /**
     * CustomerID, login and password to authenticate to CM service
     */
    private Integer _oiCustomerID;
    private String _sLogin;
    private String _sPassword;
    
    /**
     * Configurable sender-name of the SMS message
     * As documented: 
     * can be numeric or alphanumeric. If originator is alphanumeric maximum 
     * length is 11 characters. If numeric, then maximum length is 17 
     * characters. Numeric originators (MSISDN’s) must start with 
     * 00<country code>, e.g. 0031 for The Netherlands.
     */
    protected String _sFrom;

    /**
     * The user attribute that contains the phonenr to send the 
     * SMS message to
     * ?? in 0031xxxxxxxx format, or is +31xxxx also allowed ??
     */
    protected String _sPhonenrAttribute;

    /**
     * Message template that is used to format the OTP
     * This is text, with the special code ':1' replaced by the password
     */
    protected String _sMessageTemplate;


    /**
     * Default constructor
     */
    public CMOTPDistributor() {
    	_bStarted = false;
    }
    
    
	/**
	 * Initialize CMOTPDistributor from configuration. Valid configuration can contain:<br/>
	 * <url>urlvalue</url> (required) the CM URL to send SMS request to; 
	 *   consider value: https://secure.cm.nl/smssgateway/cm/gateway.ashx<br/>
	 * <customerid>numeric</customerid> (required) _number_ of the CM customerid<br/> 
	 * <login>string</login> (required) loginname of the account at CM<br/>
	 * <password>string</password> (required) password of the useraccount at CM<br/>
	 * <from>string</from> (optional) name of the originator of the SMS message; defaults to server@id<br/>
	 * <phonenrattribute>string</phonenrattribute> (required) name of the user attribute that contains the phonenr to send the SMS to the user to<br/>
	 * <messagetemplate>string</messagetemplate> (optional) Message, with %1 being replaced by the password
	 */
	public void start(IConfigurationManager oConfigurationManager, Element eConfig)
		throws OAException 
	{
        if ((eConfig == null) || (oConfigurationManager == null))
        {
            _oLogger.error("No configuration supplied");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }

		_oConfigManager = oConfigurationManager;

        _sUrl = _oConfigManager.getParam(eConfig, "url");
        if(_sUrl== null)
        {
            _oLogger.error("No 'url' element found for 'CMOTPDistributor");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }

		try {
			_oURL = new URL(_sUrl);
		} catch (MalformedURLException mue) {
			_oLogger.fatal("Invalid URL configured for CMOTPDistributor'");
			throw new OAException(SystemErrors.ERROR_INIT);
		}

		
		try {
			_oiCustomerID = Integer.decode(_oConfigManager.getParam(eConfig, "customerid"));
			if (_oiCustomerID==null) {
				throw new NumberFormatException();
			}
		} catch (NumberFormatException nfe) {
			_oLogger.fatal("Invalid 'customerid' configured for CMOTPDistributor': "+_oiCustomerID);
			throw new OAException(SystemErrors.ERROR_INIT);
		}
		
		_sLogin = _oConfigManager.getParam(eConfig, "login");
        if((_sLogin== null) || _sLogin.equals(""))
        {
            _oLogger.error("No 'login' element found for 'CMOTPDistributor'");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
		
		_sPassword = _oConfigManager.getParam(eConfig, "password");
        if((_sPassword== null) || _sPassword.equals(""))
        {
            _oLogger.error("No 'password' element found in 'CMOTPDistributor'");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
		
		_sFrom = _oConfigManager.getParam(eConfig, "from");
        if((_sFrom== null) || _sFrom.equals(""))
        {
            _oLogger.debug("No 'from' element found for 'CMOTPDistributor', using defaults");
            
            // Default to the ID of the server
            _sFrom = Engine.getInstance().getServer().getOrganization().getID();
        }
		
        _sPhonenrAttribute = _oConfigManager.getParam(eConfig, "phonenrattribute");
        if((_sPhonenrAttribute==null) || _sPhonenrAttribute.equals(""))
        {
            _oLogger.error("No 'phonenrattribute' element found for 'CMOTPDistributor'");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        _sMessageTemplate = _oConfigManager.getParam(eConfig, "messagetemplate");
        if ((_sMessageTemplate==null) || _sMessageTemplate.equals("")) {
        	_oLogger.debug("No 'messagetemplate' configured, using default");
        	_sMessageTemplate = "Password is :1";
        }
		
		_bStarted = true;
		
		_oLogger.info("Started CMOTPDistributor");
	}
	
	
	/**
	 * Stop the CMOTPDistributor component
	 */
	public void stop() {
		_bStarted = false;

	}
    
    
	/**
	 * Distribute the provided OTP to the provided user 
	 */
	public int distribute(OTP oOtp, IUser oUser) throws OAException {
		// Are we operational?
		if (!_bStarted) {
			throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
		}
		
		String sMsg, sPostbody, sResult;
		String sRecipient;
		IAttributes oUserAttributes;
		
		oUserAttributes = oUser.getAttributes();
		if (! oUserAttributes.contains(_sPhonenrAttribute)) {
			_oLogger.error("Unknown phonenr for user " + oUser.getID() + 
					"; missing attribute '"+_sPhonenrAttribute+"'");
			throw new OTPDistributorException(0);
		}
		
		sRecipient = (String) oUserAttributes.get(_sPhonenrAttribute);
		sMsg = getMessageForPwd(oOtp.getValue());
		sPostbody = createPostBody(sMsg, sRecipient);
		
		sResult = postPostBody(_oURL, sPostbody);
		if (sResult != null && sResult.length()>0) {
			_oLogger.error("Error sending message; gateway said: '"+sResult+"'");
			throw new OTPDistributorException(1);
		}
		
		// All OK, mark the SMS as being sent and return:
		oOtp.registerSent(Long.valueOf(System.currentTimeMillis()));
		
		return 0;
	}
	
	
	/**
	 * Override this implementation to provide for localization support etc.
	 * @param sPassword Password value to include in the message
	 * @return Formatted message to sent to user.
	 */
	protected String getMessageForPwd(String sPassword)
	{
		return _sMessageTemplate.replaceAll(":1", sPassword); 
	}
	
	
	/**
	 * Create the data that needs to be posted to the SMS gateway
	 * @param sMessage Message to send to recipient
	 * @param sRecipient Phonenr of recipient to use
	 * @return The response of the remote service; this should be empty when 
	 *   everything succeeded, and will contain an errormessage if something
	 *   went wrong 
	 * @throws OAException thrown upon system errors, like IO, etc.
	 */
	protected String createPostBody(String sMessage, String sRecipient) 
		throws OAException 
	{
		try {
			ByteArrayOutputStream oBAOS = new ByteArrayOutputStream();
			DocumentBuilderFactory oDBFactory = DocumentBuilderFactory.newInstance();
			oDBFactory.setNamespaceAware(true);
			
			DocumentBuilder oDocBuilder = oDBFactory.newDocumentBuilder();
			//Create blank DOM Document
			DOMImplementation oDOMImpl = oDocBuilder.getDOMImplementation();
			Document oDocument = oDOMImpl.createDocument(null, "MESSAGES", null); 
			//Document doc = docBuilder.newDocument();
			
			//create the root element
			Element oElRoot = oDocument.getDocumentElement();
			//all it to the xml tree
			
			//create child element
			Element oElCustomer = oDocument.createElement("CUSTOMER"); 
			//Add the attribute to the child 
			oElCustomer.setAttribute("ID",""+_oiCustomerID.toString()); 
			oElRoot.appendChild(oElCustomer);
			
			Element oElUser = oDocument.createElement("USER");
			oElUser.setAttribute("LOGIN", _sLogin); 
			oElUser.setAttribute("PASSWORD", _sPassword);
			oElRoot.appendChild(oElUser);
			
			Element oElMessage = oDocument.createElement("MSG"); 
			oElRoot.appendChild(oElMessage);
			
			Element oElFrom = oDocument.createElement("FROM"); 
			Text oTxtFrom = oDocument.createTextNode("FROM"); 
			oTxtFrom.setNodeValue(_sFrom); 
			oElFrom.appendChild(oTxtFrom); 
			oElMessage.appendChild(oElFrom);
			
			Element oElBody = oDocument.createElement("BODY");
			Text oTxtBody = oDocument.createTextNode("BODY"); 
			oTxtBody.setNodeValue(sMessage); 
			oElBody.appendChild(oTxtBody); 
			oElBody.setAttribute("TYPE", "TEXT"); 
			oElMessage.appendChild(oElBody);
			
			Element oElTo = oDocument.createElement("TO");
			Text oTxtTo = oDocument.createTextNode("TO"); 
			oTxtTo.setNodeValue(sRecipient); 
			oElTo.appendChild(oTxtTo);
			oElMessage.appendChild(oElTo);
			
			TransformerFactory oTransformerFactory = TransformerFactory.newInstance(); 
			Transformer oTransformer = oTransformerFactory.newTransformer();
			oTransformer.setOutputProperty(OutputKeys.INDENT, "yes");
			
			Source oDomSource = new DOMSource(oDocument);
			Result oResult = new StreamResult(oBAOS); 
			oTransformer.transform(oDomSource, oResult); 
			return oBAOS.toString();
			
		} catch (ParserConfigurationException e) {
            _oLogger.error("ParserConfigurationException occurred when building arguments for CMOTPDistributor: "
            		+e.getMessage());
            throw new OAException(SystemErrors.ERROR_INTERNAL);
		} catch (TransformerConfigurationException e) {
            _oLogger.error("TransformerConfigurationException occurred when building arguments for CMOTPDistributor: "
            		+e.getMessage());
            throw new OAException(SystemErrors.ERROR_INTERNAL);
		} catch (TransformerException e) {
            _oLogger.error("TransformerException occurred when building arguments for CMOTPDistributor: "
            		+e.getMessage());
            throw new OAException(SystemErrors.ERROR_INTERNAL);
		}
	}

	
	/**
	 * Helper function to post data to a URL; returns the returned data, or null when
	 * an error occurred
	 * @param oUrl
	 * @param sBodydata
	 * @return
	 */
	private String postPostBody(URL oUrl, String sBodydata)
		throws OAException
	{
		
		URLConnection oConn;
		OutputStreamWriter oOut;
		BufferedReader oIn;
		String s;
		StringBuilder sb;
		
		try {
			oConn = oUrl.openConnection();
			oConn.setDoOutput(true);
			oOut = new OutputStreamWriter(
					oConn.getOutputStream());
			oOut.write(sBodydata);
			oOut.flush();
			
			// Get the response
			oIn = new BufferedReader(
					new InputStreamReader(
							oConn.getInputStream())); 
			
			sb = new StringBuilder();
			
			while ((s = oIn.readLine()) != null) {
				sb.append(s);
			}
			oOut.close();
			oIn.close();
			
			return sb.toString();
		} catch (IOException e) {
            _oLogger.error("IOException occurred when sending data with CMOTPDistributor: "
            		+e.getMessage());
            throw new OAException(SystemErrors.ERROR_INTERNAL);
		}
	}
}
