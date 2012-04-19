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
package org.asimba.auth.smsotp.distributor.mollie;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.ArrayList;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.asimba.auth.smsotp.OTP;
import org.asimba.auth.smsotp.distributor.IOTPDistributor;
import org.asimba.auth.smsotp.distributor.OTPDistributorException;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.Engine;

public class MollieOTPDistributor 
	implements IOTPDistributor 
{
	protected IConfigurationManager _oConfigurationManager;
    private static Logger _oLogger = Logger.getLogger(MollieOTPDistributor.class);
    
    /**
     * Configurable URL of the Mollie service
     */
    protected String _sUrl;
    protected URL _oURL;
    
    /**
     * Username and Password to authenticate to Mollie service
     */
    private String _sUsername;
    private String _sPassword;
    
    /**
     * Configurable sender-name of the SMS message
     */
    protected String _sSenderName;
    
    /**
     * The user attribute that contains the phonenr to send the 
     *   SMS message to
     */
    protected String _sPhonenrAttribute;
    
    /**
     * Message template that is used to format the OTP
     * This is text, with the special code ':1' replaced by the password
     */
    protected String _sMessageTemplate;
    
    
    private boolean _bStarted;

    public MollieOTPDistributor()
    {
        _bStarted = false;
    }
    
    /**
     * Distribute the OTP to the user<br/>
     * Requires a configured attribute to be present in the User's Attributes()-collection to
     * establish the phonenr to send the OneTimePassword to!<br/>
     * Updates Otp-instance to reflect the result of distributing the password (timessent, timesent)
     * 
     * Sources inspired by A-Select SMS AuthSP
     */
	public int distribute(OTP oOtp, IUser oUser) 
		throws OAException, OTPDistributorException
	{
		// Are we operational?
		if (!_bStarted) {
			throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
		}
		
		String sMsg;
		String sRecipient;
		IAttributes oUserAttributes;
		int returncode = 15;

		// Establish the phonenr to send message to
		oUserAttributes = oUser.getAttributes();
		if (! oUserAttributes.contains(_sPhonenrAttribute)) {
			_oLogger.error("Unknown phonenr for user " + oUser.getID() + 
					"; missing attribute '"+_sPhonenrAttribute+"'");
			throw new OTPDistributorException(returncode);
		}
		
		sRecipient = (String) oUserAttributes.get(_sPhonenrAttribute);
		
		// Establish message
		sMsg = getMessageForPwd(oOtp.getValue());

		// Establish URL
		StringBuffer sbData = new StringBuffer();

		try
		{
			ArrayList<String> params = new ArrayList<String>();

			// Depend on Apache Commons Lang for join
			params.add(StringUtils.join(new String[] {"gebruikersnaam", 
					URLEncoder.encode(_sUsername, "UTF-8")}, "="));
			
			params.add(StringUtils.join(new String[] {"wachtwoord", 
					URLEncoder.encode(_sPassword, "UTF-8")}, "="));

			params.add(StringUtils.join(new String[] {"afzender", 
					URLEncoder.encode(_sSenderName, "UTF-8")}, "="));

			params.add(StringUtils.join(new String[] {"bericht", 
					URLEncoder.encode(sMsg, "UTF-8")}, "="));
			
			params.add(StringUtils.join(new String[] {"ontvangers", 
					URLEncoder.encode(sRecipient, "UTF-8")}, "="));

			String sCGIString = StringUtils.join(params, "&");
			
			returncode++; // 16

			URLConnection oURLConnection = _oURL.openConnection();
			returncode++; // 17

			oURLConnection.setDoOutput(true);

			OutputStreamWriter oWriter = new OutputStreamWriter(oURLConnection.getOutputStream());
			oWriter.write(sCGIString);
			oWriter.flush();
			returncode++; // 18

			// Get the response
			BufferedReader oReader = new BufferedReader(new InputStreamReader(oURLConnection.getInputStream()));
			String sLine;

			if ((sLine = oReader.readLine()) != null)
			{
				returncode = Integer.parseInt(sLine);
			}

			if (returncode != 0)
			{
				_oLogger.error("Mollie could not send sms, returncode from Mollie: " + returncode + ".");
				throw new OTPDistributorException(returncode);
			}

			returncode++; // 19
			oWriter.close();
			oReader.close();
		}
		catch (NumberFormatException e)
		{
			_oLogger.error("Sending SMS, using \'" + _oURL.toString() + ", data=" + sbData.toString() + "\' failed due to number format exception!" + e.getMessage());
			throw new OTPDistributorException(returncode);
		}

		catch (Exception e)
		{
			_oLogger.error("Sending SMS, using \'" + _oURL.toString() + ", data=" + sbData.toString() + "\' failed (return code=" + returncode + ")! " + e.getMessage());
			throw new OTPDistributorException(returncode);
		}
		
		_oLogger.info("Sending to user "+oUser.getID()+" password with value "+oOtp.getValue());

		oOtp.registerSent(Long.valueOf(System.currentTimeMillis()));
		
		return returncode;
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
	 * Initialize MollieOtpDistributoir from configuration. Valid configuration can contain:<br/>
	 * <url>urlvalue</url> (required) the Mollie URL to send SMS request to<br/>
	 * <username>string</username> (required) name of the useraccount at Mollie<br/>
	 * <password>string</password> (required) password of the useraccount at Mollie<br/>
	 * <originator>string</originator> (optional) name of the originator of the SMS message; defaults to server@id<br/>
	 * <phonenrattribute>string</phonenrattribute> (required) name of the user attribute that contains the phonenr to send the SMS to the user to<br/>
	 */
	public void start(IConfigurationManager oConfigurationManager, Element eConfig)
		throws OAException 
	{
        if ((eConfig == null) || (oConfigurationManager == null))
        {
            _oLogger.error("No configuration supplied");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }

		_oConfigurationManager = oConfigurationManager;

        _sUrl = _oConfigurationManager.getParam(eConfig, "url");
        if(_sUrl== null)
        {
            _oLogger.error("No 'url' element found in 'MollieOtpDistributor");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }

		try {
			_oURL = new URL(_sUrl);
		} catch (MalformedURLException mue) {
			_oLogger.fatal("Invalid URL configured for MollieOtpDistributor'");
			throw new OAException(SystemErrors.ERROR_INIT);
		}

		_sUsername = _oConfigurationManager.getParam(eConfig, "username");
        if((_sUsername== null) || _sUsername.equals(""))
        {
            _oLogger.error("No 'username' element found in 'MollieOtpDistributor'");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
		
		_sPassword = _oConfigurationManager.getParam(eConfig, "password");
        if((_sPassword== null) || _sPassword.equals(""))
        {
            _oLogger.error("No 'password' element found in 'MollieOtpDistributor'");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
		
		_sSenderName = _oConfigurationManager.getParam(eConfig, "originator");
        if((_sSenderName== null) || _sSenderName.equals(""))
        {
            _oLogger.debug("No 'originator' element found in 'MollieOtpDistributor', using defaults");
            
            // Default to the ID of the server
            _sSenderName = Engine.getInstance().getServer().getOrganization().getID();
        }
		
        _sPhonenrAttribute = _oConfigurationManager.getParam(eConfig, "phonenrattribute");
        if((_sPhonenrAttribute==null) || _sPhonenrAttribute.equals(""))
        {
            _oLogger.error("No 'phonenrattribute' element found in 'MollieOtpDistributor'");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        _sMessageTemplate = _oConfigurationManager.getParam(eConfig, "messagetemplate");
        if ((_sMessageTemplate==null) || _sMessageTemplate.equals("")) {
        	_oLogger.debug("No 'messagetemplate' configured, using default");
        	_sMessageTemplate = "Password is :1";
        }
		
		_bStarted = true;
	}

	
	public void stop() {
		_bStarted = false;
	}

}
