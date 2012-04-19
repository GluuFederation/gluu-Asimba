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
package org.asimba.auth.smsotp.generator;

import java.security.SecureRandom;

import org.apache.log4j.Logger;
import org.asimba.auth.smsotp.OTP;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.user.IUser;

public class BasicOTPGenerator 
	implements IOTPGenerator 
{
	private IConfigurationManager _oConfigManager;
    private static final Logger _oLogger = Logger.getLogger(BasicOTPGenerator.class);;
    
    private boolean _bStarted;
	private int _iPasswordLength;
	private long _lAllowedAge;
	
	private static SecureRandom _oRandomGenerator;
	
	
	public BasicOTPGenerator()
	{
        _bStarted = false;
	}
	
	
	/**
	 * Authenticate a user
	 */
	public boolean authenticate(IUser oUser, OTP oOtp, String sUsername,
			String sPassword) 
		throws OAException, UserException 
	{
		if (!_bStarted) {
			throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
		}

		// Possibly perform some integrity checking/assertions before making compare:
		if (oOtp.getTimesSent() == 0) {
			_oLogger.warn("User tried to authenticate with unsent OneTimePassword.");
			return false;
		}
		
		if (oOtp.getTimeSent().longValue() < (System.currentTimeMillis() - _lAllowedAge) ) {
			_oLogger.warn("User tried to authenticate with expired OneTimePassword.");
			return false;
		}
		
		// Perform verification
		return (sPassword.equals(oOtp.getValue()));
	}

	
	/**
	 * Generates a new OneTimePassword instance for the supplied user.
	 */
	public OTP generate(IUser oUser) 
		throws OAException, UserException 
	{
		if (!_bStarted) {
			throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
		}
		
		StringBuffer sbNewPassword=new StringBuffer();
        int i=0;
        while(i < _iPasswordLength) {
        	sbNewPassword.append(_oRandomGenerator.nextInt(10));
        	i++;
        }
        
		OTP oResultOtp = new OTP();
        oResultOtp.setTimeGenerated(Long.valueOf(System.currentTimeMillis()));
        oResultOtp.setTimesSent(0);
        oResultOtp.setTimeSent(new Long(0));
        oResultOtp.setValue(sbNewPassword.toString());
        
		return oResultOtp;
	}
	

	/**
	 * Initialize BasicOtpGenerator from configuration. Valid configuration can contain:<br/>
	 * <salt>longvalue</salt> (optional) used to salt the randomgenerator from external source; defaults to systemtime<br/>
	 * <length>intvalue</length> (optional) length of the generated password; defaults to 6 characters<br/>
	 * <allowed_age>intvalue</allowed_age> (optional) number of seconds a generated otp is valid; defaults to 600<br/>
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

		// Initialize RandomGenerator from configuration
		String sSalt = _oConfigManager.getParam(eConfig, "salt");
		if ((sSalt == null) || sSalt.equals(""))
        {
			_oLogger.warn(
                    "No 'salt' found in BasicOtpGenerator configuration; using default value.");
			sSalt = Long.toString(System.currentTimeMillis());
        }
		
		long lSalt;
		
        try
        {
            lSalt = Integer.parseInt(sSalt);
        }
        catch(NumberFormatException e)
        {
            _oLogger.error("Invalid 'salt' item BasicOtpGenerator configuration.", e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
		
		_oRandomGenerator = new SecureRandom();
		_oRandomGenerator.setSeed(lSalt);
		
		String sPasswordLength = _oConfigManager.getParam(eConfig, "length");
		if ((sPasswordLength == null) || sPasswordLength.equals(""))
        {
			_oLogger.debug("No 'length' found in BasicOtpGenerator configuration; using default value.");
			sSalt = "6";
        }
		
        try
        {
            _iPasswordLength = Integer.parseInt(sPasswordLength);
        }
        catch(NumberFormatException e)
        {
            _oLogger.error("Invalid 'length' item BasicOtpGenerator configuration.", e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }

        String sAllowedAge = _oConfigManager.getParam(eConfig, "allowed_age");
		if ((sAllowedAge == null) || sAllowedAge.equals(""))
        {
			_oLogger.debug("No 'allowed_age' found in BasicOtpGenerator configuration; using default value.");
			sAllowedAge = "600";
        }
		
        try
        {
        	_lAllowedAge = 1000 * Integer.parseInt(sAllowedAge);	// convert from seconds to milliseconds
        }
        catch(NumberFormatException e)
        {
            _oLogger.error("Invalid 'allowed_age' item BasicOtpGenerator configuration.", e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
		_bStarted = true;
		
		_oLogger.info("Started genersstor BasicOtpGenerator");
	}


	public void stop() 
	{
		_bStarted = false;
	}

}
