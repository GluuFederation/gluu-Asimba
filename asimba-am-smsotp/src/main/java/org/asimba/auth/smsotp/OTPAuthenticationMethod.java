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
 * SMS/OneTimePassword authentication method.
 * 
 * Authenticate a user by checking a one-time-password 
 * The implementation is based on PasswordAuthenticationMethod. 
 * 
 * Can be used as a Web Authentication Method with Asimba SSO server
 * 
 * OTPAuthenticationMethod is the controller for OTP Authentication
 *
 * Part of Asimba
 * www.asimba.org
 *
 * @author mdobrinic@cozmanova.com
 * @author Cozmanova (www.cozmanova.com)
 */
package org.asimba.auth.smsotp;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.asimba.auth.smsotp.distributor.IOTPDistributor;
import org.asimba.auth.smsotp.distributor.OTPDistributorException;
import org.asimba.auth.smsotp.generator.IOTPGenerator;
import org.w3c.dom.Element;

import com.alfaariss.oa.DetailedUserException;
import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.idmapper.IIDMapper;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoException;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.server.Server;
import com.alfaariss.oa.engine.core.user.factory.IUserFactory;
import com.alfaariss.oa.sso.authentication.web.IWebAuthenticationMethod;
import com.alfaariss.oa.util.logging.UserEventLogItem;


public class OTPAuthenticationMethod
    implements IWebAuthenticationMethod
{
    private static Logger _oLogger = Logger.getLogger(OTPAuthenticationMethod.class);;
    private static Logger _oEventLogger = Logger.getLogger(Engine.EVENT_LOGGER);
    private IConfigurationManager _oConfigManager;
    private IUserFactory _oUserFactory;
    private Engine _oEngine;
	
    /**
     * _oOTPGenerator is responsible for generating a one time password, as
     * well as verifying whether a provided password is correct
     * Can be configurable, but defaults to a generic implementation
     */
    protected IOTPGenerator _oOTPGenerator;
    
    /**
     * _oOTPDistributor is reponsible for delivering the one time password
     * to the authenticating user
     */
    protected IOTPDistributor _oOTPDistributor;
    
    /**
     * _oIDMapper maps a session-established UserID to a 
     *   OTPAuthenticationMethod-UserID
     *   When null (not configured), it is ignored. 
     */
    protected IIDMapper _oIDMapper = null;

    protected final static String AUTHORITY_NAME =
        "OTPAuthenticationMethod";
    
    private final static String HASCAPTCHA = "hasCaptcha";
    private final static String CAPTCHA ="captcha";
    private final static String PASSWORD = "password";
    private final static String RESEND_OTP = "resend_otp";
    private final static String OTP_RESEND_RETRIES = "OTPResendRetries";
    
    private final static String OTP_NAME = "OTP";
    
    /** CAPTCHA_HASH */
    private final static String CAPTCHA_HASH = "##captcha_hash##";
    
    /**
     * _sIdTemplate, _sPwdTemplate: locations to the JSP template files that
     * deal with asking for the UserID and Password
     */
    private String _sIdTemplate, _sPwdTemplate;
    private String _sMethodID;
    private String _sFriendlyName;
    private int _iAllowedTries;
    private int _iAllowedOTPResends = 5;
    
    /**
     * _bDisableDistribute: default it is false; intended for testing purposes
     *   to eliminate the actual distribution, but instead writed the code to be distributed
     *   in the logfile (level DEBUG)<br/>
     *   Configurable as element &lt;disabledistribute&gt;[true/false]&lt;/disabledistribute&gt;
     */
    protected boolean _bDisableDistribute;
    
    
    private boolean _bEnabled;
    private boolean _bCaptchaEnabled;
    private CryptoManager _CryptoManager;

    
    /**
     * Default Constructor
     */
    public OTPAuthenticationMethod()
    {
        _bEnabled = false;	/* default: disable */
    }

    /**
     * Start/Initializes the Password Authentication Method.
     * 
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager,
        Element eConfig) throws OAException
    {
        try
        {
        	_oLogger.info("Starting " + OTPAuthenticationMethod.class.getName());
            if ((eConfig == null) || (oConfigurationManager == null))
            {
                _oLogger.error("No configuration supplied");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            _oConfigManager = oConfigurationManager;
            _oEngine = Engine.getInstance();

            _CryptoManager = _oEngine.getCryptoManager();
            if (_CryptoManager == null)
            {
                _oLogger.error("No crypto manager available");
                throw new OAException(SystemErrors.ERROR_INIT);
            }

            _oUserFactory = _oEngine.getUserFactory();
            if ((_oUserFactory == null) || !_oUserFactory.isEnabled())
            {
                _oLogger.error("User Factory is disabled");
                throw new OAException(SystemErrors.ERROR_INIT);
            }

            _sMethodID = _oConfigManager.getParam(eConfig, "id");
            if ((_sMethodID == null) || _sMethodID.equals(""))
            {
                _oLogger.error(
                "No 'id' found in 'method' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            _sFriendlyName = _oConfigManager.getParam(
                eConfig, "friendlyname");
            if ((_sFriendlyName == null) || _sFriendlyName.equals(""))
            {
                _oLogger.error(
                "No 'friendlyname' parameter found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            String sEnabled = _oConfigManager.getParam(
                eConfig, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _bEnabled = true;
                }
                else if (!sEnabled.equalsIgnoreCase("FALSE"))
                {
                    _oLogger.error("Unknown value in 'enabled' configuration item: "
                        + sEnabled);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            else
            {
                _bEnabled = true;
            }

            if (_bEnabled)
            {
                _bCaptchaEnabled = false;
                String sCaptchaEnabled = _oConfigManager.getParam(
                    eConfig, "captcha");
                if (sCaptchaEnabled != null)
                {
                    if (sCaptchaEnabled.equalsIgnoreCase("TRUE"))
                    {
                        _bCaptchaEnabled = true;
                    }
                    else if (!sCaptchaEnabled.equalsIgnoreCase("FALSE"))
                    {
                        _oLogger.error(
                            "Unknown value in 'captcha' configuration item: "
                            + sCaptchaEnabled);
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                }

                _oLogger.info(_bCaptchaEnabled ? "Captcha is enabled" :  "Captcha is not enabled");

                
                Element eIdTemplate = _oConfigManager.getSection(
                    eConfig, "idtemplate");
                if(eIdTemplate  == null)
                {
                    _oLogger.error(
                        "No 'idtemplate' section found in 'method' section with id: "
                        + _sMethodID);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }

                _sIdTemplate = _oConfigManager.getParam(
                	eIdTemplate ,"path");
                if((_sIdTemplate == null) || _sIdTemplate.equals(""))
                {
                    _oLogger.error(
                        "No 'path' attribute found in 'idtemplate' section within 'method' with id: "
                        + _sMethodID);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }

                Element ePwdTemplate = _oConfigManager.getSection(
                        eConfig, "pwdtemplate");
                if(ePwdTemplate  == null)
                {
                    _oLogger.error(
                        "No 'pwdtemplate' section found in 'method' section with id: "
                        + _sMethodID);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }

                _sPwdTemplate = _oConfigManager.getParam(
                	ePwdTemplate ,"path");
                if((_sPwdTemplate == null) || _sPwdTemplate.equals(""))
                {
                    _oLogger.error(
                        "No 'path' attribute found in 'pwdtemplate' section within 'method' with id: "
                        + _sMethodID);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                String sRetries = _oConfigManager.getParam(
                    eConfig, "retries");
                if ((sRetries == null) || sRetries.equals(""))
                {
                    _oLogger.error(
                        "No 'retries' found in 'method' section with id: "
                        + _sMethodID);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                try
                {
                    _iAllowedTries = Integer.parseInt(sRetries);
                    if(_iAllowedTries < 0)
                    {
                        _oLogger.error(
                            "Invalid 'retries' item found in 'method' section with id: "
                            + _sMethodID);
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                }
                catch(NumberFormatException e)
                {
                    _oLogger.error(
                        "Invalid 'retries' item found in 'method' section with id: "
                        + _sMethodID, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }

                Element eOTPHandler = _oConfigManager.getSection(
                    eConfig, "otp_handler");
                if (eOTPHandler == null)
                {
                    _oLogger.error(
                        "No 'otp_handler' section found in 'method' section with id: "
                        + _sMethodID);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }               

                String sOTPHandlerClass = _oConfigManager.getParam(
                    eOTPHandler, "class");
                if ((sOTPHandlerClass == null) || sOTPHandlerClass.equals(""))
                {
                    _oLogger.error("No class found for otp_handler");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }

                Class<?> cOTPHandler = null;
                try
                {
                    cOTPHandler = Class.forName(sOTPHandlerClass);
                }
                catch (Exception e)
                {
                    _oLogger.error("Could not find OTP Handler Class: "
                        + sOTPHandlerClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }

                try
                {
                    _oOTPGenerator =
                        (IOTPGenerator)cOTPHandler.newInstance();
                }
                catch(Exception e)
                {
                    _oLogger.error("Could not instantiate IOTPGenerator: "
                        + sOTPHandlerClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                _oOTPGenerator.start(_oConfigManager, eOTPHandler);
                if(_oLogger.isDebugEnabled())
                {
                    StringBuffer sb = new StringBuffer(_sMethodID);
                    sb.append(" handler '");
                    sb.append(sOTPHandlerClass).append("' started");
                    _oLogger.debug(sb.toString());
                }
                
                _bDisableDistribute = false;
                String sDisableDistribute = _oConfigManager.getParam(eConfig, "disabledistribute");
                if (sDisableDistribute != null) {
                	if (sDisableDistribute.equalsIgnoreCase("TRUE")) {
                		_bDisableDistribute = true;
                	} else if (!sDisableDistribute.equalsIgnoreCase("FALSE")) {
                		_oLogger.error("Unknown value 'disabledistribute' configured: "
                				+sDisableDistribute);
                		throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                	}
                }
                _oLogger.info("OneTimePassword distribution is " + (_bDisableDistribute?"disabled":"enabled"));
                
                Element eOTPDistributor = _oConfigManager.getSection(
                    eConfig, "otp_distributor");
                if (eOTPDistributor == null)
                {
                    _oLogger.error(
                        "No 'otp_distributor' section found in 'method' section with id: "
                        + _sMethodID);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }               

                String sOTPDistributorClass = _oConfigManager.getParam(
                    eOTPDistributor, "class");
                if ((sOTPDistributorClass == null) || sOTPDistributorClass.equals(""))
                {
                    _oLogger.error("No class found for otp_distributor");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                Class<?> cOTPDistributor = null;
                try
                {
                    cOTPDistributor = Class.forName(sOTPDistributorClass);
                }
                catch (Exception e)
                {
                    _oLogger.error("Could not find otp distributor class: "
                        + sOTPDistributorClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }

                try
                {
                    _oOTPDistributor =
                        (IOTPDistributor)cOTPDistributor.newInstance();
                }
                catch(Exception e)
                {
                    _oLogger.error("Could not instantiate otp distributor: "
                        + sOTPDistributorClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                _oOTPDistributor.start(_oConfigManager, eOTPDistributor);
                if(_oLogger.isDebugEnabled())
                {
                    StringBuffer sb = new StringBuffer(_sMethodID);
                    sb.append(" handler '");
                    sb.append(sOTPDistributorClass).append("' started");
                    _oLogger.debug(sb.toString());
                }
                

                //Create mapper
                Element eIDMapper = _oConfigManager.getSection(
                    eConfig, "idmapper");
                if (eIDMapper != null)
                {
                    _oIDMapper = createMapper(eIDMapper);
                }
            }
        }
        catch (OAException e)
        {
            _oLogger.error(
                "Error during start of OneTimePassword authentication method");
            throw e;
        }
        catch (Exception e)
        {
            _oLogger.fatal(
                "Internal error during start of OneTimePassword authentication method",
                e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
    	_oLogger.info("Started " + OTPAuthenticationMethod.class.getName() + ": " + _sMethodID);

    }

    /**
     * Restart the OTPAuthenticationMethod
     * 
     * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
     */
    public void restart(Element eConfig) throws OAException
    {
        synchronized(this)
        {
            stop();
            start(_oConfigManager, eConfig);
        }
    }

    /**
     * Returns the OTPAuthenticationMethod Method ID.
     * 
     * @see com.alfaariss.oa.sso.authentication.web.IWebAuthenticationMethod#getID()
     */
    public String getID()
    {
        return _sMethodID;
    }

    /**
     * Returns whether the OTPAuthenticationMethod is enabled or not.
     * @see com.alfaariss.oa.api.IManagebleItem#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }

    /**
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }

    /**
     * Returns the OTPAuthenticationMethod Authority Name.
     * 
     * @see IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return AUTHORITY_NAME + _sMethodID;
    }

    /**
     * Authenticate the user. 
     * 
     * @see IWebAuthenticationMethod#authenticate(
     *  HttpServletRequest, HttpServletResponse, ISession)
     */
    public UserEvent authenticate(HttpServletRequest oRequest,
            HttpServletResponse oResponse, ISession oSession) throws OAException
    {
        ISessionAttributes oAttributes = null;
        Integer oiRetries;
        
        IUser oUser = null;
        OTP oOTP = null;
        
        int iTries = _iAllowedTries;	// Number of tries left in this AuthMethod session
        UserEvent userEvent = null;
        String sUserId = null;
        boolean bRetries = true;		// Is this request an authentication attempt? default: yes.
        Vector<Enum> warnings = new Vector<Enum>();
        String sUserPassword;

        try 
        {
            // Establish the number of tries from current session 
            oAttributes = oSession.getAttributes();
            oiRetries = ((Integer)oAttributes.get(
                OTPAuthenticationMethod.class,
                _sMethodID + RETRIES_ATTRIBUTE_NAME));
            
            if (oiRetries != null) {
            	iTries = oiRetries.intValue();
            }
            
            // Try to establish user from current session:
	        oUser = oSession.getUser();
	        if(oUser == null) {
	            // If no user in session, check forced user
	            sUserId = oSession.getForcedUserID();
	            if (sUserId == null) {
                    // If no user in session and no forced user, get it from 
	            	// the request
                    sUserId = oRequest.getParameter(USERID_ATTRIBUTE_NAME);
                    if((sUserId == null) || sUserId.equals("")) {
                        // We really need to know the username
                    	// This is not an authentication attempt
                        bRetries = false;
                        
                        // Only warn when this was not the first request in the process
                        if (oiRetries != null) {
                        	warnings.add(Warnings.NO_USERNAME_SUPPLIED);
                        }
                        
                        forwardUser(oRequest, oResponse, oSession, iTries, bRetries, warnings);
                        return UserEvent.AUTHN_METHOD_IN_PROGRESS;
                    }
	            }
	            
	            // User in session, initialize from UserFactory:
                oUser = _oUserFactory.getUser(sUserId);
                if (oUser == null) {
                    throw new UserException(UserEvent.AUTHN_METHOD_NOT_SUPPORTED);
                }

                oSession.setUser(oUser);
	        }

            if (!oUser.isEnabled()) {
                throw new UserException(UserEvent.USER_DISABLED);
            }

            // Check is user is registered for OTPAuthenticationMethod
            if(!oUser.isAuthenticationRegistered(_sMethodID)) {
            	_oLogger.warn("Authentication Method is not registered for this user; aborting login attempt.");
                throw new UserException(UserEvent.AUTHN_METHOD_NOT_REGISTERED);
            }
            
	        
	        // Ensure OTP-instance in session
	        oOTP = ((OTP)oAttributes.get(
	                OTPAuthenticationMethod.class,
	                _sMethodID + OTP_NAME));
	        
	        if (oOTP == null) {
	        	oOTP = _oOTPGenerator.generate(oUser);
	        	
	        	// Persist the generated OTP in session
	        	oAttributes.put(OTPAuthenticationMethod.class,
	                    _sMethodID + OTPAuthenticationMethod.OTP_NAME, oOTP);
	        	oSession.persist();
	        }
	        
	        // Check whether to distribute the OTP
	        if (mustDistributeOTP(oRequest, oOTP, oUser, warnings)) {
	        	if (_bDisableDistribute) {
	        		_oLogger.debug("Distribute disabled for sending OTP: " + oOTP.getValue());
	        		// Do act like OTP has been sent
	        		oOTP.registerSent(Long.valueOf(System.currentTimeMillis()));
	        	} else {
	        		_oOTPDistributor.distribute(oOTP, oUser);
	        	}
	        	bRetries = false;	// This is not an authentication attempt
	        	
	        	// Take user to password entry location
	        	forwardPassword(oRequest, oResponse, oSession, iTries, bRetries, warnings);
                return UserEvent.AUTHN_METHOD_IN_PROGRESS;
	        }
	        
	        // ================================================================
	        // Establish supplied password.
	        String sCaptcha = null;
            if (_bCaptchaEnabled)
            {
                // Get supplied captcha.
                sCaptcha = oRequest.getParameter(CAPTCHA);
                if((sCaptcha == null) || (sCaptcha.trim().length() <= 0))
                {
                    bRetries = false;	// This is not an authentication attempt
                    warnings.add(Warnings.NO_CAPTCHA_SUPPLIED);
                }
            }
            
            sUserPassword = oRequest.getParameter(PASSWORD);
            if((sUserPassword == null) || sUserPassword.trim().equalsIgnoreCase(""))
            {
                bRetries = false;	// This is not an authentication attempt
                warnings.add(Warnings.NO_PASSWORD_SUPPLIED);
            }

            // Deal with missing parameters
            if (!warnings.isEmpty())
            {
            	// DetailedUserException takes user to error feedback location
                throw new DetailedUserException(
                    UserEvent.AUTHN_METHOD_IN_PROGRESS, warnings);
            }

            // Verify captcha when it is enabled
            if (_bCaptchaEnabled)
            {
                Class<?> cCaptchaEngine = null;
                
                try
                {
                    cCaptchaEngine = Class.forName("com.alfaariss.oa.helper.captcha.engine.CaptchaEngine");
                }
                catch (ClassNotFoundException e)
                {
                    _oLogger.error("Captcha enabled, but 'com.alfaariss.oa.helper.captcha.engine.CaptchaEngine' is not available", e);
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                byte[] baCaptchaHash = (byte[])oAttributes.get(cCaptchaEngine
                    , CAPTCHA_HASH);
                if (!verifyCaptcha(sCaptcha, baCaptchaHash))
                {
                    throw new DetailedUserException(UserEvent.AUTHN_METHOD_IN_PROGRESS,
                        Warnings.INVALID_CAPTCHA_SUPPLIED);
                }
                oAttributes.remove(cCaptchaEngine, CAPTCHA_HASH);
            }

            // Verify the password:
            // Get the correct User ID to authenticate with the resource.
            
            String sAuthUserId = null;
            // If ID mapping is enabled, map the OA user name to the corresponding pwd username.
            if (_oIDMapper != null)
            {
                sAuthUserId = _oIDMapper.map(oUser.getID());
                if(sAuthUserId == null)
                {
                    throw new UserException(UserEvent.AUTHN_METHOD_FAILED);
                }
            }
            else
            {
                sAuthUserId = oUser.getID();
            }
	        
            // Authenticate with supplied credentials against the configured password method.
            // IUser oUser, OTP oOTP, String sUserName, String sPassword
            if (!_oOTPGenerator.authenticate(oUser, oOTP, sAuthUserId, sUserPassword))
            {
                throw new DetailedUserException(
                    UserEvent.AUTHN_METHOD_IN_PROGRESS,
                    Warnings.INVALID_CREDENTIALS_SUPPLIED);
            }
            
            // Authenticate succeeded, acknowledge
            oSession.setUser(oUser);
            _oEventLogger.info(new UserEventLogItem(oSession,
                oRequest.getRemoteAddr(), UserEvent.AUTHN_METHOD_SUCCESSFUL,
                this, null));

            userEvent = UserEvent.AUTHN_METHOD_SUCCESSFUL;
	        
        }
        catch(OTPDistributorException ode)
        {
            _oEventLogger.info(new UserEventLogItem(oSession,
                    oRequest.getRemoteAddr(), UserEvent.AUTHN_METHOD_FAILED,
                    this, "OTPDistributorException code "+ode.getCode()));
            userEvent = UserEvent.AUTHN_METHOD_FAILED;
        }
        catch(UserException e)
        {
            userEvent = e.getEvent();
            
            _oEventLogger.info(new UserEventLogItem(oSession,
                oRequest.getRemoteAddr(), e.getEvent(),
                this, null));
        }
        catch(DetailedUserException e)
        {
            if(iTries <= 0)
            {
                _oEventLogger.info(new UserEventLogItem(oSession,
                    oRequest.getRemoteAddr(), UserEvent.AUTHN_METHOD_FAILED,
                    this, e.getDetails().toString()));
                userEvent = UserEvent.AUTHN_METHOD_FAILED;
            }
            else
            {
                //Event logging is executed in showPage

                //Show page once again
                forwardPassword(oRequest, oResponse, oSession, iTries,
                    bRetries, e.getDetails());
                userEvent = e.getEvent();
            }
        }
        
        return userEvent;
    }

    
    /**
     * Helper function to decide whether OTP should be distributed or not
     * @param oRequest Context that provides user input
     * @param oOTP OneTimePassword instance
     * @param oUser User that the OneTimePassword is for
     * @param vWarnings Warnings collection that can be used to add to
     * @return true when OTP should be distributed, false if no action required
     */
    private boolean mustDistributeOTP(HttpServletRequest oRequest, 
    		OTP oOTP, IUser oUser, Vector<Enum> vWarnings) 
    {
    	// When not sent, return true
    	if (oOTP.getTimesSent() == 0) {
    		return true;
    	}

    	// When resend requested, return true
    	String sRequestResend = (String) oRequest.getAttribute(RESEND_OTP);
    	if (! (sRequestResend == null || sRequestResend == "")) {
    		int iResendCount = oOTP.getTimesSent();
    		
    		if (iResendCount >= _iAllowedOTPResends) {
    			vWarnings.add(Warnings.OTP_NO_MORE_RESEND_ALLOWED);
    			return false;
    		}
    		
    		return true;
    	}
    	
    	return false;
    }
    
    
    /**
     * Function to stop all the (sub)components of the
     * Password Authentication Method correctly.
     * 
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    public void stop()
    {
        _bEnabled = false;
        if (_oOTPGenerator!=null)
        {
            _oOTPGenerator.stop();
            _oOTPGenerator = null;
        }
        _sIdTemplate = null;
        _sPwdTemplate = null;
        _sMethodID = null;
        _sFriendlyName = null;
        _oUserFactory = null;
        _bCaptchaEnabled = false;
        _CryptoManager = null;
        _oEngine = null;
        _iAllowedTries = 0;
    }


    // Show the user page
    private void forwardUser(HttpServletRequest request, HttpServletResponse response,
        ISession session, int iTries, boolean bRetries, List<Enum> warnings) throws OAException
    {
        try
        {
            request.setAttribute(ISession.ID_NAME, session.getId());
            request.setAttribute(ISession.LOCALE_NAME, session.getLocale());
            request.setAttribute(HASCAPTCHA, _bCaptchaEnabled);

            //Set retries
            ISessionAttributes oAttributes = session.getAttributes();
            oAttributes.put(OTPAuthenticationMethod.class,
                _sMethodID + RETRIES_ATTRIBUTE_NAME, Integer.valueOf(iTries));
            session.persist();

            _oEventLogger.info(new UserEventLogItem(session,
                request.getRemoteAddr(), UserEvent.AUTHN_METHOD_IN_PROGRESS,
                this, warnings.toString()));

            request.setAttribute(DetailedUserException.DETAILS_NAME, warnings);
            request.setAttribute(AUTHN_METHOD_ATTRIBUTE_NAME, _sFriendlyName);
            request.setAttribute(Server.SERVER_ATTRIBUTE_NAME,
                _oEngine.getServer());
            IUser oUser = session.getUser();
            if (oUser!= null)
            {
                request.setAttribute(USERID_ATTRIBUTE_NAME, oUser.getID());
            }

            RequestDispatcher dispatcher = request.getRequestDispatcher(
                _sIdTemplate);

            if(dispatcher != null)
            {
                dispatcher.forward(request, response);
            }
        }
        catch(IOException e)
        {
            _oLogger.warn("IO exception occured while forwarding",e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch(ServletException e)
        {
            _oLogger.warn("Servlet exception occured while forwarding",e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    
    // Show the password page
    private void forwardPassword(HttpServletRequest request, HttpServletResponse response,
        ISession session, int iTries, boolean bRetries, List<Enum> warnings) throws OAException
    {
        try
        {
            if(iTries == 1 && _iAllowedTries != 1)
            {
                warnings.add(Warnings.ONE_RETRY_LEFT);
            }
            request.setAttribute(ISession.ID_NAME, session.getId());
            request.setAttribute(ISession.LOCALE_NAME, session.getLocale());
            request.setAttribute(HASCAPTCHA, _bCaptchaEnabled);

            if (bRetries)
            {
                // Only decrease retries if error is an attempt
                iTries--;
            }
            //Set retries
            ISessionAttributes oAttributes = session.getAttributes();
            oAttributes.put(OTPAuthenticationMethod.class,
                _sMethodID + RETRIES_ATTRIBUTE_NAME, Integer.valueOf(iTries));
            session.persist();

            _oEventLogger.info(new UserEventLogItem(session,
                request.getRemoteAddr(), UserEvent.AUTHN_METHOD_IN_PROGRESS,
                this, warnings.toString()));

            request.setAttribute(DetailedUserException.DETAILS_NAME, warnings);
            request.setAttribute(AUTHN_METHOD_ATTRIBUTE_NAME, _sFriendlyName);
            request.setAttribute(Server.SERVER_ATTRIBUTE_NAME,
                _oEngine.getServer());
            IUser oUser = session.getUser();
            if (oUser!= null)
            {
            	request.setAttribute(USERID_ATTRIBUTE_NAME, oUser.getID());
            } 
            else 
            {
            	_oLogger.error("User disappeared from session when asking for password!");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }

            RequestDispatcher dispatcher = request.getRequestDispatcher(
                _sPwdTemplate);

            if(dispatcher != null)
            {
                dispatcher.forward(request, response);
            }
        }
        catch(IOException e)
        {
            _oLogger.warn("IO exception occured while forwarding",e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch(ServletException e)
        {
            _oLogger.warn("Servlet exception occured while forwarding",e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }


    //Validate Captcha digest
    private boolean verifyCaptcha(
        String sSuppliedCaptcha, byte[] baSessionCaptcha) throws OAException
    {
        boolean bValidCaptcha = false;
        try
        {
            //Digest the provided answer
            MessageDigest oMessageDigest = null;
            oMessageDigest = _CryptoManager.getMessageDigest();
            oMessageDigest.update(sSuppliedCaptcha.getBytes(
                IOTPGenerator.CHARSET));
            byte[] baCaptcha = oMessageDigest.digest();
            bValidCaptcha = Arrays.equals(baSessionCaptcha, baCaptcha);
        }
        catch(CryptoException e)
        {
            _oLogger.warn("Unable to generate digest from captcha text", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch (Exception e)
        {
            _oLogger.warn("Unexpected error occured while generating digest", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return bValidCaptcha;
    }

    
    private IIDMapper createMapper(Element eConfig) throws OAException
    {
        IIDMapper oMapper = null;
        try
        {
            String sClass = _oConfigManager.getParam(eConfig, "class");
            if (sClass == null)
            {
                _oLogger.error(
                "No 'class' parameter found in 'idmapper' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            Class cMapper = null;
            try
            {
                cMapper = Class.forName(sClass);
            }
            catch (Exception e)
            {
                _oLogger.error("No 'class' found with name: " + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            try
            {
                oMapper = (IIDMapper)cMapper.newInstance();
            }
            catch (Exception e)
            {
                _oLogger.error(
                    "Could not create an 'IIDMapper' instance of the configured 'class': "
                    + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            oMapper.start(_oConfigManager, eConfig);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _oLogger.fatal("Internal error during creation of id mapper", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return oMapper;
    }
}

