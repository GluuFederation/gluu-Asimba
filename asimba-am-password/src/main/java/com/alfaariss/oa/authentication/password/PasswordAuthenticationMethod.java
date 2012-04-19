/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2009 Alfa & Ariss B.V.
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
package com.alfaariss.oa.authentication.password;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import com.alfaariss.oa.sso.authentication.service.IServiceAuthenticationMethod;
import com.alfaariss.oa.sso.authentication.web.IWebAuthenticationMethod;
import com.alfaariss.oa.util.logging.UserEventLogItem;

/**
 * The Password authentication method.
 * 
 * The password method authenticates the user using user name password
 * combination. Can be used as a web-based or service based authentication
 * method within the OpenASelect system.
 *
 * @author JVG
 * @author LVR
 * @author Alfa & Ariss
 *
 */
public class PasswordAuthenticationMethod
    implements IWebAuthenticationMethod, IServiceAuthenticationMethod
{

    /** password handler */
    protected IPasswordHandler _oPasswordHandler;
    /** id mapper */
    protected IIDMapper _idMapper;

    private final static String AUTHORITY_NAME =
        "PasswordAuthenticationMethod_";
    private final static String HASCAPTCHA = "hasCaptcha";
    private final static String CAPTCHA ="captcha";
    private final static String PASSWORD = "password";
    
    /** CAPTCHA_HASH */
    private final static String CAPTCHA_HASH = "captcha_hash";
    
    private static final String DEFAULT_JSP_PASSWORD = "/ui/sso/authn/password/password.jsp";
    
    private String _sTemplate;
    private String _sMethodID;
    private String _sFriendlyName;
    private int _iAllowedTries;
    //Only needs to be set once.
    private final Log _logger;
    private final Log _eventLogger;
    private IConfigurationManager _configurationManager;
    private IUserFactory _oUserFactory;
    private Engine _oEngine;
    private boolean _bEnabled;
    private boolean _bCaptchaEnabled;
    private CryptoManager _CryptoManager;

    /**
     * Default Constructor
     */
    public PasswordAuthenticationMethod()
    {
        _logger = LogFactory.getLog(PasswordAuthenticationMethod.class);
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
        _bEnabled = false;
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
            if ((eConfig == null) || (oConfigurationManager == null))
            {
                _logger.error("No configuration supplied");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            _configurationManager = oConfigurationManager;
            _oEngine = Engine.getInstance();

            _CryptoManager = _oEngine.getCryptoManager();
            if (_CryptoManager == null)
            {
                _logger.error("No crypto manager available");
                throw new OAException(SystemErrors.ERROR_INIT);
            }

            _oUserFactory = _oEngine.getUserFactory();
            if ((_oUserFactory == null) || !_oUserFactory.isEnabled())
            {
                _logger.error("User Factory is disabled");
                throw new OAException(SystemErrors.ERROR_INIT);
            }

            _sMethodID = _configurationManager.getParam(eConfig, "id");
            if ((_sMethodID == null) || _sMethodID.equals(""))
            {
                _logger.error(
                "No 'id' found in 'method' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            _sFriendlyName = _configurationManager.getParam(
                eConfig, "friendlyname");
            if ((_sFriendlyName == null) || _sFriendlyName.equals(""))
            {
                _logger.error(
                "No 'friendlyname' parameter found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            String sEnabled = _configurationManager.getParam(
                eConfig, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _bEnabled = true;
                }
                else if (!sEnabled.equalsIgnoreCase("FALSE"))
                {
                    _logger.error("Unknown value in 'enabled' configuration item: "
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
                String sCaptchaEnabled = _configurationManager.getParam(
                    eConfig, "captcha");
                if (sCaptchaEnabled != null)
                {
                    if (sCaptchaEnabled.equalsIgnoreCase("TRUE"))
                    {
                        _bCaptchaEnabled = true;
                    }
                    else if (!sCaptchaEnabled.equalsIgnoreCase("FALSE"))
                    {
                        _logger.error(
                            "Unknown value in 'captcha' configuration item: "
                            + sCaptchaEnabled);
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                }

                _logger.info(_bCaptchaEnabled ? "Captcha is enabled" :  "Captcha is not enabled");
                
                _sTemplate = DEFAULT_JSP_PASSWORD;
                Element eMethodTemplate = _configurationManager.getSection(
                    eConfig, "template");
                if(eMethodTemplate == null)
                {
                    _logger.warn(
                        "No optional 'template' section found in 'method' section with id: "
                        + _sMethodID + ", using default");
                }
                else
                {
                    _sTemplate = _configurationManager.getParam(
                        eMethodTemplate,"path");
                    if((_sTemplate == null) || _sTemplate.equals(""))
                    {
                        _logger.error(
                            "No 'path' attribute found in 'template' section within 'method' with id: "
                            + _sMethodID);
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                }
                _logger.info("Using JSP: " + _sTemplate);

                String sAllowedRetries = _configurationManager.getParam(
                    eConfig, "retries");
                if ((sAllowedRetries == null) || sAllowedRetries.equals(""))
                {
                    _logger.error(
                        "No 'retries' found in 'method' section with id: "
                        + _sMethodID);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                try
                {
                    _iAllowedTries = Integer.parseInt(sAllowedRetries);
                    if(_iAllowedTries < 0)
                    {
                        _logger.error(
                            "Invalid 'retries' item found in 'method' section with id: "
                            + _sMethodID);
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }

                    // DD Increase the value of retries. (Config uses no. of retries, code uses no. of tries)
                    // Number of tries is retries plus one.
                    if (_iAllowedTries>=0) {
                        _iAllowedTries++;
                    }
                }
                catch(NumberFormatException e)
                {
                    _logger.error(
                        "Invalid 'retries' item found in 'method' section with id: "
                        + _sMethodID, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }

                Element ePasswordHandler = _configurationManager.getSection(
                    eConfig, "password_handler");
                if (ePasswordHandler == null)
                {
                    _logger.error(
                        "No 'password_handler' section found in 'method' section with id: "
                        + _sMethodID);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }               

                String sPasswordHandlerClass = _configurationManager.getParam(
                    ePasswordHandler, "class");
                if ((sPasswordHandlerClass == null) || sPasswordHandlerClass.equals(""))
                {
                    _logger.error("No class found for password_handler");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }

                Class cPasswordHandler = null;
                try
                {
                    cPasswordHandler = Class.forName(sPasswordHandlerClass);
                }
                catch (Exception e)
                {
                    _logger.error("Could not find password handler class: "
                        + sPasswordHandlerClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }

                try
                {
                    _oPasswordHandler =
                        (IPasswordHandler)cPasswordHandler.newInstance();
                }
                catch(Exception e)
                {
                    _logger.error("Could not instantiate password handler: "
                        + sPasswordHandlerClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                _oPasswordHandler.start(_configurationManager, ePasswordHandler);
                if(_logger.isDebugEnabled())
                {
                    StringBuffer sb = new StringBuffer(_sMethodID);
                    sb.append(" handler '");
                    sb.append(sPasswordHandlerClass).append("' started");
                    _logger.debug(sb.toString());
                }

                //Create mapper
                Element eIDMapper = _configurationManager.getSection(
                    eConfig, "idmapper");
                if (eIDMapper != null)
                {
                    _idMapper = createMapper(eIDMapper);
                }
            }
        }
        catch (OAException e)
        {
            _logger.error(
                "Error during start of Password authentication method");
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal(
                "Internal error during start of Password authentication method",
                e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Restart the Password Authentication Method.
     * 
     * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
     */
    public void restart(Element eConfig) throws OAException
    {
        synchronized(this)
        {
            stop();
            start(_configurationManager, eConfig);
        }
    }

    /**
     * Returns the Password Authentication Method Id.
     * 
     * @see com.alfaariss.oa.sso.authentication.web.IWebAuthenticationMethod#getID()
     */
    public String getID()
    {
        return _sMethodID;
    }

    /**
     * Returns whether the Password Authentication Method is enabled or not.
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
     * Returns Authority Name.
     * 
     * @see IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return AUTHORITY_NAME + _sMethodID;
    }

    /**
     * Function for online authentication.
     * 
     * Authenticates the user using the configured Password handler
     * (JDBC, JNDI, RADIUS etc.). When Captcha is enabled the user must also
     * submit the supplied text in the captcha image.
     * @see IWebAuthenticationMethod#authenticate(
     *  HttpServletRequest, HttpServletResponse, ISession)
     */
    public UserEvent authenticate(HttpServletRequest oRequest,
        HttpServletResponse oResponse, ISession oSession) throws OAException
    {
        IUser oUser = null;
        String sUserPassword = null;
        boolean bRetries = true;
        int iTries = _iAllowedTries;
        ISessionAttributes oAttributes = null;
        UserEvent userEvent = null;
        String sUserId = null;
        
        try
        {
            oAttributes = oSession.getAttributes();
            // Get retries left
            Integer intTries = ((Integer)oAttributes.get(
                PasswordAuthenticationMethod.class,
                _sMethodID + RETRIES_ATTRIBUTE_NAME));

            //handle
            if(intTries == null) //First call to pwd method
            {
                //get user from session
                oUser = oSession.getUser();
                if(oUser == null)
                {
                    // If no user in session, check forced user
                    sUserId = oSession.getForcedUserID();
                    if (sUserId != null)
                    {
                        oUser = _oUserFactory.getUser(sUserId);
                        if (oUser == null)
                        {
                            throw new UserException(UserEvent.AUTHN_METHOD_NOT_SUPPORTED);
                        }

                        if (!oUser.isEnabled())
                        {
                            throw new UserException(UserEvent.USER_DISABLED);
                        }

                        // Check is user is registered for password method
                        if(!oUser.isAuthenticationRegistered(_sMethodID))
                        {
                            throw new UserException(UserEvent.AUTHN_METHOD_NOT_REGISTERED);
                        }
                        oSession.setUser(oUser);
                    }
                }
                else
                {
                    // Check is user is registered for password method
                    if(!oUser.isAuthenticationRegistered(_sMethodID))
                    {
                        throw new UserException(UserEvent.AUTHN_METHOD_NOT_REGISTERED);
                    }
                }
                forwardUser(oRequest, oResponse, oSession, iTries, bRetries,
                    new Vector<Enum>());
                userEvent = UserEvent.AUTHN_METHOD_IN_PROGRESS;
            }
            else
            {
                iTries = intTries.intValue();
                Vector<Enum> warnings = new Vector<Enum>();
                // Check if captcha is enabled and verify if a captcha is supplied.
                String sCaptcha = null;
                if (_bCaptchaEnabled)
                {
                    // Get supplied captcha.
                    sCaptcha = oRequest.getParameter(CAPTCHA);
                    if((sCaptcha == null) || (sCaptcha.trim().length() <= 0))
                    {
                        // does not count as an attempt
                        bRetries = false;
                        warnings.add(Warnings.NO_CAPTCHA_SUPPLIED);
                    }
                }

                //get user from session
                oUser = oSession.getUser();
                if(oUser == null)
                {
                    // If no user in session, get it from request
                    sUserId = oRequest.getParameter(USERID_ATTRIBUTE_NAME);
                    if((sUserId == null) || sUserId.equals(""))
                    {
                        // do not treat as an attempt
                        bRetries = false;
                        warnings.add(Warnings.NO_USERNAME_SUPPLIED);
                    }
                    else
                    {
                        oUser = _oUserFactory.getUser(sUserId);
                    }
                }

                // Get supplied password.
                sUserPassword = oRequest.getParameter(PASSWORD);
                if((sUserPassword == null) || sUserPassword.trim().equalsIgnoreCase(""))
                {
                    // does not count as an attempt
                    bRetries = false;
                    warnings.add(Warnings.NO_PASSWORD_SUPPLIED);
                }

                //Check for missing request parameters
                if (!warnings.isEmpty())
                {
                    //throw new DetailedUserException(warnings);
                    throw new DetailedUserException(
                        UserEvent.AUTHN_METHOD_IN_PROGRESS, warnings);
                }

                //Verify captcha
                if (_bCaptchaEnabled)
                {
                    Class cCaptchaEngine = null;
                    
                    try
                    {
                        cCaptchaEngine = Class.forName("com.alfaariss.oa.helper.captcha.engine.CaptchaEngine");
                    }
                    catch (ClassNotFoundException e)
                    {
                        _logger.error("Captcha enabled, but 'com.alfaariss.oa.helper.captcha.engine.CaptchaEngine' is not available", e);
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

                //Verify User
                if(sUserId != null) //Submitted user
                {
                    if(oUser == null)
                    {
                        throw new DetailedUserException(
                            UserEvent.AUTHN_METHOD_IN_PROGRESS,
                            Warnings.NO_SUCH_USER_FOUND);
                    }
                }

                //Get the correct User ID to authenticate with the resource.
                String sAuthUserId = null;
                //If ID mapping is enabled, map the OA user name to the corresponding pwd username.
                if (_idMapper != null)
                {
                    sAuthUserId = _idMapper.map(oUser.getID());
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
                if (!_oPasswordHandler.authenticate(sAuthUserId, sUserPassword))
                {
                    throw new DetailedUserException(
                        UserEvent.AUTHN_METHOD_IN_PROGRESS,
                        Warnings.INVALID_CREDENTIALS_SUPPLIED);
                }

                if(sUserId != null)
                {
                    if (!oUser.isEnabled())
                    {
                        throw new UserException(UserEvent.USER_DISABLED);
                    }

                    // Check is user is registered for password method
                    if(!oUser.isAuthenticationRegistered(_sMethodID))
                    {
                        throw new UserException(UserEvent.AUTHN_METHOD_NOT_REGISTERED);
                    }
                }

                //everything Okay
                oSession.setUser(oUser);
                _eventLogger.info(new UserEventLogItem(oSession,
                    oRequest.getRemoteAddr(), UserEvent.AUTHN_METHOD_SUCCESSFUL,
                    this, null));

                userEvent = UserEvent.AUTHN_METHOD_SUCCESSFUL;
            }
        }
        catch(UserException e)
        {
            userEvent = e.getEvent();
            
            _eventLogger.info(new UserEventLogItem(oSession,
                oRequest.getRemoteAddr(), e.getEvent(),
                this, null));
        }
        catch(DetailedUserException e)
        {
            if(iTries <= 0)
            {
                _eventLogger.info(new UserEventLogItem(oSession,
                    oRequest.getRemoteAddr(), UserEvent.AUTHN_METHOD_FAILED,
                    this, e.getDetails().toString()));
                userEvent = UserEvent.AUTHN_METHOD_FAILED;
            }
            else
            {
                //Event logging is executed in showPage

                //Show page once again
                forwardUser(oRequest, oResponse, oSession, iTries,
                    bRetries, e.getDetails());
                userEvent = e.getEvent();
            }

        }
        catch(OAException e)
        {
            _eventLogger.info(new UserEventLogItem(oSession,
                oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR,
                this, null));
            //already logged to system log.
            throw e;
        }
        catch(Exception e)
        {
            if (oSession != null)
            {
                _eventLogger.info(new UserEventLogItem(oSession,
                    oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR,
                    this, e.getMessage()));
            }
            else
            {
                _eventLogger.info(new UserEventLogItem(null, null,
                    null, UserEvent.INTERNAL_ERROR, null,
                    oRequest.getRemoteAddr(), null, this,
                    e.getMessage()));
            }

            _logger.fatal("Unexpected runtime error occured: ",e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return userEvent;
    }

    /**
     * Function for offline authentication
     * 
     * Authenticates the user using the configured Password handler
     * (JDBC, JNDI, RADIUS etc.).
     *
     * @see IServiceAuthenticationMethod#authenticate(java.lang.String, byte[])
     */
    public UserEvent authenticate(String sUserID, byte[] baCredentials)
        throws OAException
    {
        try
        {
            IUser oUser = _oUserFactory.getUser(sUserID);
            if (oUser == null)
            {
                throw new UserException(UserEvent.USER_UNKNOWN);
            }

            if (!oUser.isEnabled())
            {
                throw new UserException(UserEvent.USER_DISABLED);
            }

            if(!oUser.isAuthenticationRegistered(_sMethodID))
            {
                throw new UserException(UserEvent.AUTHN_METHOD_NOT_REGISTERED);
            }

            String sUserPassword = new String(baCredentials, IPasswordHandler.CHARSET);

            if(!_oPasswordHandler.authenticate(oUser.getID(), sUserPassword))
            {
                throw new UserException(UserEvent.AUTHN_METHOD_FAILED);
            }

            _eventLogger.info( new UserEventLogItem(null, null, null,
                UserEvent.AUTHN_METHOD_SUCCESSFUL, sUserID, null,
                null, this, null));
            return UserEvent.AUTHN_METHOD_SUCCESSFUL;

        }
        catch(UserException e)
        {
            UserEvent event = e.getEvent();
            _eventLogger.info(new UserEventLogItem(null, null, null,
                event, sUserID, null,
                null, this, null));
            return event;
        }
        catch(OAException e)
        {
            _logger.warn("Unexpected error occured",e);
            _eventLogger.info(new UserEventLogItem(null, null, null,
                UserEvent.INTERNAL_ERROR, sUserID, null,
                null, this, null));
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Unexpected internal error occured",e);
            _eventLogger.info(new UserEventLogItem(null, null, null,
                UserEvent.INTERNAL_ERROR, sUserID, null,
                null, this, null));
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
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
        if (_oPasswordHandler!=null)
        {
            _oPasswordHandler.stop();
            _oPasswordHandler = null;
        }
        _sTemplate = null;
        _sMethodID = null;
        _sFriendlyName = null;
        _oUserFactory = null;
        _bCaptchaEnabled = false;
        _CryptoManager = null;
        _oEngine = null;
        _iAllowedTries = 0;
    }


    // Show the password page
    private void forwardUser(HttpServletRequest request, HttpServletResponse response,
        ISession session, int iTries, boolean bRetries, List<Enum> warnings) throws OAException
    {
        try
        {
            if(iTries == 1 && _iAllowedTries != 1)
            {
                warnings.add(Warnings.ONE_RETRY_LEFT);
            }
            /* 20110304;dopey fix: set session instead of session.getId() into ID_NAME */
            request.setAttribute(ISession.ID_NAME, session);
            request.setAttribute(ISession.LOCALE_NAME, session.getLocale());
            request.setAttribute(HASCAPTCHA, _bCaptchaEnabled);

            if (bRetries)
            {
                // Only decrease retries if error is an attempt
                iTries--;
            }
            //Set retries
            ISessionAttributes oAttributes = session.getAttributes();
            oAttributes.put(PasswordAuthenticationMethod.class,
                _sMethodID + RETRIES_ATTRIBUTE_NAME, Integer.valueOf(iTries));
            session.persist();

            _eventLogger.info(new UserEventLogItem(session,
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
                _sTemplate);

            if(dispatcher != null)
            {
                dispatcher.forward(request, response);
            }
        }
        catch(IOException e)
        {
            _logger.warn("IO exception occured while forwarding",e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch(ServletException e)
        {
            _logger.warn("Servlet exception occured while forwarding",e);
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
                IPasswordHandler.CHARSET));
            byte[] baCaptcha = oMessageDigest.digest();
            bValidCaptcha = Arrays.equals(baSessionCaptcha, baCaptcha);
        }
        catch(CryptoException e)
        {
            _logger.warn("Unable to generate digest from captcha text", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch (Exception e)
        {
            _logger.warn("Unexpected error occured while generating digest", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return bValidCaptcha;
    }

    private IIDMapper createMapper(Element eConfig) throws OAException
    {
        IIDMapper oMapper = null;
        try
        {
            String sClass = _configurationManager.getParam(eConfig, "class");
            if (sClass == null)
            {
                _logger.error(
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
                _logger.error("No 'class' found with name: " + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            try
            {
                oMapper = (IIDMapper)cMapper.newInstance();
            }
            catch (Exception e)
            {
                _logger.error(
                    "Could not create an 'IIDMapper' instance of the configured 'class': "
                    + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            oMapper.start(_configurationManager, eConfig);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during creation of id mapper", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return oMapper;
    }
}

