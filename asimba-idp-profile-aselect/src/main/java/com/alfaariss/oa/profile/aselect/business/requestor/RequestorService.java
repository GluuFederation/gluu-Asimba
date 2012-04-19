
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
package com.alfaariss.oa.profile.aselect.business.requestor;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.Vector;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.authentication.IAuthenticationProfile;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.tgt.TGTEventError;
import com.alfaariss.oa.api.tgt.TGTListenerException;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.authentication.AuthenticationException;
import com.alfaariss.oa.engine.core.authentication.AuthenticationProfile;
import com.alfaariss.oa.engine.core.authentication.factory.IAuthenticationProfileFactory;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.profile.aselect.ASelectErrors;
import com.alfaariss.oa.profile.aselect.business.AbstractOAService;
import com.alfaariss.oa.profile.aselect.business.AuthNException;
import com.alfaariss.oa.profile.aselect.business.BusinessRuleException;
import com.alfaariss.oa.profile.aselect.business.beans.TGTInfo;
import com.alfaariss.oa.profile.aselect.processor.ASelectProcessor;
import com.alfaariss.oa.profile.aselect.processor.handler.ASelectRequestorPool;
import com.alfaariss.oa.profile.aselect.processor.handler.BrowserHandler;
import com.alfaariss.oa.util.logging.RequestorEventLogItem;
import com.alfaariss.oa.util.session.ProxyAttributes;
import com.alfaariss.oa.util.validation.LocaleValidator;
import com.alfaariss.oa.util.validation.SessionValidator;

/**
 * Default implementation of the requestor service business logic.
 * 
 * <br><br><i>Partitially based on sources from A-Select (www.a-select.org).</i>
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public class RequestorService 
    extends AbstractOAService implements IRequestorService
{   
    /** OA Profile */
    public final static String AUTHORITY_NAME = "A-Select WS Profile";
    
    private final static String PROPERTY_APP_LEVEL = "aselect.app_level";
    private final static String PROPERTY_UID_ATTRIBUTE = "aselect.uid.attribute";
    private final static String PROPERTY_UID_OPAQUE_ENABLED = "aselect.uid.opaque.enabled";
    private final static String PROPERTY_UID_OPAQUE_SALT = "aselect.uid.opaque.salt";
    private final static String PROPERTY_AUTHSP_LEVEL = "aselect.authsp_level";
    
    //Initialization state
    private boolean _initialized;   
    private boolean _forceRequestorID;
    /** Hashtable containing the authsp_level per authenticationprofile */
    private Hashtable<String, Integer> _htAuthSPLevels;
    /** Default authsp_level value */
    private int _iDefaultAuthSPLevel;
    /** Hashtable containing the app_level per requestorpool */
    private Hashtable<String, ASelectRequestorPool> _htASelectRequestorPools;
    /** Default app_level value*/
    private int _iDefaultAppLevel;
    /** Redirection URL to OA user profile*/
    private String _sRedirectURL;

    /**
     * Default constructor.
     */
    public RequestorService()
    {
        super();    
        _initialized = false;
        _forceRequestorID = false;
    }

    /**
     * Start the <code>RequestorService</code>.
     * @see AbstractOAService#start(
     *  IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager,
        Element eConfig) throws OAException
    {
        Element eWS = null;
        boolean bEnabled = false;
        try
        {
            super.start(oConfigurationManager, eConfig);
           
            //Check enabled state                       
            if(_eOASection != null) //aselect enabled
            {              
                //Read WS specific configuration        
                eWS = oConfigurationManager.getSection(_eOASection, "ws");
                if (eWS != null) //aselect ws available
                {
                    //Check if ws profile is enabled
                    String sEnabled = _configurationManager.getParam(
                        eWS, "enabled");
                    if (sEnabled != null)
                    {
                        if (sEnabled.equalsIgnoreCase("TRUE")) //aselect ws enabled
                            bEnabled = true;
                        else if (!sEnabled.equalsIgnoreCase("FALSE"))
                        {
                            _logger.error(
                                "Unknown value in 'enabled' configuration item: " 
                                + sEnabled);
                            throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                        }
                    }
                    else
                        bEnabled = true; //aselect ws enabled
                }
            }
            
            if(bEnabled)
            {                   
               //Retrieve mandatory redirect_url
               _sRedirectURL = oConfigurationManager.getParam(
                   _eOASection, "redirect_url");
               if (_sRedirectURL == null)
               {
                   _logger.warn("No 'redirect_url' parameter found in 'profile' section with id='aselect' in configuration");
                   throw new OAException(SystemErrors.ERROR_CONFIG_READ);
               }           
               try
               {
                   new URL(_sRedirectURL);
               }
               catch (MalformedURLException e)
               {
                   _logger.error("The supplied 'redirect_url' parameter isn't a URL: " 
                       + _sRedirectURL);                        
                   throw new OAException(SystemErrors.ERROR_CONFIG_READ);
               }
               _logger.info("Using configured 'redirect_url' parameter: " + _sRedirectURL);
               
               String sForced = oConfigurationManager.getParam(
                   eWS, "force_requestor_id");
               if (sForced != null)
               {
                   
                   if (sForced.equalsIgnoreCase("true"))
                   {
                       _logger.info("Force requestor ID is enabled");
                       _forceRequestorID = true;
                   }
                   else if (!sForced.equalsIgnoreCase("false"))
                   {
                       _logger.warn(
                           "Wrong 'force_requestor_id' parameter found in 'ws' section; must be TRUE or FALSE: " 
                           + sForced);
                       throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                   }
               }
                          
               if(!_forceRequestorID)
                   _logger.info("Force requestor ID is disabled");               
               
               Element eAuthentication = oConfigurationManager.getSection(
                   _eOASection, "authentication");
               if (eAuthentication == null)
               {
                   _logger.error(
                       "No 'authentication' section found in 'profile' section with id='aselect' in configuration");
                   throw new OAException(SystemErrors.ERROR_CONFIG_READ);
               }
               
               Element eRequesthandlers = _configurationManager.getSection(
                   _eOASection, "requesthandlers");
               if (eRequesthandlers == null)
               {
                   _logger.error(
                       "No 'requesthandlers' section found in 'profile' section with id='aselect' in configuration");
                   throw new OAException(SystemErrors.ERROR_CONFIG_READ);
               }
               //DD only SP is supported in A-Select WS Profile
               Element eSP = _configurationManager.getSection(eRequesthandlers, "sp");
               if (eSP == null)
               {
                   _logger.error(
                       "No 'sp' section found in 'requesthandlers' section in configuration");
                   throw new OAException(SystemErrors.ERROR_CONFIG_READ);
               }
               
               String sDefaultAppLevel = oConfigurationManager.getParam(
                   eSP, "app_level");
               if (sDefaultAppLevel == null)
               {
                   _logger.error(
                       "No default 'app_level' item in handler section found in configuration");
                   throw new OAException(SystemErrors.ERROR_CONFIG_READ);
               }

               try
               {
                   _iDefaultAppLevel = Integer.valueOf(sDefaultAppLevel);
               }
               catch (NumberFormatException e)
               {
                   _logger.error(
                       "The configured default 'app_level' parameter isn't a number: " 
                       + sDefaultAppLevel, e);
                   throw new OAException(SystemErrors.ERROR_INIT);
               }
               _logger.info("Configured default 'app_level': " + sDefaultAppLevel);              
               _htASelectRequestorPools = new Hashtable<String, ASelectRequestorPool>();
               Element eRequestorPool = oConfigurationManager.getSection(
                   eSP, "requestorpool");
               while (eRequestorPool != null)
               {
                   ASelectRequestorPool oASRequestorPool = new ASelectRequestorPool(
                       oConfigurationManager, eRequestorPool);
                   
                   String sPoolId = oASRequestorPool.getID();
                   if (_htASelectRequestorPools.containsKey(sPoolId))
                   {
                       _logger.warn("The configured 'requestorpool' doesn't have a unique id: " 
                           + sPoolId);
                       throw new OAException(SystemErrors.ERROR_INIT);
                   }
                   
                   if (!_requestorPoolFactory.isPool(sPoolId))
                   {
                       _logger.warn(
                           "The configured 'requestorpool' doesn't exist as a requestor pool: " 
                           + sPoolId);
                       throw new OAException(SystemErrors.ERROR_INIT);
                   }
                   
                   _htASelectRequestorPools.put(sPoolId, oASRequestorPool);
                   _logger.info("Configured: " + oASRequestorPool);
                   eRequestorPool = oConfigurationManager.getNextSection(eRequestorPool);
               }
               
               String sDefaultAuthSPLevel = oConfigurationManager.getParam(
                   eAuthentication, "authsp_level");
               if (sDefaultAuthSPLevel == null)
               {
                   _logger.error(
                       "No default 'authsp_level' item found in 'profile' section with id='aselect' in configuration");
                   throw new OAException(SystemErrors.ERROR_CONFIG_READ);
               }
               
               _iDefaultAuthSPLevel = -1;
               try
               {
                   _iDefaultAuthSPLevel = Integer.parseInt(sDefaultAuthSPLevel);
               }
               catch(NumberFormatException e)
               {
                   _logger.error(
                       "Invalid default 'authsp_level' item found in configuration: " 
                       + sDefaultAuthSPLevel);
                   throw new OAException(SystemErrors.ERROR_INIT);
               }
               _logger.info("Configured default 'authsp_level': " + _iDefaultAuthSPLevel);
               
               Engine oAEEngine = Engine.getInstance();
               IAuthenticationProfileFactory authNProfileFactory = 
                   oAEEngine.getAuthenticationProfileFactory();
               
               _htAuthSPLevels = new Hashtable<String, Integer>();
               Element eAuthNProfile = oConfigurationManager.getSection(
                   eAuthentication, "profile");
               while (eAuthNProfile != null)
               {
                   String sAuthNProfileID = oConfigurationManager.getParam(
                       eAuthNProfile, "id");
                   if (sAuthNProfileID == null)
                   {
                       _logger.error(
                           "No 'id' item in 'profile' section found in configuration");
                       throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                   }
                   
                   if (authNProfileFactory.getProfile(sAuthNProfileID) == null)
                   {
                       _logger.error(
                           "The configured 'id' doesn't exist as an authentication profile: " 
                           + sAuthNProfileID);
                       throw new OAException(SystemErrors.ERROR_INIT);
                   }
                   
                   String sAuthSPLevel = oConfigurationManager.getParam(
                       eAuthNProfile, "authsp_level");
                   if (sAuthSPLevel == null)
                   {
                       _logger.error(
                           "No 'authsp_level' item in 'profile' section found in configuration for profile id: " 
                           + sAuthNProfileID);
                       throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                   }
                   
                   Integer intAuthSPLevel = null;
                   try
                   {
                       intAuthSPLevel = Integer.parseInt(sAuthSPLevel);
                   }
                   catch(NumberFormatException e)
                   {
                       StringBuffer sbError = new StringBuffer(
                           "Invalid 'authsp_level' item in 'profile' section found in configuration for profile id '");
                       sbError.append(sAuthNProfileID);
                       sbError.append("' level isn't a number: ");
                       sbError.append(sAuthSPLevel);
                       _logger.error(sbError.toString(), e);
                       throw new OAException(SystemErrors.ERROR_INIT);
                   }
                   
                   if (_htAuthSPLevels.containsKey(sAuthNProfileID))
                   {
                       _logger.warn(
                           "The configured authentication profile doesn't have a unique id: " 
                           + sAuthNProfileID);
                       throw new OAException(SystemErrors.ERROR_INIT);
                   }
                   
                   _htAuthSPLevels.put(sAuthNProfileID, intAuthSPLevel);
                   StringBuffer sbInfo = new StringBuffer("Configured: authsp_level=");
                   sbInfo.append(sAuthSPLevel);
                   sbInfo.append(" for authentication profile with id: ");
                   sbInfo.append(sAuthNProfileID);
                   _logger.info(sbInfo.toString());
                   
                   eAuthNProfile = oConfigurationManager.getNextSection(
                       eAuthNProfile);
               }               
              
               _initialized = true;   
           }
        }
        catch (OAException e)
        {
            _logger.error(
                "Could not start A-Select WS service", e);
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal(
                "Could not start A-Select WS service due to internal error", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }             
    }
    
    /**
     * Retrieve the initialization state.
     * @see IRequestorService#isInitialized()
     */
    public boolean isInitialized()
    {
        return _initialized;
    }
    
    /**
     * Returns <code>AUTHORITY_NAME</code>.
     * @see IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return AUTHORITY_NAME;
    }
         

    /**
     * Initiate authentication.
     * @see IRequestorService#initiateAuthentication(java.lang.String, 
     *  java.lang.String, java.lang.String, java.lang.String, java.lang.String, 
     *  java.lang.String, java.lang.String, java.lang.String, java.lang.String, 
     *  boolean, java.lang.String)
     */
    public ISession initiateAuthentication(String sOaID, String sRequestorID,
        String sRequestorURL, String sRemoteOrganization, String sForcedLogon,
        String sUID, String sRemoteAddr, String sCountry, String sLanguage, 
        boolean isSigned, String sPassive) throws BusinessRuleException, OAException
    {  
        ISession oSession = null;
        try
        {
            if(!isInitialized())
            {
                _logger.warn("OA Requestor Service not initialized");
                throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
            }
            
            //Null checks
            if (sOaID == null)
            {
                _logger.debug("No oa server ID found in request");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }            
            
            if (sRequestorID == null)
            {
                _logger.debug("No requestor ID found in request");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            if (sRequestorURL == null)
            {
                _logger.debug( "No requestor URL found in request");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            try
            {
                new URL(sRequestorURL);
            }
            catch(MalformedURLException e)
            {
                _logger.debug( "Invalid requestor URL found in request");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_APP_URL);
            }    
            
            boolean forcedLogon = false; // default false            
            if (sForcedLogon != null)
            {
                if(sForcedLogon.equalsIgnoreCase("true"))
                {
                    forcedLogon = true;
                }
                else if(!sForcedLogon.equalsIgnoreCase("false"))
                {
                    _logger.debug(
                        "Invalid forced logon parameter found: " + sForcedLogon);
                    throw new BusinessRuleException(
                        RequestorEvent.REQUEST_INVALID,
                        ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                }

            }
            
            boolean passive = false; // default false            
            if (sPassive != null)
            {
                if(sPassive.equalsIgnoreCase("true"))
                {
                    passive = true;
                }
                else if(!sPassive.equalsIgnoreCase("false"))
                {
                    _logger.debug(
                        "Invalid forced logon parameter found: " + sPassive);
                    throw new BusinessRuleException(
                        RequestorEvent.REQUEST_INVALID,
                        ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                }

            }
                        
            //Bussiness rule validation
            if (!_OAServer.getID().equals(sOaID))
            {
                _logger.debug("Supplied OA Server ID doesn't correspond: " + sOaID);
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_ID_MISMATCH);
            }
            
            IRequestor oRequestor = _requestorPoolFactory.getRequestor(
                sRequestorID);
            if (oRequestor == null)
            {
                StringBuffer sbError = new StringBuffer(
                    "Unknown requestor found in request: ");
                sbError.append(sRequestorID);
                _logger.debug(sbError.toString());
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_APP);                   
            }
            
            if (!oRequestor.isEnabled())
            {
                _logger.debug("Disabled requestor found in request: " + sRequestorID);
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
            }                        
            
            RequestorPool oRequestorPool = 
                _requestorPoolFactory.getRequestorPool(oRequestor.getID());
            if (oRequestorPool == null)
            {
                _logger.warn("Requestor not available in a pool: " 
                    + oRequestor.getID());
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }

            if (!oRequestorPool.isEnabled())
            {
                StringBuffer sbError = new StringBuffer("Requestor '");
                sbError.append(oRequestor.getID());
                sbError.append("' is found in a disabled requestor pool: ");
                sbError.append(oRequestorPool.getID());
                _logger.warn(sbError.toString());
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            ASelectRequestorPool oASRequestorPool = 
                _htASelectRequestorPools.get(oRequestorPool.getID());
            if(!isSigned && doSigning(oRequestorPool, oASRequestorPool, oRequestor))
            {
                StringBuffer sbError = new StringBuffer("Requestor '");
                sbError.append(oRequestor.getID());
                sbError.append(
                    "' requires signing and the message is not signed");
                _logger.debug(sbError.toString());
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);   
            }
            
            //Create session
            oSession = _SessionFactory.createSession(sRequestorID);
            oSession.setForcedAuthentication(forcedLogon);
            oSession.setPassive(passive);
            
            //set all the attributes needed for the verify credentials handling
            ISessionAttributes oAttributes = oSession.getAttributes();
            oAttributes.put(ASelectProcessor.class, 
                ASelectProcessor.SESSION_REQUESTOR_URL, sRequestorURL);
                        
            //Optional parameters
            if (sUID != null)
            {
                if(sUID.length() <= 0)
                {
                    _logger.debug( "Invalid uid found in request");
                    throw new BusinessRuleException(
                        RequestorEvent.REQUEST_INVALID,
                        ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                }
                //set supplied uid as forced user id
                oSession.setForcedUserID(sUID);
            }
            else
                _logger.debug("No optional user ID found in request");
            
            if (sRemoteOrganization != null)
            {
                //set supplied organization as forced organization
                Collection<String> cOrganizations = new Vector<String>();
                cOrganizations.add(sRemoteOrganization);
                oAttributes.put(ProxyAttributes.class, 
                    ProxyAttributes.FORCED_ORGANIZATIONS, cOrganizations);
            }
            else
                _logger.debug(
                    "No optional remote organization found in request");
            
            Locale oLocale = null;            
            if (sCountry == null)
            {
                _logger.debug("No optional country found in request");
            }
            else if (!LocaleValidator.validateCountry(sCountry))
            {
                StringBuffer sbError = new StringBuffer(
                    "Invalid country found in request: ");
                sbError.append(sCountry);
                _logger.debug(sbError.toString());
                throw new BusinessRuleException(
                    RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            if(sLanguage == null)
            {                
                _logger.debug("No optional language found in request");
                if(sCountry != null)
                {
                    //Create Locale with country, no language
                    oLocale = new Locale(
                        Locale.getDefault().getLanguage(), sCountry);
                }
            }
            else
            {
                if (!LocaleValidator.validateLanguage(sLanguage))
                {
                    StringBuffer sbError = new StringBuffer(
                        "Invalid language found in request: ");
                    sbError.append(sLanguage);
                    _logger.debug(sbError.toString());
                    throw new BusinessRuleException(
                        RequestorEvent.REQUEST_INVALID,
                        ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                }
                if(sCountry != null)
                {
                    //Create Locale with language and country
                    oLocale = new Locale(sLanguage, sCountry);
                }
                else
                {
                    // Create Locale with language, no country
                    oLocale = new Locale(sLanguage);
                }
            }    
            //DD if the locale is specified by the requestor then force this locale
            oSession.setLocale(oLocale);     
                             
            //Persist session
            oSession.persist();           
            
            //Event logging
            _eventLogger.info(new RequestorEventLogItem(oSession, sRemoteAddr, 
              RequestorEvent.AUTHN_INITIATION_SUCCESSFUL, this, null));        
        }
        catch (BusinessRuleException e)
        { 
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                e.getEvent(), null, sRemoteAddr, null, this, 
                e.getMessage()));               
            throw e;
        }    
        catch (OAException e)
        {  
            _logger.warn(
                "Internal error during initiation of the authentication process"
                , e);
            if(oSession != null)
            {
                _eventLogger.info(new RequestorEventLogItem(
                    oSession, sRemoteAddr, RequestorEvent.INTERNAL_ERROR, 
                    this, null));
            }
            else
            {
                _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                    RequestorEvent.INTERNAL_ERROR, null, sRemoteAddr, null, this, 
                    null));               
            }
            throw e;
        }
        catch (Exception e)
        {   
            _logger.error(
                "Internal error during initiation of the authentication process"
                , e);
            if(oSession != null)
            {
                _eventLogger.info(new RequestorEventLogItem(
                    oSession, sRemoteAddr, RequestorEvent.INTERNAL_ERROR, 
                    this, null));
            }
            else
            {
                _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                    RequestorEvent.INTERNAL_ERROR, null, sRemoteAddr, null, this, 
                    null));               
            }
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
        return oSession;
    }

    /**
     * verify authentication.
     * @throws AuthNException 
     * @see IRequestorService#verifyAuthentication(java.lang.String, 
     *  java.lang.String, java.lang.String, java.lang.String, java.lang.String, 
     *  boolean)
     */
    public TGTInfo verifyAuthentication(String sOaID, String sRequestorID,
        String sRID, String sCredentials, String sRemoteAddr, boolean isSigned) 
        throws BusinessRuleException, OAException, AuthNException
    {
        TGTInfo info = null;
        ISession oSession = null;
        try
        {
            //Initialization check 
            if(!isInitialized())
            {
                _logger.warn("A-Select WS Requestor Service not initialized");
                throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
            }
            
            //Null checks
            if (sRID == null)
            {
                _logger.debug("No rid found in request");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }   
            
            if (sOaID == null)
            {
                _logger.debug("No oa server ID found in request");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }            
            
            if(_forceRequestorID && sRequestorID == null) //Optional by configuration
            {
                _logger.debug("No requestor ID found in request");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
                         
            if(!SessionValidator.validateDefaultSessionId(sRID))
            {
                _logger.debug("Invalid rid found in request");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
                       
            if (sCredentials == null)
            {
                _logger.debug("No credentials found in request");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
                        
            //Bussiness rule validation
            if (!_OAServer.getID().equals(sOaID))
            {
                StringBuffer sbError = new StringBuffer(
                    "The OA Server ID doesn't correspond to the supplied oa ID: ");
                sbError.append(sOaID);
                _logger.debug(sbError.toString());
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_ID_MISMATCH);
            }
            
            oSession = _SessionFactory.retrieve(sRID);
            if (oSession == null)
            {
                _logger.debug("No session found with id: " + sRID);
                throw new BusinessRuleException(RequestorEvent.SESSION_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
            }
            if (oSession.isExpired())
            {
                _logger.debug("Session expired with id: " + sRID);
                throw new BusinessRuleException(RequestorEvent.SESSION_EXPIRED,
                    ASelectErrors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
            }
                        
            String sOrigionalRequestor = oSession.getRequestorId();
            //Check requestor id if available
            if(sRequestorID != null)
            {                          
                if(!sOrigionalRequestor.equals(sRequestorID))
                {                
                    _logger.debug("Supplied requestor ID does not match original requestor");
                    throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                        ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                }
            }
                           
            //Check session attributes
            ISessionAttributes oAttributes = oSession.getAttributes();
            String sRequestorUrl = (String)oAttributes.get(
                ASelectProcessor.class, 
                ASelectProcessor.SESSION_REQUESTOR_URL);
            if (sRequestorUrl == null)
            {
                _logger.warn(
                    "No session attribute found with with name: " 
                    + ASelectProcessor.SESSION_REQUESTOR_URL);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            String sSessionCredentials = (String)oAttributes.get(
                ASelectProcessor.class, 
                ASelectProcessor.SESSION_CREDENTIALS);
            if (sSessionCredentials == null)
            {
                _logger.debug("No valid credentials in session");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_TGT);
            }
            //TODO syntax check for credentials
            if (!sSessionCredentials.equals(sCredentials))
            {
                StringBuffer sbWarn = new StringBuffer("Credentials in session (");
                sbWarn.append(sSessionCredentials);
                sbWarn.append(") doesn't correspond to credentials in request: ");
                sbWarn.append(sCredentials);
                _logger.debug(sbWarn.toString());
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_TGT);
            }
            
            //Check autentication result
            switch (oSession.getState())
            {
                case AUTHN_OK:
                {
                    //Authentication Ok create response
                    IUser oUser = oSession.getUser();
                    if (oUser == null)
                    {
                        _logger.warn("No User found in session");
                        throw new OAException(SystemErrors.ERROR_INTERNAL);
                    }
                    
                    IRequestor oRequestor = _requestorPoolFactory.getRequestor(sOrigionalRequestor);
                    if (oRequestor == null)
                    {
                        _logger.warn("No Requestor found with id: " + sOrigionalRequestor);
                        throw new OAException(SystemErrors.ERROR_INTERNAL);
                    }
                    
                    RequestorPool oRequestorPool = 
                        _requestorPoolFactory.getRequestorPool(sOrigionalRequestor);
                    if (oRequestorPool == null)
                    {
                        _logger.warn("No Requestor Pool found for requestor id: " + sOrigionalRequestor);
                        throw new OAException(SystemErrors.ERROR_INTERNAL);
                    }
                    
                    ASelectRequestorPool oASRequestorPool = 
                        _htASelectRequestorPools.get(oRequestorPool.getID());
                    if(!isSigned && doSigning(oRequestorPool, oASRequestorPool, oRequestor))
                    {
                        StringBuffer sbError = new StringBuffer("Requestor '");
                        sbError.append(oRequestor.getID());
                        sbError.append(
                            "' requires signing and the message is not signed");
                        _logger.debug(sbError.toString());
                        throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                            ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);   
                    }
                    
                    String sAppLevel = getAppLevel(oRequestorPool, 
                        oASRequestorPool, oRequestor);
                    int iAppLevel = Integer.valueOf(sAppLevel);//already verified in getAppLevel
                    
                    //DD TGT Expiration time is 0 when single sign-on disabled
                    long lTGTExpireTime = 0; 
                    String sAuthNProfile = null;
                    ITGT oTGT = null;
                    String sTGTID = oSession.getTGTId();
                    if (sTGTID != null)
                    {
                        oTGT = _tgtFactory.retrieve(sTGTID);
                        if (oTGT == null)
                        {
                            _logger.warn("No TGT ID found in session");
                            throw new OAException(SystemErrors.ERROR_INTERNAL);
                        }
                        
                        lTGTExpireTime = oTGT.getTgtExpTime().getTime();
                        
                        sAuthNProfile = getHighestAuthNProfile(oTGT.getAuthNProfileIDs());
                        
                        if (sAuthNProfile == null)
                        {
                            IAuthenticationProfile oAuthNProfile = oSession.getSelectedAuthNProfile();
                            if (oAuthNProfile != null)
                                sAuthNProfile = oAuthNProfile.getID();
                        }
                        
                        if (sAuthNProfile == null)
                            sAuthNProfile = oTGT.getAuthNProfileIDs().get(0);
                    }
                    else
                    {
                        IAuthenticationProfile oAuthNProfile = 
                            oSession.getSelectedAuthNProfile();
                        if (oAuthNProfile == null)
                        {
                            _logger.warn(
                                "No authentication profile found in Session");
                            throw new OAException(SystemErrors.ERROR_INTERNAL);
                        }
                        
                        sAuthNProfile = oAuthNProfile.getID();
                    }
                   
                    int iAuthSPLevel = getAuthSPLevel(sAuthNProfile);
                    
                    String sUid = null;
                    try
                    {
                        //uid mapping/opaque uid
                        sUid = getUid(oUser, oASRequestorPool, 
                            oRequestorPool, oRequestor);
                    }
                    catch (AuthNException e)
                    {
                        if (oTGT != null)
                        {
                            oTGT.removeRequestorID(oRequestor.getID());
                            _aliasStoreSP.removeAlias(
                                BrowserHandler.ALIAS_TYPE_CREDENTIALS, 
                                oRequestor.getID(), sCredentials);
                            
                            if (oTGT.getRequestorIDs().size() == 0)
                            {
                                oTGT.expire();
                                oTGT.persist();
                            }
                        }
                        
                        throw e;
                    }
                    
                    String sAttributes = null;
                    IAttributes attributes = oUser.getAttributes();
                    if (attributes != null && attributes.size() > 0)
                        sAttributes = serializeAttributes(attributes);
                    
                    info = new TGTInfo(_OAServer.getID(), 
                       oUser.getOrganization(), iAppLevel,  
                        iAuthSPLevel, sAuthNProfile, sUid, lTGTExpireTime);
                    info.setAttributes(sAttributes);
                    
                    //Event logging
                    _eventLogger.info(new RequestorEventLogItem(oSession, sRemoteAddr, 
                      RequestorEvent.TOKEN_DEREFERENCE_SUCCESSFUL, this, null));
                    //Expire session
                    oSession.expire();
                    oSession.persist();
                    break;
                }
                case USER_CANCELLED:
                {
                    _logger.debug("Authentication failed: " 
                        + oSession.getState().name());
                    throw new AuthNException(
                        ASelectErrors.ERROR_ASELECT_SERVER_CANCEL);
                }
                case AUTHN_FAILED:
                {
                    _logger.debug("Authentication failed: " 
                        + oSession.getState().name());
                    throw new AuthNException(
                        ASelectErrors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
                }
                case PRE_AUTHZ_FAILED:
                {
                    _logger.debug("Authentication failed: " 
                        + oSession.getState().name());
                    throw new AuthNException(
                        ASelectErrors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
                }   
                case POST_AUTHZ_FAILED:
                {
                    _logger.debug("Authentication failed: " 
                        + oSession.getState().name());
                    throw new AuthNException(
                        ASelectErrors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
                }
                case AUTHN_SELECTION_FAILED:
                {
                    _logger.debug("Authentication failed: " 
                        + oSession.getState().name());
                    throw new AuthNException(
                        ASelectErrors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER);
                }
                case USER_BLOCKED:
                {
                    _logger.debug("Authentication failed: " 
                        + oSession.getState().name());
                    throw new AuthNException(
                        ASelectErrors.ERROR_USER_BLOCKED);
                }
                case USER_UNKNOWN:
                {
                    _logger.debug("Authentication failed: " 
                        + oSession.getState().name());
                    throw new AuthNException(
                        ASelectErrors.ERROR_ASELECT_UDB_UNKNOWN_USER);
                }
                case PASSIVE_FAILED:
                {
                    _logger.debug("Authentication failed: " 
                        + oSession.getState().name());
                    throw new AuthNException(
                        ASelectErrors.ERROR_PASSIVE_FAILED);
                }
                default:
                {
                    _logger.warn(
                        "Authentication failed, due to invalid session state: " 
                        + oSession.getState().name());
                    throw new AuthNException(
                        ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                }
            }           
        }
        catch(AuthNException e)
        {
            if(oSession != null)
            {
                _eventLogger.info(new RequestorEventLogItem(oSession, sRemoteAddr, 
                    e.getEvent(), this, e.getMessage()));
                info = new TGTInfo(e.getMessage());
                oSession.expire();
                oSession.persist();
            }
            else
            {
                _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                    e.getEvent(), null, sRemoteAddr, null, this, 
                    e.getMessage()));  
                info = new TGTInfo(e.getMessage());
            }
        }
        catch (BusinessRuleException e)
        { 
            if(oSession != null)
            {
                _eventLogger.info(new RequestorEventLogItem(
                    oSession, sRemoteAddr, e.getEvent(), 
                    this, e.getMessage()));
            }
            else
            {
                _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                    e.getEvent(), null, sRemoteAddr, null, this, 
                    e.getMessage()));               
            }
            throw e;
        }    
        catch (OAException e)
        {        
            _logger.warn(
                "Internal error during verification of the authentication process"
                , e);
            if(oSession != null)
            {
                _eventLogger.info(new RequestorEventLogItem(
                    oSession, sRemoteAddr, RequestorEvent.INTERNAL_ERROR, 
                    this, null));
            }
            else
            {
                _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                    RequestorEvent.INTERNAL_ERROR, null, sRemoteAddr, null, this, 
                    null));               
            }
            throw e;
        }
        catch (Exception e)
        {   
            _logger.fatal(
                "Internal error during verification of the authentication process"
                , e);
            if(oSession != null)
            {
                _eventLogger.info(new RequestorEventLogItem(
                    oSession, sRemoteAddr, RequestorEvent.INTERNAL_ERROR, 
                    this, null));
            }
            else
            {
                _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                    RequestorEvent.INTERNAL_ERROR, null, sRemoteAddr, null, this, 
                    null));               
            }
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }      
        return info;
    }
    
    /**
     * Initiate asynchronous logout.
     * @see IRequestorService#slo(java.lang.String, java.lang.String, 
     * java.lang.String, java.lang.String, java.lang.String, boolean)
     */
    public ISession slo(String sOaID, String sRequestorID, String sCredentials,
        String sRequestorURL, String sRemoteAddr, boolean isSigned) 
        throws BusinessRuleException, OAException
    {
        ISession oSession = null;
        try
        {
            if(!isInitialized())
            {
                _logger.warn("OA Requestor Service not initialized");
                throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
            }
            
            //Null checks
            if (sOaID == null)
            {
                _logger.debug("No oa server ID found in request");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }            
            
            if (sRequestorID == null)
            {
                _logger.debug("No requestor ID found in request");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            if (sCredentials == null)
            {
                _logger.debug("No cerdentials found in request");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            if (sRequestorURL != null)
            {
                StringBuffer sbDebug = new StringBuffer("Optional '");
                sbDebug.append(ASelectProcessor.PARAM_APPURL);
                sbDebug.append("' found in request: ");
                sbDebug.append(sRequestorURL);
                _logger.debug(sbDebug.toString());
                try
                {
                    new URL(sRequestorURL);
                }
                catch(MalformedURLException e)
                {
                    _logger.debug( "Invalid requestor URL found in request");
                    throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                        ASelectErrors.ERROR_ASELECT_SERVER_INVALID_APP_URL);
                } 
            }
            else
            {//DD if no app_url is supplied as return url, use the profile url
                sRequestorURL = _sRedirectURL;
            }
                       
            
            //Bussiness rule validation
            if (!_OAServer.getID().equals(sOaID))
            {
                _logger.debug("The oa ID doesn't correspond.");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_ID_MISMATCH);
            }
            
            IRequestor oRequestor = _requestorPoolFactory.getRequestor(
                sRequestorID);
            if (oRequestor == null)
            {
                StringBuffer sbError = new StringBuffer(
                    "Unknown requestor found in request: ");
                sbError.append(sRequestorID);
                _logger.debug(sbError.toString());
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_APP);                   
            }
            
            
            if (!oRequestor.isEnabled())
            {
                _logger.debug("Disabled requestor found in request: " + sRequestorID);
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
            }
            
            RequestorPool oRequestorPool = 
                _requestorPoolFactory.getRequestorPool(oRequestor.getID());
            if (oRequestorPool == null)
            {
                _logger.warn("Requestor not available in a pool: " 
                    + oRequestor.getID());
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }

            if (!oRequestorPool.isEnabled())
            {
                StringBuffer sbError = new StringBuffer("Requestor '");
                sbError.append(oRequestor.getID());
                sbError.append("' is found in a disabled requestor pool: ");
                sbError.append(oRequestorPool.getID());
                _logger.warn(sbError.toString());
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            ASelectRequestorPool oASRequestorPool = 
                _htASelectRequestorPools.get(oRequestorPool.getID());
            if(!isSigned && doSigning(oRequestorPool, oASRequestorPool, oRequestor))
            {
                StringBuffer sbError = new StringBuffer("Requestor '");
                sbError.append(oRequestor.getID());
                sbError.append(
                    "' requires signing and the message is not signed");
                _logger.debug(sbError.toString());
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);   
            }
            
            if (!_aliasStoreSP.isAlias(BrowserHandler.ALIAS_TYPE_CREDENTIALS, 
                sRequestorID, sCredentials))
            {
                _logger.debug("Unknown credentials supplied in request: " 
                    + sCredentials);
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_TGT); 
            }
                   
            oSession = _SessionFactory.createSession(sRequestorID);
            
            //set all the attributes
            ISessionAttributes oAttributes = oSession.getAttributes();
            oAttributes.put(ASelectProcessor.class, 
                ASelectProcessor.SESSION_REQUESTOR_URL, sRequestorURL);
            
            oSession.persist();                               
            //Event logging
            _eventLogger.info(new RequestorEventLogItem(oSession, sRemoteAddr, 
              RequestorEvent.LOGOUT_INITIATION_SUCCESSFUL, this, null));        
        }
        catch (BusinessRuleException e)
        { 
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                e.getEvent(), null, sRemoteAddr, null, this, 
                e.getMessage()));               
            throw e;
        }    
        catch (OAException e)
        {  
            _logger.warn(
                "Internal error during initiation of the logout process"
                , e);
            if(oSession != null)
            {
                _eventLogger.info(new RequestorEventLogItem(
                    oSession, sRemoteAddr, RequestorEvent.INTERNAL_ERROR, 
                    this, null));
            }
            else
            {
                _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                    RequestorEvent.INTERNAL_ERROR, null, sRemoteAddr, null, 
                    this, null));               
            }
            throw e;
        }
        catch (Exception e)
        {   
            _logger.error(
                "Internal error during initiation of the logout process"
                , e);
            if(oSession != null)
            {
                _eventLogger.info(new RequestorEventLogItem(
                    oSession, sRemoteAddr, RequestorEvent.INTERNAL_ERROR, 
                    this, null));
            }
            else
            {
                _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                    RequestorEvent.INTERNAL_ERROR, null, sRemoteAddr, null, this, 
                    null));               
            }
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
        return oSession;
    }
    

    /**
     * Perform a synchronous logout.
     * @see IRequestorService#logout(java.lang.String, 
     *  java.lang.String, java.lang.String, boolean, java.lang.String)
     */
    public String logout(String sRequestorID, String sCredentials, 
        String sRemoteAddr, boolean isSigned, String reason) 
        throws BusinessRuleException, OAException
    {
        try
        {            
            if(!isInitialized())
            {
                _logger.warn("OA Requestor Service not initialized");
                throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
            }
            
            //Null checks            
            if (sRequestorID == null)
            {
                _logger.debug("No requestor ID found in request");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            if (sCredentials == null)
            {
                _logger.debug("No credentials found in request");
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
           
            
            //Bussiness rule validation
            if (reason != null && !ASelectProcessor.VALUE_REASON_TIMEOUT.equalsIgnoreCase(reason))
            {
                _logger.debug(
                    "Invalid reason in request from SP with id: " 
                    + sRequestorID);
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            IRequestor oRequestor = _requestorPoolFactory.getRequestor(
                sRequestorID);
            if (oRequestor == null)
            {
                StringBuffer sbError = new StringBuffer(
                    "Unknown requestor found in request: ");
                sbError.append(sRequestorID);
                _logger.debug(sbError.toString());
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_APP);                   
            }
            
            if (!oRequestor.isEnabled())
            {
                _logger.debug("Disabled requestor found in request: " + sRequestorID);
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
            }
            
            RequestorPool oRequestorPool = 
                _requestorPoolFactory.getRequestorPool(oRequestor.getID());
            if (oRequestorPool == null)
            {
                _logger.warn("Requestor not available in a pool: " 
                    + oRequestor.getID());
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }

            if (!oRequestorPool.isEnabled())
            {
                StringBuffer sbError = new StringBuffer("Requestor '");
                sbError.append(oRequestor.getID());
                sbError.append("' is found in a disabled requestor pool: ");
                sbError.append(oRequestorPool.getID());
                _logger.warn(sbError.toString());
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            ASelectRequestorPool oASRequestorPool = 
                _htASelectRequestorPools.get(oRequestorPool.getID());
            if(!isSigned && doSigning(oRequestorPool, oASRequestorPool, oRequestor))
            {
                StringBuffer sbError = new StringBuffer("Requestor '");
                sbError.append(oRequestor.getID());
                sbError.append(
                    "' requires signing and the message is not signed");
                _logger.debug(sbError.toString());
                throw new BusinessRuleException(RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);   
            }                      
            
            if (_aliasStoreSP == null)
            {
                _logger.debug("TGT Factory has no SP alias support");
                throw new BusinessRuleException(
                    RequestorEvent.REQUEST_INVALID,
                    ASelectErrors.ERROR_LOGOUT_FAILED);
            }
                                          
            String sTGTID = _aliasStoreSP.getTGTID(
                BrowserHandler.ALIAS_TYPE_CREDENTIALS, 
                oRequestor.getID(), sCredentials);
            RequestorEvent event = RequestorEvent.LOGOUT_SUCCESS;
            if (sTGTID != null)
            {
                ITGT tgt = _tgtFactory.retrieve(sTGTID);
                if (tgt != null && !tgt.isExpired())
                {
                    //DD remove the credentials, so offline logout will not be triggered again to this requestor
                    _aliasStoreSP.removeAlias(
                        BrowserHandler.ALIAS_TYPE_CREDENTIALS, 
                        oRequestor.getID(), sCredentials);
                    
                    if (reason != null && tgt.getRequestorIDs().size() > 1)
                    {//DD If reason == timeout then do not expire the tgt
                        tgt.removeRequestorID(oRequestor.getID());
                        tgt.persist();
                        event = RequestorEvent.LOGOUT_PARTIALLY;
                    }
                    else
                    {
                        try
                        {
                            if (reason != null)
                            {
                                tgt.clean();//performs the expire event
                            }
                            else
                            {
                                tgt.expire();
                                tgt.persist();//performs the remove event
                            }   
                        }
                        catch (TGTListenerException e)
                        {
                            event = getLogoutError(e.getErrors());
                        }
                    }
                }
            }
            
            String aselectError = null;
            switch(event)
            {
                case LOGOUT_SUCCESS:
                    aselectError = ASelectErrors.ERROR_ASELECT_SUCCESS;
                    break;
                case LOGOUT_PARTIALLY:
                    aselectError = ASelectErrors.ERROR_LOGOUT_PARTIALLY;
                    break;
                default:
                    aselectError = ASelectErrors.ERROR_LOGOUT_FAILED;
            }              
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                event, null, sRemoteAddr, null, this, 
                aselectError));
            return aselectError;
        }
        catch (BusinessRuleException e)
        { 
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                e.getEvent(), null, sRemoteAddr, null, this, 
                e.getMessage()));               
            throw e;
        }    
        catch (OAException e)
        {  
            _logger.warn(
                "Internal error during the logout process", e);
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                    RequestorEvent.INTERNAL_ERROR, null, sRemoteAddr, null, 
                    this, null));               
            throw e;
        }
        catch (Exception e)
        {   
            _logger.error("Internal error during the logout process", e);
           _eventLogger.info(new RequestorEventLogItem(null, null, null, 
               RequestorEvent.INTERNAL_ERROR, null, sRemoteAddr, null, this, 
               null));               
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
    }
    
    /**
     * retrieve the base URL to the A-Select Profile User service.
     * @return The base URL.
     */
    public String getRedirectURLBase()
    {
        return _sRedirectURL;
    }

    /**
     * Stop the <code>RequestorService</code>
     * @see com.alfaariss.oa.profile.aselect.business.AbstractOAService#stop()
     */
    public void stop()
    {
        _initialized = false;
        _sRedirectURL = null;
        super.stop();             
    }
    
    //TODO the following ,methods are redundant; merge the ASelect Profile and ws (Erwin, Martijn)
    
    /*
     * Returns the authN profile id with the highest authsp_level value.
     *
     * @param listAuthNProfileIDs a list with authN profile id's
     * @return authN profile id
     * @throws OAException if authsp_level could not be resolved from model
     */
    private String getHighestAuthNProfile(List<String> listAuthNProfileIDs) 
        throws OAException
    {
        String sHighestProfile = null;
        int iMaxLevel = -1; 
        for (String sAuthNProfileID: listAuthNProfileIDs)
        {
            if (_htAuthSPLevels.containsKey(sAuthNProfileID))
            {
                int iAuthNProfileID = _htAuthSPLevels.get(sAuthNProfileID);
                if (iAuthNProfileID > iMaxLevel)
                {
                    iMaxLevel = iAuthNProfileID;
                    sHighestProfile = sAuthNProfileID;
                }
            }
            else
            {
                AuthenticationProfile authnProfile = null;
                try
                {
                    authnProfile = _authenticationProfileFactory.getProfile(sAuthNProfileID);
                }
                catch (AuthenticationException e)
                {
                    _logger.error("Authentication profile not available: " + sAuthNProfileID);
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                
                String sLevel = (String)authnProfile.getProperty(PROPERTY_AUTHSP_LEVEL);
                if (sLevel != null)
                {
                    try
                    {
                        int iAuthNProfileID = Integer.valueOf(sLevel);
                        if (iAuthNProfileID > iMaxLevel)
                        {
                            iMaxLevel = iAuthNProfileID;
                            sHighestProfile = sAuthNProfileID;
                        }
                    }
                    catch (NumberFormatException e)
                    {
                        StringBuffer sbError = new StringBuffer("Invalid value of the '");
                        sbError.append(PROPERTY_AUTHSP_LEVEL);
                        sbError.append("' property available: ");
                        sbError.append(sLevel);
                        _logger.error(sbError.toString());
                        
                        throw new OAException(SystemErrors.ERROR_INTERNAL);
                    }
                }
            }
        }
        return sHighestProfile;
    }
    
    /*
     * Resolves the authsp_level for the specified authentication profile.
     * 
     * @param sAuthNProfileID The profile id for which the authsp_level should be resolved
     * @return The authsp_level
     * @throws OAException if authsp_level could not be resolved from model
     * @since 1.1
     */
    private Integer getAuthSPLevel(String sAuthNProfileID) throws OAException
    {
        Integer intAuthSPLevel = _iDefaultAuthSPLevel; 
        if (_htAuthSPLevels.containsKey(sAuthNProfileID))
            intAuthSPLevel = _htAuthSPLevels.get(sAuthNProfileID);
        else
        {
            AuthenticationProfile authnProfile = null;
            try
            {
                authnProfile = _authenticationProfileFactory.getProfile(sAuthNProfileID);
            }
            catch (AuthenticationException e)
            {
                _logger.error("Authentication profile not available: " + sAuthNProfileID);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            String sLevel = (String)authnProfile.getProperty(PROPERTY_AUTHSP_LEVEL);
            if (sLevel != null)
            {
                try
                {
                    intAuthSPLevel = new Integer(sLevel);
                }
                catch (NumberFormatException e)
                {
                    StringBuffer sbError = new StringBuffer("Invalid value of the '");
                    sbError.append(PROPERTY_AUTHSP_LEVEL);
                    sbError.append("' property available: ");
                    sbError.append(sLevel);
                    _logger.error(sbError.toString());
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
            }
        }
        return intAuthSPLevel;
    }    
    
    /*
     * Serialize attributes contained in a hashtable.
     * 
     * This method serializes attributes contained in a hashtable:
     * <ul>
     *  <li>They are formatted as attr1=value1&attr2=value2;...</li>
     *  <li>If a "&amp;" or a "=" appears in either the attribute name
     *  or value, they are transformed to %26 or %3d respectively.</li>
     *  <li>The end result is base64 encoded.</li>
     * </ul>
     * 
     * @param oAttributes IAttributes object containing all attributes
     * @return Serialized representation of the attributes
     * @throws ASelectException If serialization fails.
     */
    private String serializeAttributes(IAttributes oAttributes)
        throws OAException
    {
        String sReturn = null;
        try
        {
            StringBuffer sbCGI = new StringBuffer();

            Enumeration enumGatheredAttributes = oAttributes.getNames();
            while (enumGatheredAttributes.hasMoreElements())
            {
                StringBuffer sbPart = new StringBuffer();
                
                String sKey = (String)enumGatheredAttributes.nextElement();
                Object oValue = oAttributes.get(sKey);

                if (oValue instanceof Vector)
                {// it's a multivalue attribute
                    Vector vValue = (Vector)oValue;
                    Enumeration eEnum = vValue.elements();
                    while (eEnum.hasMoreElements())
                    {
                        String sValue = (String)eEnum.nextElement();
                        sbPart.append(URLEncoder.encode(sKey + "[]",
                            ASelectProcessor.CHARSET));
                        sbPart.append("=");
                        sbPart.append(URLEncoder.encode(sValue,
                            ASelectProcessor.CHARSET));

                        if (eEnum.hasMoreElements())
                            sbPart.append("&");
                    }
                }
                else if (oValue instanceof String)
                {// it's a single value attribute
                    String sValue = (String)oValue;

                    sbPart.append(URLEncoder.encode(sKey,
                        ASelectProcessor.CHARSET));
                    sbPart.append("=");
                    sbPart.append(URLEncoder.encode(sValue,
                        ASelectProcessor.CHARSET));
                }
                else
                {
                    StringBuffer sbDebug = new StringBuffer("Attribute '");
                    sbDebug.append(sKey);
                    sbDebug.append("' has an unsupported value; is not a String: ");
                    sbDebug.append(oValue);
                    _logger.debug(sbDebug.toString());
                }

                if (sbPart.length() > 0 && sbCGI.length() > 0)
                    sbCGI.append("&");
                
                sbCGI.append(sbPart);
            }

            if (sbCGI.length() > 0)
            {
                byte[] baCGI = Base64.encodeBase64(sbCGI.toString().getBytes(
                    ASelectProcessor.CHARSET));
                sReturn = new String(baCGI, ASelectProcessor.CHARSET);
            }
        }
        catch (Exception e)
        {
            _logger.fatal("Could not serialize attributes: "
                + oAttributes.toString(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }

        return sReturn;
    }
    
    /*
     * Resolves the value for the uid parameter of the A-Select protocol.
     * 
     * @param oUser The User object
     * @param oASRequestorPool Requestor Pool object or <code>null</code>
     * @param oRequestor OA Requestor
     * @return the resolved uid value
     * @throws OAException if no uid can be resolved (internal error)
     * @throws AuthNException If uid could not be resolved (missing required attribute)
     */
    private String getUid(IUser oUser, ASelectRequestorPool oASRequestorPool, 
        RequestorPool oRequestorPool, IRequestor oRequestor) 
        throws OAException, AuthNException
    {
        String sUid = oUser.getID();
        
        String sUidAttribute = (String)oRequestor.getProperty(PROPERTY_UID_ATTRIBUTE);
        if (sUidAttribute == null)
        {
            if (oASRequestorPool != null)
                sUidAttribute = oASRequestorPool.getUidAttribute();
            if (sUidAttribute == null)
                sUidAttribute = (String)oRequestorPool.getProperty(PROPERTY_UID_ATTRIBUTE);
        }
        
        if (sUidAttribute != null)
        {
            IAttributes oAttributes = oUser.getAttributes();
            sUid = (String)oAttributes.get(sUidAttribute);
            if (sUid == null)
            {
                StringBuffer sbError = new StringBuffer(
                    "Missing required attribute (");
                sbError.append(sUidAttribute);
                sbError.append(") to resolve uid for user with ID: ");
                sbError.append(oUser.getID());
                _logger.warn(sbError.toString());
                throw new AuthNException(
                    ASelectErrors.ERROR_MISSING_REQUIRED_ATTRIBUTE);
            }
            
            //DD Remove the used attribute from the user attributes, so it will not be released to the application
            oAttributes.remove(sUidAttribute);
        }
        
        boolean bOpaqueUID = false;
        String sUIDOpaque = (String)oRequestor.getProperty(PROPERTY_UID_OPAQUE_ENABLED);
        if (sUIDOpaque != null)
        {
            if ("TRUE".equalsIgnoreCase(sUIDOpaque))
                bOpaqueUID = true;
            else if (!"FALSE".equalsIgnoreCase(sUIDOpaque))
            {
                StringBuffer sbError = new StringBuffer("Invalid value for requestor property '");
                sbError.append(PROPERTY_UID_OPAQUE_ENABLED);
                sbError.append("': ");
                sbError.append(sUIDOpaque);
                
                _logger.error(sbError.toString());
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        else
        {
            if (oASRequestorPool != null)
                bOpaqueUID = oASRequestorPool.isUidOpaque();
            if (!bOpaqueUID)
            {
                sUIDOpaque = (String)oRequestorPool.getProperty(PROPERTY_UID_OPAQUE_ENABLED);
                if (sUIDOpaque != null)
                {
                    if ("TRUE".equalsIgnoreCase(sUIDOpaque))
                        bOpaqueUID = true;
                    else if (!"FALSE".equalsIgnoreCase(sUIDOpaque))
                    {
                        StringBuffer sbError = new StringBuffer("Invalid value for '");
                        sbError.append(PROPERTY_UID_OPAQUE_ENABLED);
                        sbError.append("' requestor pool attribute: ");
                        sbError.append(sUIDOpaque);
                        
                        _logger.error(sbError.toString());
                        throw new OAException(SystemErrors.ERROR_INTERNAL);
                    }
                }
            }
        }
        
        if (bOpaqueUID)
        {
            String sSalt = (String)oRequestor.getProperty(PROPERTY_UID_OPAQUE_SALT);
            if (sSalt == null)
            {
                if (oASRequestorPool != null)
                    sSalt = oASRequestorPool.getUidOpaqueSalt();
                if (sSalt == null)
                    sSalt = (String)oRequestorPool.getProperty(PROPERTY_UID_OPAQUE_SALT);
            }
            
            if (sSalt != null)
                sUid = sUid + sSalt;
            
            // the returned user ID must contain an opaque value 
            MessageDigest oMessageDigest = _cryptoManager.getMessageDigest();
            try
            {
                oMessageDigest.update(sUid.getBytes(ASelectProcessor.CHARSET));
                sUid = toHexString(oMessageDigest.digest());
            }
            catch (Exception e)
            {
                _logger.warn(
                    "Unable to generate SHA1 hash from user ID: " 
                    + sUid);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        
        return sUid;
    }
    
    /**
     * Resolves the app level from ASelectRequestorPool or RequestorPool.
     *
     * @param oRequestorPool OA Requestor pool
     * @param oASRequestorPool A-Select requestor pool
     * @param oRequestor OA Requestor
     * @return The app level
     * @throws OAException
     * @since 1.1
     */
    private String getAppLevel(RequestorPool oRequestorPool, 
        ASelectRequestorPool oASRequestorPool, IRequestor oRequestor) throws OAException
    {
        String sAppLevel = String.valueOf(_iDefaultAppLevel);
        
        int iAppLevel = -1;
        
        String appLevel = (String)oRequestor.getProperty(PROPERTY_APP_LEVEL);
        if (appLevel != null)
        {
            try
            {
                iAppLevel = Integer.valueOf(appLevel);
            }
            catch (NumberFormatException e)
            {
                StringBuffer sbError = new StringBuffer("The configured requestor property (");
                sbError.append(PROPERTY_APP_LEVEL);
                sbError.append(") value isn't a number: ");
                sbError.append(appLevel);
                
                _logger.error(sbError.toString(), e);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        else
        {
            if (oASRequestorPool != null)
                iAppLevel = oASRequestorPool.getAppLevel();
            
            if (iAppLevel == -1)
            {
                appLevel = (String)oRequestorPool.getProperty(PROPERTY_APP_LEVEL);
                if (appLevel != null)
                {
                    try
                    {
                        iAppLevel = Integer.valueOf(appLevel);
                    }
                    catch (NumberFormatException e)
                    {
                        StringBuffer sbError = new StringBuffer("The configured requestorpool property (");
                        sbError.append(PROPERTY_APP_LEVEL);
                        sbError.append(") value isn't a number: ");
                        sbError.append(appLevel);
                        
                        _logger.error(sbError.toString(), e);
                        throw new OAException(SystemErrors.ERROR_INTERNAL);
                    }
                }
            }
        }
        
        if (iAppLevel > 0)
            sAppLevel = String.valueOf(iAppLevel);
        
        return sAppLevel;
    }
    
    /**
     * Returns the logout result.
     *
     * @param listErrors containing all TGT event errors to be verified
     * @return the A-Select Error code as String
     * @since 1.4
     */
    private RequestorEvent getLogoutError(List<TGTEventError> listErrors)
    {
        RequestorEvent event = RequestorEvent.LOGOUT_FAILED;
        for (TGTEventError eventError: listErrors)
        {
            switch(eventError.getCode())
            {
                case USER_LOGOUT_PARTIALLY:
                {
                    event = RequestorEvent.LOGOUT_PARTIALLY;
                    break;
                }
                case USER_LOGOUT_IN_PROGRESS:
                case USER_LOGOUT_FAILED:
                default:
                {
                    //do not search further; logout failed already.
                    return RequestorEvent.LOGOUT_FAILED;
                }
            }
        }
        return event;
    }
        
    /*
     * Hexstring encoding.
     * 
     * Outputs a hex-string respresentation of a byte array.
     * This method returns the hexadecimal String representation of a byte
     * array. 
     * 
     * Example: 
     * For input <code>[0x13, 0x2f, 0x98, 0x76]</code>, this method returns a
     * String object containing <code>"132F9876"</code>.
     * 
     * DD For backwards compatibly the hex presentation is converted to upper case.
     * @param baBytes Source byte array.
     * @return a String object respresenting <code>baBytes</code> in hexadecimal 
     *  format.
     *  @see Hex#encodeHex(byte[])
     */
    private static String toHexString(byte[] baBytes)
    {
        char[] ca = Hex.encodeHex(baBytes);
        String s = new String(ca).toUpperCase();
        return s;       
    }   
}