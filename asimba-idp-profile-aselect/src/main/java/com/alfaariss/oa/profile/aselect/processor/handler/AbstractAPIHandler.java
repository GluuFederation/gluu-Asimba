
/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2010 Alfa & Ariss B.V.
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
package com.alfaariss.oa.profile.aselect.processor.handler;

import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.tgt.TGTEventError;
import com.alfaariss.oa.api.tgt.TGTListenerException;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.authentication.remote.aselect.idp.storage.ASelectIDP;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.authentication.AuthenticationException;
import com.alfaariss.oa.engine.core.authentication.AuthenticationProfile;
import com.alfaariss.oa.engine.core.authentication.factory.IAuthenticationProfileFactory;
import com.alfaariss.oa.engine.core.crypto.CryptoException;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.idp.IDPStorageManager;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
import com.alfaariss.oa.engine.core.server.Server;
import com.alfaariss.oa.engine.core.session.factory.ISessionFactory;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory;
import com.alfaariss.oa.profile.aselect.ASelectErrors;
import com.alfaariss.oa.profile.aselect.ASelectException;
import com.alfaariss.oa.profile.aselect.binding.IBinding;
import com.alfaariss.oa.profile.aselect.binding.IRequest;
import com.alfaariss.oa.profile.aselect.binding.IResponse;
import com.alfaariss.oa.profile.aselect.processor.ASelectProcessor;
import com.alfaariss.oa.util.logging.AbstractEventLogItem;
import com.alfaariss.oa.util.logging.RequestorEventLogItem;


/**
 * Abstract API request handler.
 *
 * <br><br><i>Partitially based on sources from A-Select (www.a-select.org).</i>
 * 
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class AbstractAPIHandler implements IAuthority
{
    /** system logger */
    protected Log _logger;
    /** event logger */
    protected Log _eventLogger;
    /** Server object */
    protected Server _OAServer;
    /** session factory */
    protected ISessionFactory _sessionFactory;
    /** requestor pool factory */
    protected IRequestorPoolFactory _requestorPoolFactory;
    /** authentication profile factory */
    protected IAuthenticationProfileFactory _authnProfileFactory;
    /** tgt factory */
    protected ITGTFactory _tgtFactory;
    /** redirect url */
    protected String _sRedirectURL;
    /** enabled */
    protected boolean _bEnabled;
    /** Hashtable containing the authsp_level per authenticationprofile */
    protected Hashtable<String, Integer> _htAuthSPLevels;
    /** Default authsp_level value */
    protected int _iDefaultAuthSPLevel;
    /** Hashtable containing the app_level per requestorpool */
    protected Hashtable<String, ASelectRequestorPool> _htASelectRequestorPools;
    /** Default app_level value*/
    protected int _iDefaultAppLevel;
    /** Requestors alias store */
    protected ITGTAliasStore _aliasStoreSPRole;
    /** IdP's alias store */
    protected ITGTAliasStore _aliasStoreIDPRole;
    /** IDP Storage manager */
    protected IDPStorageManager _idpStorageManager;
    
    private final static String PROPERTY_SIGN_REQUESTS = ".sign.requests";
    private final static String PROPERTY_APP_LEVEL = ".app_level";
    private final static String PROPERTY_UID_ATTRIBUTE = ".uid.attribute";
    private final static String PROPERTY_UID_OPAQUE_ENABLED = ".uid.opaque.enabled";
    private final static String PROPERTY_UID_OPAQUE_SALT = ".uid.opaque.salt";
    private final static String PROPERTY_AUTHSP_LEVEL = ".authsp_level";
    
    private String _sProfileID;
    /** crypto manager */
    private CryptoManager _cryptoManager;
    
    /**
     * Creates the object.
     *
     * The object can be disabled. This should be checked before the object is 
     * used, because the object won't be fully initialized if its disabled.
     * The object is disabled if no 'enabled' item is found in the supplied 
     * configuration section or the 'disabled' parameter has the value 'false'.
     *  
     * @param oConfigurationManager the configuration manager
     * @param eConfig the config section containing the configuration of this object
     * @param sRedirectURL the full URL to this profile or <code>null</code> (for loadbalanced environments)
     * @param htAuthSPLevels Hashtable containing authsp_levels per authentication profile
     * @param iDefaultAuthSPLevel Default authsp_level
     * @param sProfileID The ID of the OA profile
     * @throws OAException if the creation fails
     */
    public AbstractAPIHandler (IConfigurationManager oConfigurationManager, 
        Element eConfig, String sRedirectURL, 
        Hashtable<String, Integer> htAuthSPLevels, int iDefaultAuthSPLevel,
        String sProfileID) 
        throws OAException
    {
        try
        {
            _logger = LogFactory.getLog(AbstractAPIHandler.class);
            _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
            
            _htAuthSPLevels = htAuthSPLevels;
            _iDefaultAuthSPLevel = iDefaultAuthSPLevel;
            _sProfileID = sProfileID;
            
            _bEnabled = false;
            if (eConfig != null)//if no config supplied, then component is disabled
            {
                String sEnabled = oConfigurationManager.getParam(
                    eConfig, "enabled");
                if (sEnabled == null)
                {
                    _logger.info(
                        "No optional 'enabled' parameter found in handler section in configuration");
                    _bEnabled = true;
                }
                else if (sEnabled.equalsIgnoreCase("true"))
                {
                    _logger.info("Request handler is enabled");
                    _bEnabled = true;
                }
                else if (sEnabled.equalsIgnoreCase("false"))
                {
                    _logger.info("Request handler is disabled");
                    _bEnabled = false;
                }
                else
                {
                    _logger.error(
                        "Wrong 'enabled' parameter found in handler section in configuration: " 
                        + sEnabled);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            if (_bEnabled)
            {
                Engine engine = Engine.getInstance();
                _OAServer = engine.getServer();
                _sessionFactory = engine.getSessionFactory();
                _requestorPoolFactory = engine.getRequestorPoolFactory();
                _tgtFactory = engine.getTGTFactory();
                _aliasStoreSPRole = _tgtFactory.getAliasStoreSP();
                _aliasStoreIDPRole = _tgtFactory.getAliasStoreIDP();
                _idpStorageManager = engine.getIDPStorageManager();
                _authnProfileFactory = engine.getAuthenticationProfileFactory();
                
                _cryptoManager = engine.getCryptoManager();
                if (_cryptoManager == null)
                {
                    _logger.error("No crypto manager available");
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
                _sRedirectURL = sRedirectURL;
                
                String sDefaultAppLevel = oConfigurationManager.getParam(
                    eConfig, "app_level");
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
                    _logger.error("The configured default 'app_level' parameter isn't a number: " 
                        + sDefaultAppLevel, e);
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
                _logger.info("Configured default 'app_level': " + sDefaultAppLevel);
                
                _htASelectRequestorPools = 
                    new Hashtable<String, ASelectRequestorPool>();
                Element eRequestorPool = oConfigurationManager.getSection(
                    eConfig, "requestorpool");
                while (eRequestorPool != null)
                {
                    ASelectRequestorPool oASRequestorPool = 
                        new ASelectRequestorPool(oConfigurationManager, eRequestorPool);
                    
                    String sPoolId = oASRequestorPool.getID();
                    if (_htASelectRequestorPools.containsKey(sPoolId))
                    {
                        _logger.warn(
                            "The configured 'requestorpool' doesn't have a unique id: " 
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
                    eRequestorPool = oConfigurationManager.getNextSection(
                        eRequestorPool);
                }
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during object creation", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Verify if the object is enabled.
     * @return TRUE if this handler is enabled
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }
    
    /**
     * @see IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return ASelectProcessor.AUTHORITY_NAME;
    }
    
    /**
     * Process an asynchronous logout request revieved from a requestor.
     * 
     * @param oServletRequest HTTP servlet request object
     * @param oBinding The binding object
     * @param sRequestorID requestor id or NULL if app id supplied
     * @param sAppID app id or NULL if requestor id supplied 
     * @param credentials aselect_credentials
     * @throws ASelectException if request handling failed
     * @since 1.4
     */
    public void doRequestorSynchronousLogout(HttpServletRequest oServletRequest, 
        IBinding oBinding, String sRequestorID, String sAppID, String credentials) 
        throws ASelectException
    {
        AbstractEventLogItem oLogItem = null;
        try
        {
            if (sRequestorID == null && sAppID == null)
            {
                _logger.debug("No 'requestor' or 'app_id' found in request");
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            if (credentials == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_ASELECT_CREDENTIALS);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            IRequest oRequest = oBinding.getRequest();
                        
            if (sRequestorID == null)
                sRequestorID = sAppID;
                
            IRequestor oRequestor = _requestorPoolFactory.getRequestor(sRequestorID);
            if (oRequestor == null)
            {
                _logger.debug("Unknown 'requestor' or 'app_id' found in request: " + sRequestorID);
                throw new ASelectException(ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
            }
            
            String reason = (String)oRequest.getParameter(ASelectProcessor.PARAM_REASON);
            if (reason != null)
            {
                StringBuffer sbDebug = new StringBuffer("Received optional '");
                sbDebug.append(ASelectProcessor.PARAM_REASON);
                sbDebug.append("' in request from requestor: ");
                sbDebug.append(oRequestor.getID());
                _logger.debug(sbDebug.toString());
            }
                        
            IResponse oResponse = oBinding.getResponse();
            if (oResponse == null)
            {
                _logger.error("No response for request");
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
            }
            
            String sResultCode = ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR;
            try
            {
                if (!oRequestor.isEnabled())
                {
                    StringBuffer sbError = new StringBuffer("Disabled '");
                    sbError.append(ASelectProcessor.PARAM_LOCAL_IDP);
                    sbError.append("' found in request: ");
                    sbError.append(oRequestor.getID());
                    _logger.debug(sbError.toString());
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
                }
                
                RequestorPool oRequestorPool = 
                    _requestorPoolFactory.getRequestorPool(oRequestor.getID());
                if (oRequestorPool == null)
                {
                    _logger.warn("Requestor not available in a pool: " 
                        + oRequestor.getID());
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                }
                
                if (!oRequestorPool.isEnabled())
                {
                    StringBuffer sbError = new StringBuffer("Requestor '");
                    sbError.append(oRequestor.getID());
                    sbError.append("' is found in a disabled requestor pool: ");
                    sbError.append(oRequestorPool.getID());
                    _logger.warn(sbError.toString());
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                }
                
                ASelectRequestorPool oASRequestorPool = _htASelectRequestorPools.get(oRequestorPool.getID());
                if (doSigning(oRequestorPool, oASRequestorPool, oRequestor))
                {
                    String sSignature = (String)oRequest.getParameter(
                        ASelectProcessor.PARAM_SIGNATURE);
                    if (sSignature == null)
                    {
                        StringBuffer sbError = new StringBuffer("No '");
                        sbError.append(ASelectProcessor.PARAM_SIGNATURE);
                        sbError.append("' found in request");
                        _logger.debug(sbError.toString());
                        
                        throw new ASelectException(
                            ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                    }
                    
                    Hashtable<String,String> htSignatureData = new Hashtable<String,String>();
                    htSignatureData.put(ASelectProcessor.PARAM_ASELECT_CREDENTIALS, credentials);
                    if (sRequestorID != null)
                        htSignatureData.put(ASelectProcessor.PARAM_REQUESTORID, sRequestorID);
                    if (sAppID != null)
                        htSignatureData.put(ASelectProcessor.PARAM_APPID, sAppID);
                    if (reason != null)
                        htSignatureData.put(ASelectProcessor.PARAM_REASON, reason);
                    if (!verifySignature(sSignature, oRequestor.getID(), 
                        htSignatureData))
                    {
                        _logger.error(
                            "Invalid signature for request from requestor with id: " 
                            + oRequestor.getID());
                        throw new ASelectException(
                            ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                    }
                }
                
                if (reason != null && !ASelectProcessor.VALUE_REASON_TIMEOUT.equalsIgnoreCase(reason))
                {
                    _logger.debug(
                        "Invalid reason in request from SP with id: " 
                        + oRequestor.getID());
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                }
                
                RequestorEvent logoutResult = RequestorEvent.LOGOUT_FAILED;
                if (_aliasStoreSPRole == null)
                {
                    _logger.debug("TGT Factory has no alias support");
                    
                    sResultCode = ASelectErrors.ERROR_LOGOUT_FAILED;
                    logoutResult = RequestorEvent.LOGOUT_FAILED;
                }
                else
                {
                    sResultCode = ASelectErrors.ERROR_ASELECT_SUCCESS;
                    logoutResult = RequestorEvent.LOGOUT_SUCCESS;
                    
                    String sTGTID = _aliasStoreSPRole.getTGTID(
                        BrowserHandler.ALIAS_TYPE_CREDENTIALS, 
                        oRequestor.getID(), credentials);
                    if (sTGTID != null)
                    {
                        ITGT tgt = _tgtFactory.retrieve(sTGTID);
                        if (tgt != null && !tgt.isExpired())
                        {
                            //DD remove the credentials alias, so offline logout won't be triggered back to this requestor
                            _aliasStoreSPRole.removeAlias(
                                BrowserHandler.ALIAS_TYPE_CREDENTIALS, 
                                oRequestor.getID(), credentials);
                            
                            if (reason != null && tgt.getRequestorIDs().size() > 1)
                            {//DD If reason == timeout then do not expire the tgt
                                tgt.removeRequestorID(oRequestor.getID());
                                tgt.persist();
                                sResultCode = ASelectErrors.ERROR_LOGOUT_PARTIALLY;
                                logoutResult = RequestorEvent.LOGOUT_PARTIALLY;
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
                                    logoutResult = getLogoutResult(e.getErrors());
                                    switch (logoutResult)
                                    {
                                        case LOGOUT_PARTIALLY:
                                        {
                                            sResultCode = ASelectErrors.ERROR_LOGOUT_PARTIALLY;
                                            break;
                                        }
                                        case LOGOUT_FAILED:
                                        default:
                                        {
                                            sResultCode = ASelectErrors.ERROR_LOGOUT_FAILED;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                oLogItem = new RequestorEventLogItem(null, null, 
                    null, logoutResult, null, 
                    oServletRequest.getRemoteAddr(), null, this, 
                    "slogout SP role");
            }
            catch (ASelectException e)
            {
                sResultCode = e.getMessage();
                
                if (sResultCode.equals(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST))
                    throw e;

                oLogItem = new RequestorEventLogItem(null, null, null, 
                    RequestorEvent.REQUEST_INVALID, null, 
                    oServletRequest.getRemoteAddr(), 
                    oRequestor.getID(), this, "slogout SP role: " + sResultCode);
            }
            
            oResponse.setParameter(ASelectProcessor.PARAM_RESULT_CODE, 
                sResultCode);
            
            _eventLogger.info(oLogItem);
            
            oResponse.send();
        }
        catch (ASelectException e)
        {
            throw e;
        }
        catch (OAException e)
        {
            oLogItem = new RequestorEventLogItem(null, null, 
                null, RequestorEvent.REQUEST_INVALID, null, 
                oServletRequest.getRemoteAddr(), null, this, 
                "request=logout: " + e.getMessage());
            _eventLogger.info(oLogItem);
            
            throw new ASelectException(e.getMessage());
        }
        catch (Exception e)
        {
            oLogItem = new RequestorEventLogItem(null, null, 
                null, RequestorEvent.INTERNAL_ERROR, null, 
                oServletRequest.getRemoteAddr(), null, this, 
                "request=logout");
            _eventLogger.info(oLogItem);
            
            _logger.fatal("Internal error during 'logout' process", e);
            throw new ASelectException(
                ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
        }
    }
    
    
    /**
     * Process a synchronous logout request received from an organization.
     * 
     * @param oServletRequest HTTP servlet request object
     * @param oBinding The binding object
     * @param sLocalOrganization local_organization
     * @param credentials aselect_credentials
     * @throws ASelectException if request handling failed
     * @since 1.4
     */
    public void doOrganizationSynchronousLogout(HttpServletRequest oServletRequest, 
        IBinding oBinding, String sLocalOrganization, String credentials) 
        throws ASelectException
    {
        AbstractEventLogItem oLogItem = null;
        try
        {
            if (sLocalOrganization == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_LOCAL_IDP);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            if (credentials == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_ASELECT_CREDENTIALS);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            IRequest oRequest = oBinding.getRequest();
            
            IIDP idp = _idpStorageManager.getIDP(sLocalOrganization);
            if (idp == null)
            {
                _logger.debug("Unknown 'local_organization' found in request: " + sLocalOrganization);
                throw new ASelectException(ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
            }
            
            String reason = (String)oRequest.getParameter(ASelectProcessor.PARAM_REASON);
            if (reason != null)
            {
                StringBuffer sbDebug = new StringBuffer("Received optional '");
                sbDebug.append(ASelectProcessor.PARAM_REASON);
                sbDebug.append("' in request from idp: ");
                sbDebug.append(idp.getID());
                _logger.debug(sbDebug.toString());
            }
            
            ASelectIDP aselectIDP = null;
            if (idp instanceof ASelectIDP)  
            {
                aselectIDP = (ASelectIDP)idp;
            }
            else
            {
                _logger.debug("Supplied 'local_organization' is not of type ASelectIDP: " + idp.getID());
                throw new ASelectException(ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
            }
            
            IResponse oResponse = oBinding.getResponse();
            if (oResponse == null)
            {
                _logger.error("No response for request");
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
            }
            
            String sResultCode = ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR;
            try
            {
                if (aselectIDP.doSigning())
                {
                    String sSignature = (String)oRequest.getParameter(
                        ASelectProcessor.PARAM_SIGNATURE);
                    if (sSignature == null)
                    {
                        StringBuffer sbError = new StringBuffer("No '");
                        sbError.append(ASelectProcessor.PARAM_SIGNATURE);
                        sbError.append("' found in request");
                        _logger.debug(sbError.toString());
                        
                        throw new ASelectException(
                            ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                    }
                    
                    Hashtable<String,String> htSignatureData = new Hashtable<String,String>();
                    htSignatureData.put(ASelectProcessor.PARAM_ASELECT_CREDENTIALS, credentials);
                    if (sLocalOrganization != null)
                        htSignatureData.put(ASelectProcessor.PARAM_LOCAL_IDP, sLocalOrganization);
                    if (reason != null)
                        htSignatureData.put(ASelectProcessor.PARAM_REASON, reason);
                    if (!verifySignature(sSignature, idp.getID(), 
                        htSignatureData))
                    {
                        _logger.error(
                            "Invalid signature for request from IDP with id: " 
                            + idp.getID());
                        throw new ASelectException(
                            ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                    }
                }
                
                if (reason != null && !ASelectProcessor.VALUE_REASON_TIMEOUT.equalsIgnoreCase(reason))
                {
                    _logger.debug(
                        "Invalid reason in request from IDP with id: " 
                        + aselectIDP.getID());
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                }
                
                RequestorEvent logoutResult = RequestorEvent.LOGOUT_FAILED;
                if (_aliasStoreIDPRole == null)
                {
                    _logger.debug("TGT Factory has no alias support");
                    
                    sResultCode = ASelectErrors.ERROR_LOGOUT_FAILED;
                    logoutResult = RequestorEvent.LOGOUT_FAILED;
                }
                else
                {
                    sResultCode = ASelectErrors.ERROR_ASELECT_SUCCESS;
                    logoutResult = RequestorEvent.LOGOUT_SUCCESS;
                    
                    String sTGTID = _aliasStoreIDPRole.getTGTID(
                        BrowserHandler.ALIAS_TYPE_CREDENTIALS, 
                        aselectIDP.getID(), credentials);
                    if (sTGTID != null)
                    {
                        ITGT tgt = _tgtFactory.retrieve(sTGTID);
                        if (tgt != null && !tgt.isExpired())
                        {
                            _aliasStoreIDPRole.removeAlias(
                                BrowserHandler.ALIAS_TYPE_CREDENTIALS, 
                                aselectIDP.getID(), credentials);
                            
                            if (reason != null)
                            {//DD If reason == timeout then do not expire the tgt
                                sResultCode = ASelectErrors.ERROR_LOGOUT_PARTIALLY;
                                logoutResult = RequestorEvent.LOGOUT_PARTIALLY;
                            }
                            else
                            {
                                tgt.expire();
                                
                                try
                                {
                                    tgt.persist();
                                }
                                catch (TGTListenerException e)
                                {
                                    logoutResult = getLogoutResult(e.getErrors());
                                    switch (logoutResult)
                                    {
                                        case LOGOUT_PARTIALLY:
                                        {
                                            sResultCode = ASelectErrors.ERROR_LOGOUT_PARTIALLY;
                                            break;
                                        }
                                        case LOGOUT_FAILED:
                                        default:
                                        {
                                            sResultCode = ASelectErrors.ERROR_LOGOUT_FAILED;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                oLogItem = new RequestorEventLogItem(null, null, 
                    null, logoutResult, null, 
                    oServletRequest.getRemoteAddr(), null, this, 
                    "slogout IDP role");
            }
            catch (ASelectException e)
            {
                sResultCode = e.getMessage();
                
                if (sResultCode.equals(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST))
                    throw e;

                oLogItem = new RequestorEventLogItem(null, null, null, 
                    RequestorEvent.REQUEST_INVALID, null, 
                    oServletRequest.getRemoteAddr(), aselectIDP.getID(), this, 
                    "slogout IDP role: " + sResultCode);
            }
            
            oResponse.setParameter(ASelectProcessor.PARAM_RESULT_CODE, 
                sResultCode);
            
            _eventLogger.info(oLogItem);
            
            oResponse.send();
        }
        catch (ASelectException e)
        {
            throw e;
        }
        catch (OAException e)
        {
            oLogItem = new RequestorEventLogItem(null, null, 
                null, RequestorEvent.REQUEST_INVALID, null, 
                oServletRequest.getRemoteAddr(), null, this, 
                "request=logout: " + e.getMessage());
            _eventLogger.info(oLogItem);
            
            throw new ASelectException(e.getMessage());
        }
        catch (Exception e)
        {
            oLogItem = new RequestorEventLogItem(null, null, 
                null, RequestorEvent.INTERNAL_ERROR, null, 
                oServletRequest.getRemoteAddr(), null, this, 
                "request=logout");
            _eventLogger.info(oLogItem);
            
            _logger.fatal("Internal error during 'logout' process", e);
            throw new ASelectException(
                ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
        }
    }

    /**
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
    protected String serializeAttributes(IAttributes oAttributes)
        throws ASelectException
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
            throw new ASelectException(
                ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
        }

        return sReturn;
    }

    /**
     * Verifies signatures for requests and the signed parameters are supplied as map.
     * @param sSignature the signature that must be verified
     * @param sKeyAlias the key alias
     * @param mapRequest the data that is signed
     * @return TRUE if the signature is valid
     * @throws ASelectException if verification failed
     */
    protected boolean verifySignature(String sSignature, String sKeyAlias, 
        Map<String, String> mapRequest) throws ASelectException
    {
        StringBuffer sbSignatureData = new StringBuffer();
        TreeSet<String> sortedSet = new TreeSet<String>(mapRequest.keySet());
        for (Iterator<String> iter = sortedSet.iterator(); iter.hasNext();)
        {
            String sKey = iter.next();
            sbSignatureData.append(mapRequest.get(sKey));
        }
        
        return verifySignature(sSignature, sKeyAlias, sbSignatureData.toString());
    }
    

    /**
     * Verifies signatures for requests retrieved from a requestor.
     * @param sSignature the signature that must be verified
     * @param sKeyAlias the key alias
     * @param sData the signed data
     * @return TRUE if the signature is valid
     * @throws ASelectException if verification failed
     */
    protected boolean verifySignature(String sSignature, String sKeyAlias,
        String sData) throws ASelectException
    {
        try
        {
            Certificate oCertificate = _cryptoManager
                .getCertificate(sKeyAlias);
            if (oCertificate == null)
            {
                _logger.warn("No certificate object found with alias: "
                    + sKeyAlias);
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
            }

            Signature oSignature = _cryptoManager.getSignature();
            if (oSignature == null)
            {
                _logger.warn("No signature object found");
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
            }

            oSignature.initVerify(oCertificate);
            oSignature.update(sData.getBytes(ASelectProcessor.CHARSET));
            
            byte[] baData = Base64.decodeBase64(sSignature
                .getBytes(ASelectProcessor.CHARSET));
            boolean bVerified = oSignature.verify(baData);
            if (!bVerified)
            {
                StringBuffer sbDebug = new StringBuffer(
                    "Could not verify signature '");
                sbDebug.append(sSignature);
                sbDebug.append("' for key with alias '");
                sbDebug.append(sKeyAlias);
                sbDebug.append("' with data: ");
                sbDebug.append(sData);
                _logger.debug(sbDebug.toString());
            }
            return bVerified;
        }
        catch (CryptoException e)
        {
            _logger.warn("A crypto exception occurred", e);
            throw new ASelectException(e.getMessage());
        }
        catch (ASelectException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer(
                "Could not verify signature '");
            sbError.append(sSignature);
            sbError.append("' for key with alias: ");
            sbError.append(sKeyAlias);
            _logger.fatal(sbError.toString(), e);
            throw new ASelectException(
                ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
        }
    }
    
    /**
     * Returns the authN profile id with the highest authsp_level value.
     *
     * @param listAuthNProfileIDs a list with authN profile id's
     * @return authN profile id
     * @throws OAException if authsp_level could not be resolved from model
     */
    protected String getHighestAuthNProfile(List<String> listAuthNProfileIDs) 
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
                    authnProfile = _authnProfileFactory.getProfile(sAuthNProfileID);
                }
                catch (AuthenticationException e)
                {
                    _logger.error("Authentication profile not available: " + sAuthNProfileID);
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                
                String sLevel = (String)authnProfile.getProperty(_sProfileID + PROPERTY_AUTHSP_LEVEL);
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
                        sbError.append(_sProfileID);
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
    
    /**
     * Resolves the authsp_level for the specified authentication profile.
     * 
     * @param sAuthNProfileID The profile id for which the authsp_level should be resolved
     * @return The authsp_level
     * @throws OAException if authsp_level could not be resolved from model
     * @since 1.1
     */
    protected Integer getAuthSPLevel(String sAuthNProfileID) throws OAException
    {
        Integer intAuthSPLevel = _iDefaultAuthSPLevel; 
        if (_htAuthSPLevels.containsKey(sAuthNProfileID))
            intAuthSPLevel = _htAuthSPLevels.get(sAuthNProfileID);
        else
        {
            AuthenticationProfile authnProfile = null;
            try
            {
                authnProfile = _authnProfileFactory.getProfile(sAuthNProfileID);
            }
            catch (AuthenticationException e)
            {
                _logger.error("Authentication profile not available: " + sAuthNProfileID);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            String sLevel = (String)authnProfile.getProperty(_sProfileID + PROPERTY_AUTHSP_LEVEL);
            if (sLevel != null)
            {
                try
                {
                    intAuthSPLevel = new Integer(sLevel);
                }
                catch (NumberFormatException e)
                {
                    StringBuffer sbError = new StringBuffer("Invalid value of the '");
                    sbError.append(_sProfileID);
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
    
    /**
     * Resolves the value for the uid parameter of the A-Select protocol.
     * 
     * @param oUser The User object
     * @param oASRequestorPool Requestor Pool object or <code>null</code>
     * @param oRequestorPool OA Requestorpool
     * @param oRequestor OA Requestor
     * @return the resolved uid value
     * @throws ASelectException if no uid can be resolved
     * @throws OAException if conversion to hexadecimal fails
     */
    protected String getUid(IUser oUser, ASelectRequestorPool oASRequestorPool, 
        RequestorPool oRequestorPool, IRequestor oRequestor) 
        throws ASelectException, OAException
    {
        String sUid = oUser.getID();
        
        String sUidAttribute = (String)oRequestor.getProperty(_sProfileID + PROPERTY_UID_ATTRIBUTE);
        if (sUidAttribute == null)
        {
            if (oASRequestorPool != null)
                sUidAttribute = oASRequestorPool.getUidAttribute();
            
            if (sUidAttribute == null)
                sUidAttribute = (String)oRequestorPool.getProperty(_sProfileID + PROPERTY_UID_ATTRIBUTE);
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
                throw new ASelectException(
                    ASelectErrors.ERROR_MISSING_REQUIRED_ATTRIBUTE);
            }
            //DD Remove the used attribute from the user attributes, so it will not be released to the application
            oAttributes.remove(sUidAttribute);
        }
        
        boolean bOpaqueUID = false;
        
        String sUIDOpaque = (String)oRequestor.getProperty(_sProfileID + PROPERTY_UID_OPAQUE_ENABLED);
        if (sUIDOpaque != null)
        {
            if ("TRUE".equalsIgnoreCase(sUIDOpaque))
                bOpaqueUID = true;
            else if (!"FALSE".equalsIgnoreCase(sUIDOpaque))
            {
                StringBuffer sbError = new StringBuffer("Invalid value for requestor property '");
                sbError.append(_sProfileID);
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
                sUIDOpaque = (String)oRequestorPool.getProperty(_sProfileID + PROPERTY_UID_OPAQUE_ENABLED);
                if (sUIDOpaque != null)
                {
                    if ("TRUE".equalsIgnoreCase(sUIDOpaque))
                        bOpaqueUID = true;
                    else if (!"FALSE".equalsIgnoreCase(sUIDOpaque))
                    {
                        StringBuffer sbError = new StringBuffer("Invalid value for requestorpool property '");
                        sbError.append(_sProfileID);
                        sbError.append(PROPERTY_UID_OPAQUE_ENABLED);
                        sbError.append("': ");
                        sbError.append(sUIDOpaque);
                        
                        _logger.error(sbError.toString());
                        throw new OAException(SystemErrors.ERROR_INTERNAL);
                    }
                }
            }
        }
        
        if (bOpaqueUID)
        {
            String sSalt = (String)oRequestor.getProperty(_sProfileID + PROPERTY_UID_OPAQUE_SALT);
            if (sSalt == null)
            {
                if (oASRequestorPool != null)
                    sSalt = oASRequestorPool.getUidOpaqueSalt();
                if (sSalt == null)
                    sSalt = (String)oRequestorPool.getProperty(_sProfileID + PROPERTY_UID_OPAQUE_SALT);
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
                    + sUid, e);
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
    protected String getAppLevel(RequestorPool oRequestorPool, 
        ASelectRequestorPool oASRequestorPool, IRequestor oRequestor) throws OAException
    {
        String sAppLevel = String.valueOf(_iDefaultAppLevel);
        
        int iAppLevel = -1;
        
        String appLevel = (String)oRequestor.getProperty(_sProfileID + PROPERTY_APP_LEVEL);
        if (appLevel != null)
        {
            try
            {
                iAppLevel = Integer.valueOf(appLevel);
            }
            catch (NumberFormatException e)
            {
                StringBuffer sbError = new StringBuffer("The configured requestor property (");
                sbError.append(_sProfileID);
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
                appLevel = (String)oRequestorPool.getProperty(_sProfileID + PROPERTY_APP_LEVEL);
                if (appLevel != null)
                {
                    try
                    {
                        iAppLevel = Integer.valueOf(appLevel);
                    }
                    catch (NumberFormatException e)
                    {
                        StringBuffer sbError = new StringBuffer("The configured requestorpool property (");
                        sbError.append(_sProfileID);
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
     * Returns TRUE if requests must be signed.
     * 
     * Resolves signing value from ASelectRequestorPool or RequestorPool.
     * @param oRequestorPool OA Requestor pool
     * @param oASRequestorPool A-Select Requestor pool
     * @param oRequestor OA Requestor
     * @return true if requests must be signed
     * @throws OAException
     * @since 1.1
     */
    protected boolean doSigning(RequestorPool oRequestorPool, 
        ASelectRequestorPool oASRequestorPool, IRequestor oRequestor) 
        throws OAException
    {
        String sEnabled = (String)oRequestor.getProperty(_sProfileID + PROPERTY_SIGN_REQUESTS);
        if (sEnabled != null)
        {
            if ("TRUE".equalsIgnoreCase(sEnabled))
                return true;
            else if (!"FALSE".equalsIgnoreCase(sEnabled))
            {
                StringBuffer sbError = new StringBuffer("The configured requestor property (");
                sbError.append(_sProfileID);
                sbError.append(PROPERTY_SIGN_REQUESTS);
                sbError.append(") value isn't a boolean: ");
                sbError.append(sEnabled);
                _logger.error(sbError.toString());
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        
        if (oASRequestorPool != null && oASRequestorPool.doSigning())
            return true;
        
        sEnabled = (String)oRequestorPool.getProperty(_sProfileID + PROPERTY_SIGN_REQUESTS);
        if (sEnabled != null)
        {
            if ("TRUE".equalsIgnoreCase(sEnabled))
                return true;
            else if (!"FALSE".equalsIgnoreCase(sEnabled))
            {
                StringBuffer sbError = new StringBuffer("The configured requestorpool property (");
                sbError.append(_sProfileID);
                sbError.append(PROPERTY_SIGN_REQUESTS);
                sbError.append(") value isn't a boolean: ");
                sbError.append(sEnabled);
                _logger.error(sbError.toString());
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        
        return false;
    }
    
    /**
     * Returns the logout result as requestor event.
     *
     * @param listErrors containing all TGT event errors to be verified
     * @return the resulting logout requestor event
     * @since 1.4
     */
    private RequestorEvent getLogoutResult(List<TGTEventError> listErrors)
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

    /**
     * Hexstring encoding.
     * 
     * Outputs a hex-string representation of a byte array.
     * This method returns the hexadecimal String representation of a byte
     * array. 
     * 
     * Example: 
     * For input <code>[0x13, 0x2f, 0x98, 0x76]</code>, this method returns a
     * String object containing <code>"132F9876"</code>.
     * 
     * DD For backwards compatibly the hex presentation is converted to upper case.
     * @param baBytes Source byte array.
     * @return a String object representing <code>baBytes</code> in hexadecimal 
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