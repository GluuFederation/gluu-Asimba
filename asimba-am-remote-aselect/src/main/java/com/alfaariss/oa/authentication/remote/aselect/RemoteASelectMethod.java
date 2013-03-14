/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authentication.remote.aselect;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.authentication.IAuthenticationProfile;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.api.sso.logout.IASLogout;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.authentication.remote.AbstractRemoteMethod;
import com.alfaariss.oa.authentication.remote.aselect.idp.storage.ASelectIDP;
import com.alfaariss.oa.authentication.remote.aselect.logout.LogoutManager;
import com.alfaariss.oa.authentication.remote.aselect.selector.ISelector;
import com.alfaariss.oa.engine.core.attribute.AttributeException;
import com.alfaariss.oa.engine.core.attribute.UserAttributes;
import com.alfaariss.oa.engine.core.authentication.AuthenticationProfile;
import com.alfaariss.oa.engine.core.authentication.factory.IAuthenticationProfileFactory;
import com.alfaariss.oa.engine.core.idp.IDPStorageManager;
import com.alfaariss.oa.engine.core.idp.storage.IIDPStorage;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.sso.authentication.web.IWebAuthenticationMethod;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.session.ProxyAttributes;

/**
 * Remote A-Select Authentication Method.
 *
 * Performs an authentication with a remote A-Select Organization (Cross A-Select). 
 * If more A-Select Servers are configured, a selection screen will be shown.
 * 
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class RemoteASelectMethod extends AbstractRemoteMethod implements IASLogout
{
    /** aslogout_organization */
    public final static String TGT_LOGOUT_ORGANIZATION = "aslogout_organization";//contains a ASelectOrganization object
    
    private final static String AUTHORITY_NAME = "RemoteASelectMethod_";
    private final static String SESSION_SELECTED_ORGANIZATION = "organization";//contains a ASelectOrganization object
    private final static String SESSION_AVAILABLE_ORGANIZATIONS = "available_organizations";
    private final static String SESSION_PROXY_REQUIRED_LEVEL = "required_level";
    private final static String SESSION_LOGOUT_ORGANIZATION = "aslogout_organization";//contains a ASelectOrganization object
    private final static String SESSION_PROXY_ARP_TARGET = "arp_target";
    
    private final static String SINGLE_LOGOUT = "slo";
    private final static String AUTHENTICATE = "authenticate";
    private final static String VERIFY_CREDENTIALS = "verify_credentials";
    private final static String ERROR_ASELECT_SUCCESS = "0000";
    private static final String ERROR_ASELECT_SERVER_UNKNOWN_TGT = "0007";
    private final static String ERROR_ASELECT_CANCEL = "0040";
    
    private final static String PARAM_REQUEST = "request";
    private final static String PARAM_RID = "rid";
    private final static String PARAM_FORCED = "forced_logon";
    private final static String PARAM_LOCAL_AS_URL = "local_as_url";
    private final static String PARAM_LOCAL_ORG = "local_organization";
    private final static String PARAM_ASELECTSERVER = "a-select-server";
    private final static String PARAM_UID = "uid";
    private final static String PARAM_COUNTRY = "country";
    private final static String PARAM_LANGUAGE = "language";
    private final static String PARAM_RESULTCODE = "result_code";
    private final static String PARAM_AS_URL = "as_url";
    private final static String PARAM_ASELECTCREDENTIALS = "aselect_credentials";
    private final static String PARAM_ORGANIZATION = "organization";
    private final static String PARAM_AUTHSP_LEVEL = "authsp_level";
    private final static String PARAM_AUTHSP = "authsp";
    private final static String PARAM_APP_LEVEL = "app_level";
    private final static String PARAM_TGT_EXP_TIME = "tgt_exp_time";
    private final static String PARAM_ATTRIBUTES = "attributes";
    private final static String PARAM_SIGNATURE = "signature";
    private final static String PARAM_REMOTE_ORGANIZATION = "remote_organization";
    private final static String PARAM_REQUIRED_LEVEL = "required_level";
    private final static String PARAM_ARP_TARGET = "arp_target";
    
    private IAuthenticationProfileFactory _authNProfileFactory;
    private String _sMyOrganization;
    private ISelector _oSelector;
    private boolean _bFallback;
    private Hashtable<String, String> _htAttributeMapper;
    private IIDPStorage _idpStorage;
    private LogoutManager _logoutManager;
    private ITGTAliasStore _aliasStoreIDPRole;
    private String _sForceAuthNProfile;
    
    /**
     * Constructor.
     */
    public RemoteASelectMethod()
    {
        _logger = LogFactory.getLog(RemoteASelectMethod.class);
        _htAttributeMapper = new Hashtable<String, String>();
        _bFallback = false;
        _logoutManager = null;
        _sForceAuthNProfile = null;
    }
    
    /**
     * @see AbstractRemoteMethod#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws OAException 
    {
        try
        {
            super.start(oConfigurationManager, eConfig);
            
            _authNProfileFactory = _engine.getAuthenticationProfileFactory();
            
            Element eSelector = _configurationManager.getSection(eConfig, "selector");
            if (eSelector == null)
            {
                _logger.info("No optional 'selector' section found in configuration");
            }
            else
            {
                String sSelectorClass = _configurationManager.getParam(eSelector, "class");
                if (sSelectorClass == null)
                {
                    _logger.error("No 'class' item in 'selector' section found");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                try
                {
                    _oSelector = (ISelector)Class.forName(sSelectorClass).newInstance();
                }
                catch (InstantiationException e)
                {
                    _logger.error("Can't create an instance of the configured class: " + sSelectorClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ, e);
                }
                catch (IllegalAccessException e)
                {
                    _logger.error("Configured class can't be accessed: " + sSelectorClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ, e);
                }
                catch (ClassNotFoundException e)
                {
                    _logger.error("Configured class doesn't exist: " + sSelectorClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ, e);
                }
                catch (ClassCastException e)
                {
                    _logger.error("Configured class isn't of type 'ISelector': " + sSelectorClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ, e);
                }
                
                _oSelector.start(_configurationManager, eSelector);
            }
            
            Element eOrganizations = _configurationManager.getSection(eConfig, "idps");
            if (eOrganizations == null)
            {
                _logger.error("No 'idps' section found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _bFallback = false;
            String sFallback = _configurationManager.getParam(eOrganizations, "fallback");
            if (sFallback != null)
            {
                if (sFallback.equalsIgnoreCase("TRUE"))
                    _bFallback = true;
                else if(!sFallback.equalsIgnoreCase("FALSE"))
                {
                    _logger.error("Invalid 'fallback' item found in 'idps' section in configuration: " + sFallback);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            _idpStorage = createStorage(eOrganizations);
            _idpStorage.start(oConfigurationManager, eOrganizations);
            IDPStorageManager idpStorageManager = _engine.getIDPStorageManager();
            if (idpStorageManager.existStorage(_idpStorage.getID()))
            {
                _logger.error("Storage not unique: " + _idpStorage.getID());
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            idpStorageManager.addStorage(_idpStorage);
            
            _sMyOrganization = _engine.getServer().getOrganization().getID();
            
            Element eMapper = oConfigurationManager.getSection(eConfig, "attributemapper");
            if (eMapper == null)
                _logger.info("No optional 'attributemapper' section found in configuration");
            else
            {
                Element eMap = oConfigurationManager.getSection(eMapper, "map");
                while (eMap != null)
                {
                    String sExt = oConfigurationManager.getParam(eMap, "ext");
                    if (sExt == null)
                    {
                        _logger.error("No 'ext' item found in 'map' section");
                        throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    String sInt = oConfigurationManager.getParam(eMap, "int");
                    if (sInt == null)
                    {
                        _logger.error("No 'int' item found in 'map' section");
                        throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    if (_htAttributeMapper.containsKey(sExt))
                    {
                        _logger.error("Ext name not unique in map with 'ext' value: " + sExt);
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    if (_htAttributeMapper.contains(sInt))
                    {
                        _logger.error("Int name not unique in map with 'int' value: " + sInt);
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    _htAttributeMapper.put(sExt, sInt);
                    
                    eMap = oConfigurationManager.getNextSection(eMap);
                }
            }
            
            _aliasStoreIDPRole = null;
            
            _logoutManager = new LogoutManager(oConfigurationManager, eConfig, _idpStorage, _sMethodId);
            if (_logoutManager.isEnabled())
            {
                _aliasStoreIDPRole = _engine.getTGTFactory().getAliasStoreIDP();
                if (_aliasStoreIDPRole == null)
                {
                    _logger.error("No IDP Role TGT Alias Store available");
                    throw new OAException(SystemErrors.ERROR_INIT); 
                }
                
                _engine.getTGTFactory().addListener(_logoutManager);
            }
            
            Element eReplay = _configurationManager.getSection(eConfig, "replay");
            if (eReplay != null)
            {
                readReplay(eReplay);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during start", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }   
    }

    /**
     * @see com.alfaariss.oa.authentication.remote.AbstractRemoteMethod#stop()
     */
    public void stop() 
    {
        super.stop();
        _oSelector = null;
        
        if (_htAttributeMapper != null)
            _htAttributeMapper.clear();
        
        if (_idpStorage != null)
        {
            _engine.getIDPStorageManager().removeStorage(_idpStorage.getID());
            _idpStorage.stop();
        }
        
        if (_logoutManager != null)
        {
            try
            {
                _engine.getTGTFactory().removeListener(_logoutManager);
            }
            catch (OAException e)
            {
                _logger.warn("Could not remove TGT listener (Logout manager)", e);
            }
        }
	}

    /**
     * @see IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return AUTHORITY_NAME + _sMethodId;
    }
    
    /**
     * @see IWebAuthenticationMethod#authenticate(
     *  javax.servlet.http.HttpServletRequest, 
     *  javax.servlet.http.HttpServletResponse, ISession)
     */
    @SuppressWarnings("unchecked")//because attributes object removes typing of List 
    public UserEvent authenticate(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession) throws OAException
    {
        //retrieve initial set with organzations
        ISessionAttributes oAttributes = oSession.getAttributes();
        List<ASelectIDP> listAvailableOrganizations = 
            (List)oAttributes.get(RemoteASelectMethod.class, 
                _sMethodId+SESSION_AVAILABLE_ORGANIZATIONS);         
        if (listAvailableOrganizations == null)
        {           
            listAvailableOrganizations = new Vector<ASelectIDP>();
            listAvailableOrganizations.addAll(_idpStorage.getAll());
        }
        
        if (oRequest.getParameter(PARAM_ASELECTCREDENTIALS) == null 
            && oAttributes.contains(RemoteASelectMethod.class, _sMethodId+SESSION_SELECTED_ORGANIZATION))
        {
            oAttributes.remove(RemoteASelectMethod.class, _sMethodId+SESSION_SELECTED_ORGANIZATION);
            _logger.debug("User returned from organization by using browser back button");
            
            if (performReplay(oSession, oAttributes))
                return UserEvent.AUTHN_METHOD_IN_PROGRESS;
        }
        
        //Authenticate
        return authenticate(oRequest, oResponse, oSession, 
            oAttributes, listAvailableOrganizations, new Vector<Warnings>());
    }
    
    /**
     * @see com.alfaariss.oa.api.sso.logout.IASLogout#canLogout(com.alfaariss.oa.api.tgt.ITGT)
     */
    public boolean canLogout(ITGT tgt) throws OAException
    {
        if (tgt == null)
        {
            _logger.error("No TGT supplied");
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        IUser user = tgt.getUser();
        if (user == null)
        {
            _logger.error("No user available in TGT");
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        ASelectIDP org = (ASelectIDP)_idpStorage.getIDP(user.getOrganization());
        if (org != null && org.hasASynchronousLogout())
        {//also verify if there are aselect_credentials available.
            String sASelectCredentials = _aliasStoreIDPRole.getAlias(LogoutManager.ALIAS_TYPE_CREDENTIALS, org.getID(), tgt.getId());
            return (sASelectCredentials != null);
        }
        
        return false;
    }

    /**
     * @see com.alfaariss.oa.api.sso.logout.IASLogout#logout(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, com.alfaariss.oa.api.tgt.ITGT, com.alfaariss.oa.api.session.ISession)
     */
    public UserEvent logout(HttpServletRequest request,
        HttpServletResponse response, ITGT tgt, ISession session) throws OAException
    {
        try
        {
            if (tgt == null)
            {
                _logger.error("No TGT supplied");
                _eventLogger.info(new UserEventLogItem(session, 
                    request.getRemoteAddr(), UserEvent.INTERNAL_ERROR, this, 
                    "no tgt"));
                return UserEvent.INTERNAL_ERROR;
            }
            
            IUser user = tgt.getUser();
            if (user == null)
            {
                _logger.error("No user available in TGT");
                _eventLogger.info(new UserEventLogItem(session, 
                    request.getRemoteAddr(), UserEvent.INTERNAL_ERROR, this, 
                    "invalid tgt"));
                return UserEvent.INTERNAL_ERROR;
            }
            
            ISessionAttributes sessionAttributes = session.getAttributes();
            ASelectIDP oASelectIDP = null;
            if (sessionAttributes.contains(RemoteASelectMethod.class, _sMethodId+SESSION_LOGOUT_ORGANIZATION))
            {
                oASelectIDP = 
                    (ASelectIDP)sessionAttributes.get(RemoteASelectMethod.class, 
                        _sMethodId+SESSION_LOGOUT_ORGANIZATION);
                
                if (!oASelectIDP.getID().equals(user.getOrganization()))
                {
                    StringBuffer sbDebug = new StringBuffer("Session invalid; User was logging out at '");
                    sbDebug.append(oASelectIDP.getID());
                    sbDebug.append("' instead of: ");
                    sbDebug.append(user.getOrganization());
                    _logger.debug(sbDebug.toString());
                    
                    _eventLogger.info(new UserEventLogItem(session, 
                        request.getRemoteAddr(), UserEvent.USER_LOGOUT_FAILED, this, 
                        "invalid organization"));
                    
                    return UserEvent.USER_LOGOUT_FAILED;
                }
                
                return logoutFinished(oASelectIDP, tgt, session, request);
            }
            
            oASelectIDP = (ASelectIDP)_idpStorage.getIDP(user.getOrganization());
            if (oASelectIDP == null)
            {
                _logger.warn("Organization unknown: " + user.getOrganization());
                
                _eventLogger.info(new UserEventLogItem(session, 
                    request.getRemoteAddr(), UserEvent.USER_LOGOUT_FAILED, this, 
                    "unknown organization: " + user.getOrganization()));
                
                return UserEvent.USER_LOGOUT_FAILED;
            }
            
            sessionAttributes.put(RemoteASelectMethod.class, 
                _sMethodId+SESSION_LOGOUT_ORGANIZATION, oASelectIDP);
            
            String sASelectCredentials = _aliasStoreIDPRole.getAlias(
                LogoutManager.ALIAS_TYPE_CREDENTIALS, oASelectIDP.getID(), tgt.getId());
            
            return performLogout(request, response, session, oASelectIDP, 
                sASelectCredentials, tgt);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error when performing asynchronous logout", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private UserEvent performLogout(HttpServletRequest request,
        HttpServletResponse response, ISession session, 
        ASelectIDP oASelectIDP, String sASelectCredentials, ITGT tgt) throws OAException
    {
        Hashtable<String, String> htRequest = new Hashtable<String, String>();
        try
        {
            StringBuffer sbMyURL = new StringBuffer();
                sbMyURL.append(request.getRequestURL().toString());
                sbMyURL.append("?").append(ISession.ID_NAME);
                sbMyURL.append("=").append(URLEncoder.encode(session.getId(), CHARSET));
            
            htRequest.put(PARAM_LOCAL_AS_URL, sbMyURL.toString());
            htRequest.put(PARAM_LOCAL_ORG, _sMyOrganization);
            htRequest.put(PARAM_ASELECTSERVER, oASelectIDP.getServerID());
            htRequest.put(PARAM_ASELECTCREDENTIALS, sASelectCredentials);
            
            if (oASelectIDP.doSigning())
            {
                String sSignature = createSignature(htRequest);
                htRequest.put(PARAM_SIGNATURE, sSignature);
            }
            
            htRequest.put(PARAM_REQUEST, SINGLE_LOGOUT);//not part of signature
                
            Hashtable<String, String> htResponse = null;
            
            try
            {
                htResponse = sendRequest(oASelectIDP.getURL(), htRequest);
            }
            catch (IOException e)
            {
                _logger.debug("Could not send single logout request to: " + 
                    oASelectIDP.getURL(), e);
                
                _eventLogger.info(new UserEventLogItem(session, 
                    request.getRemoteAddr(), UserEvent.USER_LOGOUT_FAILED, this, 
                    "No logout response from: " + oASelectIDP.getID()));
                
                return UserEvent.USER_LOGOUT_FAILED;
            }
            
            String sResultCode = htResponse.get(PARAM_RESULTCODE);
            if (sResultCode == null)
            {
                StringBuffer sbError = new StringBuffer("Required parameter (");
                sbError.append(PARAM_RESULTCODE);
                sbError.append(") not found in request=logout response (");
                sbError.append(htResponse);
                sbError.append(") from A-Select Organization: ");
                sbError.append(oASelectIDP.getServerID());
                _logger.warn(sbError.toString());
                _eventLogger.info(new UserEventLogItem(session, 
                    request.getRemoteAddr(), UserEvent.USER_LOGOUT_FAILED, this, 
                    "Invalid logout response"));
                return UserEvent.USER_LOGOUT_FAILED;
            }
                        
            if (!ERROR_ASELECT_SUCCESS.equals(sResultCode))
            {
                if (sResultCode.equals(ERROR_ASELECT_SERVER_UNKNOWN_TGT))
                {
                    _logger.debug("Credentials are unkown at the remote server, server returned result code: " 
                        + sResultCode);
                    
                    return logoutFinished(oASelectIDP, tgt, session, request);
                }
                
                StringBuffer sbError = new StringBuffer("Response parameter (");
                sbError.append(PARAM_RESULTCODE);
                sbError.append(") from A-Select Organization '");
                sbError.append(oASelectIDP.getServerID());
                sbError.append("' contains error code: ");
                sbError.append(sResultCode);
                _logger.warn(sbError.toString());
                _eventLogger.info(new UserEventLogItem(session, 
                    request.getRemoteAddr(), UserEvent.USER_LOGOUT_FAILED, 
                    this, sResultCode));                
               
                return UserEvent.USER_LOGOUT_FAILED;
            }
            String sRemoteRid = htResponse.get(PARAM_RID);
            if (sRemoteRid == null)
            {
                StringBuffer sbError = new StringBuffer("Required parameter (");
                sbError.append(PARAM_RID);
                sbError.append(") not found in request=logout response (");
                sbError.append(htResponse);
                sbError.append(") from A-Select Organization: ");
                sbError.append(oASelectIDP.getServerID());
                _logger.warn(sbError.toString());                
                _eventLogger.info(new UserEventLogItem(session, 
                    request.getRemoteAddr(), UserEvent.USER_LOGOUT_FAILED, 
                    this, "Invalid logout response"));                
                return UserEvent.USER_LOGOUT_FAILED;
            }
            String sRemoteUrl = htResponse.get(PARAM_AS_URL);
            if (sRemoteUrl == null)
            {
                StringBuffer sbError = new StringBuffer("Required parameter (");
                sbError.append(PARAM_AS_URL);
                sbError.append(") not found in request=logout response (");
                sbError.append(htResponse);
                sbError.append(") from A-Select Organization: ");
                sbError.append(oASelectIDP.getServerID());
                _logger.warn(sbError.toString());
                _eventLogger.info(new UserEventLogItem(session, 
                    request.getRemoteAddr(), UserEvent.USER_LOGOUT_FAILED, this, 
                    "Invalid logout response"));
                return UserEvent.USER_LOGOUT_FAILED;
            }
            
            StringBuffer sbRedirect = new StringBuffer(sRemoteUrl);
            sbRedirect.append("&").append(PARAM_RID);
            sbRedirect.append("=").append(sRemoteRid);
            sbRedirect.append("&").append(PARAM_ASELECTSERVER);
            sbRedirect.append("=").append(oASelectIDP.getServerID());
            
            _eventLogger.info(new UserEventLogItem(session, 
                request.getRemoteAddr(), UserEvent.USER_LOGOUT_IN_PROGRESS, 
                this, "Redirect user with request=logout"));
            
            session.persist();
            
            _logger.debug("Redirecting user to: " + sbRedirect.toString());
            try
            {
                response.sendRedirect(sbRedirect.toString());
            }
            catch (IOException e)
            {
                _logger.debug("Could not send logout request to: " + 
                    sbRedirect.toString(), e);
                return UserEvent.USER_LOGOUT_FAILED;
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during logout initiation", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return UserEvent.USER_LOGOUT_IN_PROGRESS;
    }
    
    private UserEvent logoutFinished(ASelectIDP oASelectIDP, ITGT tgt, 
        ISession session, HttpServletRequest request) throws OAException
    {
        _eventLogger.info(new UserEventLogItem(session, 
            request.getRemoteAddr(), UserEvent.USER_LOGGED_OUT, this, 
            oASelectIDP.getID()));
        
        tgt.getAttributes().put(RemoteASelectMethod.class, 
            _sMethodId+TGT_LOGOUT_ORGANIZATION, oASelectIDP);
        tgt.persist();
        
        _logger.debug("Logout finished at: " + oASelectIDP.getID());
        return UserEvent.USER_LOGGED_OUT;
    }
    
    private IIDPStorage createStorage(Element config) throws OAException
    {
        IIDPStorage storage = null;
        try
        {
            String sClass = _configurationManager.getParam(config, "class");
            if (sClass == null)
            {
                _logger.error("No 'class' item found in 'idps' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Class oClass = null;
            try
            {
                oClass = Class.forName(sClass);
            }
            catch (Exception e)
            {
                _logger.error("No 'class' found with name: " + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            try
            {
                storage = (IIDPStorage)oClass.newInstance();
            }
            catch (Exception e)
            {
                _logger.error("Could not create an 'IIDPStorage' instance of the configured 'class' found with name: " 
                    + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during creation of storage object", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return storage;
    }
    
    //Recursive method to authenticate
    private UserEvent authenticate(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession, 
        ISessionAttributes oAttributes, 
        List<ASelectIDP> listOrganizations, List<Warnings> oWarnings) 
        throws OAException
    {
        UserEvent oUserEvent = null;
        try
        {
            //No more organizations available
            if (listOrganizations.isEmpty())
            {
               throw new UserException(UserEvent.AUTHN_METHOD_FAILED);
            }
            
            Collection cForcedOrganizations = null;
            
            ASelectIDP oASelectOrganization = null;
            if (oAttributes.contains(RemoteASelectMethod.class, _sMethodId+SESSION_SELECTED_ORGANIZATION))
            {
                oASelectOrganization = 
                    (ASelectIDP)oAttributes.get(RemoteASelectMethod.class, 
                        _sMethodId+SESSION_SELECTED_ORGANIZATION);
            }
            else
            {  
                IUser oUser = oSession.getUser();
                if (oUser != null)
                {
                    if (!oUser.isAuthenticationRegistered(getID()))
                    {
                        throw new UserException(UserEvent.AUTHN_METHOD_NOT_REGISTERED);
                    }
                }
                
                List<ASelectIDP> listSelectableOrganizations = 
                    new Vector<ASelectIDP>();
                cForcedOrganizations = (Collection)oAttributes.get(
                    ProxyAttributes.class, ProxyAttributes.FORCED_ORGANIZATIONS);
                if (cForcedOrganizations != null)
                { //filter all forced orgs
                    
                    for(Object oForceOrganization : cForcedOrganizations)
                    {
                        String sForceOrganization = (String)oForceOrganization; 
                        for (ASelectIDP oOrganization: listOrganizations)
                        {
                            if (oOrganization.getID().equals(sForceOrganization))
                                listSelectableOrganizations.add(oOrganization);
                        }
                    } 
                }
               
                if (listSelectableOrganizations.isEmpty())
                {
                    //forced organization not known by this server, just proxy the 
                    //forced one with the "remote_organization" parameter
                    listSelectableOrganizations.addAll(listOrganizations);
                }
                
                if (_oSelector == null)
                {
                    oASelectOrganization = listSelectableOrganizations.get(0);
                    _logger.debug("No selector configured, using: " + oASelectOrganization.getID());
                }
                else
                {
                    try
                    {
                        //Select organization
                        oASelectOrganization = _oSelector.resolve(
                            oRequest, oResponse, oSession, listSelectableOrganizations, 
                            _sFriendlyName, oWarnings);
                    }
                    catch (OAException e)
                    {
                        _eventLogger.info(new UserEventLogItem(oSession, 
                            oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                            this, oWarnings.toString()));
                        
                        throw e;
                    }
                }
                
                if (oASelectOrganization == null)
                {
                    //Page is shown
                    _eventLogger.info(new UserEventLogItem(oSession, 
                        oRequest.getRemoteAddr(), UserEvent.AUTHN_METHOD_IN_PROGRESS, 
                        this, null));
                    
                    return UserEvent.AUTHN_METHOD_IN_PROGRESS;
                }
                
                oAttributes.put(RemoteASelectMethod.class, 
                    _sMethodId+SESSION_SELECTED_ORGANIZATION, oASelectOrganization);
            }
            
            if (oRequest.getParameter(PARAM_ASELECTCREDENTIALS) != null)
            {
                oUserEvent = 
                    requestVerifyCredentials(oRequest, oSession, oASelectOrganization);
            }
            else
            {
                try
                {
                    oUserEvent = 
                        requestAuthenticate(oRequest, oResponse, oSession, 
                            oASelectOrganization, cForcedOrganizations);
                }
                catch (IOException e)
                {
                    _logger.warn("Could not communicate with: " + oASelectOrganization.getURL(), e);
                    
                    if (!_bFallback)
                    {                       
                       throw new UserException(UserEvent.AUTHN_METHOD_FAILED);
                    }                    
                    
                    oAttributes.remove(RemoteASelectMethod.class, 
                        _sMethodId+SESSION_SELECTED_ORGANIZATION);
                    listOrganizations.remove(oASelectOrganization);
                    oAttributes.put(RemoteASelectMethod.class, 
                        _sMethodId+SESSION_AVAILABLE_ORGANIZATIONS, listOrganizations);
                    oWarnings.add(Warnings.WARNING_ORGANIZATION_UNAVAILABLE);                                                               
                }
            }
            
            if(oUserEvent == null)
            {
                //Call method recursively
                oUserEvent = authenticate(oRequest, oResponse, oSession, 
                    oAttributes, listOrganizations, oWarnings);
            }
        }
        catch(UserException e)
        {
            oUserEvent = e.getEvent();
            _eventLogger.info(new UserEventLogItem(oSession, 
                oRequest.getRemoteAddr(), 
                oUserEvent, this, 
                null));
        }        
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during authenticate", e);
            if (oSession != null)
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                    this, null));
            else
                _eventLogger.info(new UserEventLogItem(null, null, 
                    null, UserEvent.INTERNAL_ERROR, null, 
                    oRequest.getRemoteAddr(), null, this, 
                    null));            
            
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return oUserEvent;
    }
   
    private UserEvent requestAuthenticate(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession, 
        ASelectIDP oASelectOrganization, Collection cForcedOrganizations) 
        throws OAException, IOException
    {
        UserEvent oUserEvent = UserEvent.AUTHN_METHOD_FAILED;
        Hashtable<String, String> htRequest = new Hashtable<String, String>();
        try
        {
            String sUID = null;
            IUser oUser = oSession.getUser();
            if (oUser != null)
                sUID = oUser.getID();
            else
                sUID = oSession.getForcedUserID();
            
            if (sUID != null)
            {
                if (_idMapper != null)
                {
                    sUID = _idMapper.map(sUID); 
                    if (sUID == null)
                    {
                        _eventLogger.info(new UserEventLogItem(oSession, 
                            oRequest.getRemoteAddr(), 
                            UserEvent.AUTHN_METHOD_NOT_SUPPORTED, 
                            this, "No user mapping"));
                        
                        return UserEvent.AUTHN_METHOD_NOT_SUPPORTED;
                    }
                }
                
                htRequest.put(PARAM_UID, sUID);
            }
            
            htRequest.put(PARAM_FORCED, String.valueOf(oSession.isForcedAuthentication()));
            
            StringBuffer sbMyURL = new StringBuffer();
            sbMyURL.append(oRequest.getRequestURL().toString());
            sbMyURL.append("?").append(ISession.ID_NAME);
            sbMyURL.append("=").append(URLEncoder.encode(oSession.getId(), CHARSET));
            
            htRequest.put(PARAM_LOCAL_AS_URL, sbMyURL.toString());
            htRequest.put(PARAM_LOCAL_ORG, _sMyOrganization);
            htRequest.put(PARAM_ASELECTSERVER, oASelectOrganization.getServerID());
            
            ISessionAttributes oAttributes = oSession.getAttributes();
            
            String sRequiredLevel = null;
            if (oAttributes.contains(ProxyAttributes.class, SESSION_PROXY_REQUIRED_LEVEL))
                sRequiredLevel = (String)oAttributes.get(ProxyAttributes.class, SESSION_PROXY_REQUIRED_LEVEL);
            else
                sRequiredLevel = String.valueOf(oASelectOrganization.getLevel());
            htRequest.put(PARAM_REQUIRED_LEVEL, sRequiredLevel);
            
            String sCountry = null;
            String sLanguage = null;
            
            Locale oLocale = oSession.getLocale();
            if (oLocale != null)
            {
                sCountry = oLocale.getCountry();
                sLanguage = oLocale.getLanguage();
            }
            
            if (sCountry == null && oASelectOrganization.getCountry() != null)
                sCountry = oASelectOrganization.getCountry();
            if (sCountry != null)
                htRequest.put(PARAM_COUNTRY, sCountry);
            
            if (sLanguage == null && oASelectOrganization.getLanguage() != null)
                sLanguage = oASelectOrganization.getLanguage();
            if (sLanguage != null)
                htRequest.put(PARAM_LANGUAGE, sLanguage);
            
            if (cForcedOrganizations != null)
            {//DD Only send the optional remote_organization parameter if it the value is not the target organization ID 
                Iterator iter = cForcedOrganizations.iterator();
                while (iter.hasNext())
                {
                    String sRemoteOrg = (String)iter.next();
                    if (!sRemoteOrg.equals(oASelectOrganization.getID()))
                    {
                        htRequest.put(PARAM_REMOTE_ORGANIZATION, sRemoteOrg);
                        break;
                    }
                }
            }
            
            if (oASelectOrganization.isArpTargetEnabled())
            {
                String sArpTarget = resolveArpTarget(oAttributes, 
                    oSession.getRequestorId());
                if (sArpTarget != null)
                    htRequest.put(PARAM_ARP_TARGET, sArpTarget);
            }
            
            if (oASelectOrganization.doSigning())
            {
                String sSignature = createSignature(htRequest);
                htRequest.put(PARAM_SIGNATURE, sSignature);
            }
            
            htRequest.put(PARAM_REQUEST, AUTHENTICATE);
            
            Hashtable<String, String> htResponse = null;
            
            try
            {
                htResponse = sendRequest(oASelectOrganization.getURL(), htRequest);
            }
            catch (IOException e)
            {
                _logger.debug("Could not send authenticate request to: " + 
                    oASelectOrganization.getURL(), e);
                throw e;
            }
            
            String sResultCode = htResponse.get(PARAM_RESULTCODE);
            if (sResultCode == null)
            {
                StringBuffer sbError = new StringBuffer("Required parameter (");
                sbError.append(PARAM_RESULTCODE);
                sbError.append(") not found in request=authenticate response (");
                sbError.append(htResponse);
                sbError.append(") from A-Select Organization: ");
                sbError.append(oASelectOrganization.getServerID());
                _logger.warn(sbError.toString());
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, this, 
                    "Invalid authenticate response"));
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            if (!ERROR_ASELECT_SUCCESS.equals(sResultCode))
            {
                StringBuffer sbError = new StringBuffer("Response parameter (");
                sbError.append(PARAM_RESULTCODE);
                sbError.append(") from A-Select Organization '");
                sbError.append(oASelectOrganization.getServerID());
                sbError.append("' contains error code: ");
                sbError.append(sResultCode);
                _logger.warn(sbError.toString());
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.AUTHN_METHOD_FAILED, 
                    this, sResultCode));                
               
                return UserEvent.AUTHN_METHOD_FAILED;
            }
            String sRemoteRid = htResponse.get(PARAM_RID);
            if (sRemoteRid == null)
            {
                StringBuffer sbError = new StringBuffer("Required parameter (");
                sbError.append(PARAM_RID);
                sbError.append(") not found in request=authenticate response (");
                sbError.append(htResponse);
                sbError.append(") from A-Select Organization: ");
                sbError.append(oASelectOrganization.getServerID());
                _logger.warn(sbError.toString());                
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                    this, "Invalid authenticate response"));                
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            String sRemoteLoginUrl = htResponse.get(PARAM_AS_URL);
            if (sRemoteLoginUrl == null)
            {
                StringBuffer sbError = new StringBuffer("Required parameter (");
                sbError.append(PARAM_AS_URL);
                sbError.append(") not found in request=authenticate response (");
                sbError.append(htResponse);
                sbError.append(") from A-Select Organization: ");
                sbError.append(oASelectOrganization.getServerID());
                _logger.warn(sbError.toString());
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, this, 
                    "Invalid authenticate response"));
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            StringBuffer sbRedirect = new StringBuffer(sRemoteLoginUrl);
            sbRedirect.append("&").append(PARAM_RID);
            sbRedirect.append("=").append(sRemoteRid);
            sbRedirect.append("&").append(PARAM_ASELECTSERVER);
            sbRedirect.append("=").append(oASelectOrganization.getServerID());
            
            _eventLogger.info(new UserEventLogItem(oSession, 
                oRequest.getRemoteAddr(), UserEvent.AUTHN_METHOD_IN_PROGRESS, 
                this, "Redirect user with request=login1"));
            
            oSession.persist();
            
            oUserEvent = UserEvent.AUTHN_METHOD_IN_PROGRESS;
            
            try
            {
                oResponse.sendRedirect(sbRedirect.toString());
            }
            catch (IOException e)
            {
                _logger.debug("Could not send redirect: " + sbRedirect.toString(), e);
                throw e;
            }
        }
        catch (IOException e)
        {
            throw e;
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            if (oSession != null)
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                    this, null));
            else
                _eventLogger.info(new UserEventLogItem(null, null, 
                    null, UserEvent.INTERNAL_ERROR, null, 
                    oRequest.getRemoteAddr(), null, this, 
                   null));
            
            _logger.fatal("Internal error during 'request=authenticate' API call to: " 
                + oASelectOrganization.getServerID(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return oUserEvent;
    }
    
    private UserEvent requestVerifyCredentials(HttpServletRequest oRequest, 
        ISession oSession, ASelectIDP oASelectOrganization) throws OAException
    {
        UserEvent oUserEvent = UserEvent.AUTHN_METHOD_FAILED;
        Hashtable<String, String> htRequest = new Hashtable<String, String>();
        try
        {   
            _logger.debug("Processing request: " +  oRequest.getParameterMap().keySet());
            String sASelectServerId = oRequest.getParameter(PARAM_ASELECTSERVER);
            if (sASelectServerId == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(PARAM_ASELECTSERVER);
                sbError.append("' parameter found in request");
                _logger.debug(sbError.toString());
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.REQUEST_INVALID, 
                    this, "Missing " + PARAM_ASELECTSERVER));
                               
                return UserEvent.REQUEST_INVALID;
            }
            if (!sASelectServerId.equals(oASelectOrganization.getServerID()))
            {
                StringBuffer sbError = new StringBuffer("Invalid '");
                sbError.append(PARAM_ASELECTSERVER);
                sbError.append("' parameter found in request: ");
                sbError.append(sASelectServerId);
                _logger.debug(sbError.toString());
                
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.REQUEST_INVALID, this, 
                    "Invalid " + PARAM_ASELECTSERVER));
               
                return UserEvent.REQUEST_INVALID;
            }
            String sRemoteRid = oRequest.getParameter(PARAM_RID);
            if (sRemoteRid == null)
            {
                StringBuffer sbError = new StringBuffer("Request parameter (");
                sbError.append(PARAM_RID);
                sbError.append(") not found in request from A-Select Organization: ");
                sbError.append(sASelectServerId);
                _logger.debug(sbError.toString()); 
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.REQUEST_INVALID, this, 
                    "Missing " + PARAM_RID));
                                
                return UserEvent.REQUEST_INVALID;
            }
            
            String sASelectCredentials = oRequest.getParameter(PARAM_ASELECTCREDENTIALS);
            if (sASelectCredentials == null)
            {
                StringBuffer sbError = new StringBuffer("Request parameter (");
                sbError.append(PARAM_ASELECTCREDENTIALS);
                sbError.append(") not found in request from A-Select Organization: ");
                sbError.append(sASelectServerId);
                _logger.debug(sbError.toString());          
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.REQUEST_INVALID, this, 
                    "Missing " + PARAM_ASELECTCREDENTIALS));
                               
                return UserEvent.REQUEST_INVALID;
            }

            htRequest.put(PARAM_RID, sRemoteRid);
            htRequest.put(PARAM_ASELECTCREDENTIALS, sASelectCredentials);
            htRequest.put(PARAM_ASELECTSERVER, oASelectOrganization.getServerID());
            htRequest.put(PARAM_LOCAL_ORG, _sMyOrganization);
            
            if (oASelectOrganization.doSigning())
            {
                String sSignature = createSignature(htRequest);
                htRequest.put(PARAM_SIGNATURE, sSignature);
            }
            htRequest.put(PARAM_REQUEST, VERIFY_CREDENTIALS);
            
            Hashtable<String, String> htResponse = null;
            try
            {
                htResponse = sendRequest(oASelectOrganization.getURL(), htRequest);
            }
            catch (IOException e)
            {
                _logger.error("Could not verify credentials to: " +  oASelectOrganization.getURL(), e);
                throw new OAException(SystemErrors.ERROR_RESOURCE_CONNECT);
            }
            _logger.debug("Processing response: " +  htResponse);
            String sResultCode = htResponse.get(PARAM_RESULTCODE);
            if (sResultCode == null)
            {
                StringBuffer sbError = new StringBuffer("Required parameter (");
                sbError.append(PARAM_RESULTCODE);
                sbError.append(") not found in request=verify_credentials response (");
                sbError.append(htResponse);
                sbError.append(") from A-Select Organization: ");
                sbError.append(oASelectOrganization.getServerID());
                _logger.warn(sbError.toString());
                
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                    this, "Invalid verify_credentials response"));
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            if (!ERROR_ASELECT_SUCCESS.equals(sResultCode))
            {
                //DD The result code form the remote server is not shown to the user
                if (ERROR_ASELECT_CANCEL.equals(sResultCode))
                {
                    _eventLogger.info(new UserEventLogItem(oSession, 
                        oRequest.getRemoteAddr(), UserEvent.USER_CANCELLED, 
                        this, null));
                    
                    oUserEvent = UserEvent.USER_CANCELLED;
                    _logger.debug("User returned from organization where the cancel button was used");
                    
                    oSession.getAttributes().remove(RemoteASelectMethod.class, _sMethodId+SESSION_SELECTED_ORGANIZATION);
                    
                    if (performReplay(oSession, oSession.getAttributes()))
                        return UserEvent.AUTHN_METHOD_IN_PROGRESS;
                }
                else
                {                 
                    _eventLogger.info(new UserEventLogItem(oSession, 
                        oRequest.getRemoteAddr(), UserEvent.AUTHN_METHOD_FAILED, 
                        this, sResultCode));
                    
                    oUserEvent = UserEvent.AUTHN_METHOD_FAILED;
                }
            }
            else
            {
                String sRemoteUID = htResponse.get(PARAM_UID);
                if (sRemoteUID == null)
                {
                    StringBuffer sbError = new StringBuffer("Request parameter (");
                    sbError.append(PARAM_UID);
                    sbError.append(") not found in response from A-Select Organization: ");
                    sbError.append(sASelectServerId);
                    _logger.warn(sbError.toString());

                    _eventLogger.info(new UserEventLogItem(oSession, 
                        oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                        this, "Invalid verify_credentials response"));
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                //DD 2x URLDecode i.v.m. bug in A-Select 1.5
                sRemoteUID = URLDecoder.decode(sRemoteUID, CHARSET);
                sRemoteUID = URLDecoder.decode(sRemoteUID, CHARSET);
                
                String sRemoteOrganization = htResponse.get(PARAM_ORGANIZATION);
                if (sRemoteOrganization == null)
                {
                    StringBuffer sbError = new StringBuffer("Request parameter (");
                    sbError.append(PARAM_ORGANIZATION);
                    sbError.append(") not found in response from A-Select Organization: ");
                    sbError.append(oASelectOrganization.getID());
                    _logger.warn(sbError.toString());

                    _eventLogger.info(new UserEventLogItem(oSession, 
                        oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                        this, "Invalid verify_credentials response"));
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                
                if (!sRemoteOrganization.equals(oASelectOrganization.getID()))
                {
                    StringBuffer sbError = new StringBuffer("Unknown `");
                    sbError.append(PARAM_ORGANIZATION);
                    sbError.append("` in response; Expected `");
                    sbError.append(oASelectOrganization.getID());
                    sbError.append("` received: ");
                    sbError.append(sRemoteOrganization);
                    _logger.warn(sbError.toString());

                    _eventLogger.info(new UserEventLogItem(oSession, 
                        oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                        this, "Unknown organization in response"));
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                
                if (_idMapper != null)
                {
                    sRemoteUID = _idMapper.remap(sRemoteUID);
                    if (sRemoteUID == null)
                    {
                        _eventLogger.info(new UserEventLogItem(oSession, 
                            oRequest.getRemoteAddr(), UserEvent.USER_UNKNOWN, 
                            this, null));
                        
                        return UserEvent.USER_UNKNOWN;
                    }
                }
                
                IUser oUser = oSession.getUser();
                if (oUser == null)
                {
                    oUser = new ASelectRemoteUser(sRemoteOrganization, sRemoteUID, getID(), sASelectCredentials);
                    oSession.setUser(oUser);
                }
                
                String sRemoteAuthSP = htResponse.get(PARAM_AUTHSP);
                if (sRemoteAuthSP == null)
                {
                    StringBuffer sbError = new StringBuffer("Request parameter (");
                    sbError.append(PARAM_AUTHSP);
                    sbError.append(") not found in response from A-Select Organization: ");
                    sbError.append(sASelectServerId);
                    _logger.warn(sbError.toString());
                    _eventLogger.info(new UserEventLogItem(oSession, 
                        oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                        this, "Invalid verify_credentials response"));
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                String sRemoteAuthSPLevel = htResponse.get(PARAM_AUTHSP_LEVEL);
                if (sRemoteAuthSPLevel == null)
                {
                    StringBuffer sbError = new StringBuffer("Request parameter (");
                    sbError.append(PARAM_AUTHSP_LEVEL);
                    sbError.append(") not found in response from A-Select Organization: ");
                    sbError.append(sASelectServerId);
                    _logger.warn(sbError.toString());
                    _eventLogger.info(new UserEventLogItem(oSession, 
                        oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                        this, "Invalid verify_credentials response"));
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                String sRemoteAppLevel = htResponse.get(PARAM_APP_LEVEL);
                if (sRemoteAppLevel == null)
                {
                    StringBuffer sbError = new StringBuffer("Request parameter (");
                    sbError.append(PARAM_APP_LEVEL);
                    sbError.append(") not found in response from A-Select Organization: ");
                    sbError.append(sASelectServerId);
                    _logger.warn(sbError.toString());
                    _eventLogger.info(new UserEventLogItem(oSession, 
                        oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                        this, "Invalid verify_credentials response"));
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                String sRemoteTGTExpTime = htResponse.get(PARAM_TGT_EXP_TIME);
                if (sRemoteTGTExpTime == null)
                {
                    StringBuffer sbError = new StringBuffer("Request parameter (");
                    sbError.append(PARAM_TGT_EXP_TIME);
                    sbError.append(") not found in response from A-Select Organization: ");
                    sbError.append(sASelectServerId);
                    _logger.warn(sbError.toString());
                    _eventLogger.info(new UserEventLogItem(oSession, 
                        oRequest.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                        this, "Invalid verify_credentials response"));
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
        
                IAttributes oAttributes = new UserAttributes();
                String sRemoteAttributes = htResponse.get(PARAM_ATTRIBUTES);
                if (sRemoteAttributes != null)
                {
                    _logger.debug("Remote A-Select Organization returned serialized attributes: " 
                        + sRemoteAttributes);
                    IAttributes oRemoteAttributes = deserializeAttributes(sRemoteAttributes, oAttributes);
                    oAttributes = mapAttributes(oRemoteAttributes, oUser.getAttributes());
                }
                else
                    oAttributes = oUser.getAttributes();
                
                oUser.setAttributes(oAttributes);
                
                oUserEvent = UserEvent.AUTHN_METHOD_SUCCESSFUL;
                
                _eventLogger.info(new UserEventLogItem(oSession, 
                    oRequest.getRemoteAddr(), UserEvent.AUTHN_METHOD_SUCCESSFUL, 
                    this, null));
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during 'request=verify_credentials'", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }        
        
        return oUserEvent;
    }
    
    private IAttributes mapAttributes(IAttributes source, IAttributes target)
    {
        Enumeration enumNames = source.getNames();
        while (enumNames.hasMoreElements())
        {
            String sName = (String)enumNames.nextElement();
            Object oValue = source.get(sName);
            String sMappedName = _htAttributeMapper.get(sName);
            if (sMappedName != null) 
                sName = sMappedName;
            
            target.put(sName, oValue);
        }
        return target;
    }
    
    private String resolveArpTarget(ISessionAttributes oAttributes, String requestor)
    {
        String sArpTarget = null;
        try
        {
            sArpTarget = (String)oAttributes.get(ProxyAttributes.class, SESSION_PROXY_ARP_TARGET);
            if (sArpTarget == null)
            {
                StringBuffer sbArpTarget = new StringBuffer();
                sbArpTarget.append(URLEncoder.encode(requestor, "UTF-8"));
                sbArpTarget.append("@");
                sbArpTarget.append(URLEncoder.encode(_sMyOrganization, "UTF-8"));
                sArpTarget = sbArpTarget.toString();
            }
        }
        catch (UnsupportedEncodingException e)
        {
            _logger.warn("No support for UTF-8", e);
        }
        
        return sArpTarget;
    }
    
    /**
     * Returns false when replay is not performed.
     * If replay is performed and user authentication should not proceed, a userevent should be returned. 
     */
    private boolean performReplay(ISession oSession, ISessionAttributes oAttributes) 
        throws OAException
    {   
        boolean bPerformed = false;
        if (_sForceAuthNProfile != null)
        {
            AuthenticationProfile forceAuthNProfile = _authNProfileFactory.getProfile(_sForceAuthNProfile);
            if (forceAuthNProfile == null)
            {
                _logger.error("AuthenticationProfile is not available: " + _sForceAuthNProfile);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            if (!forceAuthNProfile.isEnabled())
            {
                _logger.error("AuthenticationProfile is disabled: " + _sForceAuthNProfile);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            List<IAuthenticationProfile> listProfiles = new Vector<IAuthenticationProfile>();
            listProfiles.add(forceAuthNProfile);
            
            oSession.setState(SessionState.AUTHN_NOT_SUPPORTED);
            oSession.setAuthNProfiles(listProfiles);
            oSession.setSelectedAuthNProfile(forceAuthNProfile);
            
            //Reset forced organizations which is set by authn.entree.wayf
            if (oAttributes.contains(ProxyAttributes.class, ProxyAttributes.FORCED_ORGANIZATIONS))
                oAttributes.remove(ProxyAttributes.class, ProxyAttributes.FORCED_ORGANIZATIONS);
            
            oSession.persist();
            
            bPerformed = true;
        }
        
        return bPerformed;
    }
    
    private void readReplay(Element eConfig) throws OAException
    {
        Element eForceProfile = _configurationManager.getSection(eConfig, "forceprofile");
        if (eForceProfile != null)
        {
            _sForceAuthNProfile = _configurationManager.getParam(eForceProfile, "id");
            if (_sForceAuthNProfile == null)
            {
                _logger.error("No 'id' parameter in 'forceprofile' configured");
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            AuthenticationProfile forceAuthNProfile = _authNProfileFactory.getProfile(_sForceAuthNProfile);
            if (forceAuthNProfile == null)
            {
                _logger.error("AuthenticationProfile is not available: " + _sForceAuthNProfile);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            if (!forceAuthNProfile.isEnabled())
            {
                _logger.warn("AuthenticationProfile is disabled: " + _sForceAuthNProfile);
            }
        }        
    }

}
