/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authentication.remote.saml2.logout;

import java.util.Hashtable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.LogoutResponse;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.attribute.ITGTAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.idmapper.IIDMapper;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.tgt.ITGTListener;
import com.alfaariss.oa.api.tgt.TGTEventError;
import com.alfaariss.oa.api.tgt.TGTListenerEvent;
import com.alfaariss.oa.api.tgt.TGTListenerException;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.authentication.remote.saml2.BaseSAML2AuthenticationMethod;
import com.alfaariss.oa.authentication.remote.saml2.beans.SAMLRemoteUser;
import com.alfaariss.oa.authentication.remote.saml2.profile.logout.LogoutProfile;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.idp.storage.IIDPStorage;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.saml2.NameIDFormatter;
import com.alfaariss.oa.util.saml2.SAML2Exchange;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;

/**
 * Sends logout requests to IdPs, when TGT factory indicates that a TGT has expired
 * (time-out or user-initiated log-out).
 *
 * @author jre
 * @author Alfa & Ariss
 * @since 1.1
 */
public class LogoutManager implements ITGTListener, IAuthority
{
    private final static String AUTHORITY_NAME = "SAML2AuthNLogoutManager_";
    private static Log _logger;
    private static Log _eventLogger;
    private String _sMethodID;
    private LogoutProfile _profile;
    private Hashtable<TGTListenerEvent, String> _htReasons;
    private IIDPStorage _store = null;
    private boolean _bEnabled;
    private ITGTAliasStore _aliasStoreIDPRole;
    private NameIDFormatter _nameIDFormatter;

    /**
     * Constructor.
     * 
     * @param configurationManager The configuration manager
     * @param config The configuration section for this component
     * @param methodID The authentication method id, using this logout manager
     * @param store The organization storage
     * @param idMapper User ID mapper
     * @throws OAException If configuration is invalid.
     */
    public LogoutManager(IConfigurationManager configurationManager, 
        Element config, String methodID, IIDPStorage store, 
        IIDMapper idMapper) throws OAException
    {
        _logger = LogFactory.getLog(LogoutManager.class);
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
        
        _bEnabled = true;
        
        Element eLogout = configurationManager.getSection(config, "logout");
        if (eLogout != null)
        {
            String sEnabled = configurationManager.getParam(eLogout, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    _bEnabled = false;
                else if (!sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _logger.error("Unknown value in 'enabled' configuration item: " 
                        + sEnabled);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
        }
        
        if (!_bEnabled)
        {
            _logger.info("Logout Manager: disabled");
        }
        else
        {
            _sMethodID = methodID;
            _store = store;
            _htReasons = new Hashtable<TGTListenerEvent, String>();
            
            if (eLogout != null)
            {
                Element eEvent = configurationManager.getSection(eLogout, "event");
                while (eEvent != null)
                {
                    String id = configurationManager.getParam(eEvent, "id");
                    if (id == null)
                    {
                        _logger.error("No 'id' parameter in 'event' section found in configuration");
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    TGTListenerEvent event = TGTListenerEvent.valueOf(id);
                    if (event == null)
                    {
                        _logger.error("Invalid 'id' parameter in 'event' section found in configuration: " + id);
                        throw new OAException(SystemErrors.ERROR_INIT);
                    }
                    
                    String reason = configurationManager.getParam(eEvent, "reason");
                    if (reason == null)
                    {
                        _logger.error("No 'reason' parameter in 'event' section found in configuration");
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    if (_htReasons.containsKey(event))
                    {
                        _logger.error("Configured 'id' parameter in 'event' section is not unique in configuration: " + id);
                        throw new OAException(SystemErrors.ERROR_INIT);
                    }
                    
                    _htReasons.put(event, reason);
                    eEvent = configurationManager.getNextSection(eEvent);
                }
            }
            
            if (_htReasons.isEmpty())
            {
                _logger.info("No optional event reason configured, using defaults");
            }
            
            _aliasStoreIDPRole = Engine.getInstance().getTGTFactory().getAliasStoreIDP();
            if (_aliasStoreIDPRole == null)
            {
                _logger.error("No IDP Role TGT Alias Store available");
                throw new OAException(SystemErrors.ERROR_INIT); 
            }
            
            _nameIDFormatter = new NameIDFormatter(
                Engine.getInstance().getCryptoManager(), _aliasStoreIDPRole);
            
            _profile = new LogoutProfile(SAMLConstants.SAML2_SOAP11_BINDING_URI);
            _profile.init(configurationManager, null, 
                SAML2Exchange.getEntityDescriptor(), idMapper, 
                _store, _sMethodID, null);
        }
    }

    /**
     * @see com.alfaariss.oa.api.tgt.ITGTListener#processTGTEvent(com.alfaariss.oa.api.tgt.TGTListenerEvent, com.alfaariss.oa.api.tgt.ITGT)
     */
    public void processTGTEvent(TGTListenerEvent event, ITGT tgt) throws TGTListenerException
    {   
        if (!_bEnabled)
            return;
        
        
        switch(event)
        {
            case ON_CREATE:
            {
                processCreate(tgt);
                break;
            }
            case ON_EXPIRE:
            {
                String reason = _htReasons.get(event);
                if (reason == null)
                    reason = LogoutResponse.SP_TIMEOUT_URI;
                
                logout(reason, tgt);
                break;
            }
            case ON_REMOVE:
            {
                String reason = _htReasons.get(event);
                if (reason == null)
                    reason = LogoutResponse.USER_LOGOUT_URI;
                
                logout(reason, tgt);
                break;
            }
            default:
            {
                //do nothing
            }
        }
    }

    /**
     * @see com.alfaariss.oa.api.logging.IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return AUTHORITY_NAME + _sMethodID;
    }
    
    /**
     * @return TRUE if this logout manager is enabled
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }
    
    /**
     * Remove class variables.
     */
    public void destroy()
    {
        if (_profile != null)
            _profile.destroy();
    }
    
    private void processCreate(ITGT tgt) throws TGTListenerException
    {
        try
        {
            IUser user = tgt.getUser();
            if (user instanceof SAMLRemoteUser)
            {
                SAMLRemoteUser samlUser = (SAMLRemoteUser)user;
                String sRemoteOrganization = samlUser.getIDP();
                if (_store.exists(sRemoteOrganization))
                {
                    String sTGTID = tgt.getId();
                    
                    //DD currently only one session index is supported
                    String sessionIndex = samlUser.getSessionIndexes().get(0);
                    if (sessionIndex != null)
                    {
                        _aliasStoreIDPRole.putAlias(NameIDFormatter.TYPE_ALIAS_TGT, 
                            sRemoteOrganization, sTGTID, sessionIndex);
                    }
                    
                    String sNameIDFormat = samlUser.getFormat();
                    String sNameID = samlUser.getID();
                    if (sNameIDFormat != null && sNameID != null)
                    {
                        _nameIDFormatter.store(sTGTID, sNameIDFormat, 
                            sRemoteOrganization, sNameID);
                    }
                }
            }
        }
        catch (TGTListenerException e)
        {
            throw e;
        }
        catch (OAException e)
        {
            throw new TGTListenerException(new TGTEventError(UserEvent.INTERNAL_ERROR));
        }
    }
    
    private void logout(String reason, ITGT tgt) throws TGTListenerException
    {
        SAML2IDP org = null;
        try
        {
            IUser user = tgt.getUser();
            
            if (user instanceof SAMLRemoteUser)
            {
                String orgid = ((SAMLRemoteUser)user).getIDP();
                
                org = (SAML2IDP)_store.getIDP(orgid);
                if (org != null)
                {
                    if (_profile.getService(org) != null)
                    {//synchronous logout is supported in metadata
                        
                        ITGTAttributes tgtAttributes = tgt.getAttributes();
                        
                        SAML2IDP tgtOrganization = (SAML2IDP)tgtAttributes.get(
                            BaseSAML2AuthenticationMethod.class, _sMethodID, 
                                LogoutProfile.TGT_LOGOUT_ORGANIZATION);
                        if (tgtOrganization == null || !org.equals(tgtOrganization))
                        {//asynchronous logout was not already performed
                            
                            String sessionIndex = 
                                _aliasStoreIDPRole.getAlias(
                                    NameIDFormatter.TYPE_ALIAS_TGT, orgid, tgt.getId());
                            if (sessionIndex != null)
                            {
                                UserEvent userEvent = 
                                    _profile.processSynchronous(user, org, 
                                        reason, sessionIndex);
                                
                                UserEventLogItem logItem = new UserEventLogItem(null,
                                    tgt.getId(), null, userEvent, 
                                    user.getID(), user.getOrganization(),
                                    null, null, this, null);
                                _eventLogger.info(logItem);
                                
                                if (userEvent != UserEvent.USER_LOGGED_OUT)
                                {
                                    throw new TGTListenerException(
                                        new TGTEventError(userEvent, org.getFriendlyName()));
                                }
                            }
                        }
                    }
                }
            }
        }
        catch (TGTListenerException e)
        {
            throw e;
        }
        catch (OAException e)
        {
            TGTEventError errorEvent = null;
            
            if (org != null)
                errorEvent = new TGTEventError(UserEvent.USER_LOGOUT_FAILED, 
                    org.getFriendlyName());
            else
                errorEvent = new TGTEventError(UserEvent.USER_LOGOUT_FAILED);
            
            _eventLogger.info(new UserEventLogItem(null, tgt.getId(), null, 
                UserEvent.USER_LOGOUT_FAILED, tgt.getUser().getID(), 
                tgt.getUser().getOrganization(), null, null, this, null));
            
            throw new TGTListenerException(errorEvent);
        }
    }
}
