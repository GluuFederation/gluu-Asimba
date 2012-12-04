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
package com.alfaariss.oa.authentication.remote.saml2;

import java.util.Hashtable;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.xml.ConfigurationException;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.idmapper.IIDMapper;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.sso.logout.IASLogout;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.tgt.TGTListenerEvent;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.authentication.remote.saml2.beans.SAMLRemoteUser;
import com.alfaariss.oa.authentication.remote.saml2.logout.LogoutManager;
import com.alfaariss.oa.authentication.remote.saml2.profile.logout.LogoutProfile;
import com.alfaariss.oa.authentication.remote.saml2.selector.ISAMLOrganizationSelector;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.idp.storage.IIDPStorage;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory;
import com.alfaariss.oa.sso.authentication.web.IWebAuthenticationMethod;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.saml2.NameIDFormatter;
import com.alfaariss.oa.util.saml2.SAML2ConditionsWindow;
import com.alfaariss.oa.util.saml2.SAML2Exchange;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;
import com.alfaariss.oa.util.saml2.opensaml.CustomOpenSAMLBootstrap;

/**
 * Base class for creating authentication methods based on the SAML protocol. It reads
 * basic configuration items.
 *
 * @author MHO
 * @author jre
 * @author Alfa & Ariss
 * @since 1.0
 */
public abstract class BaseSAML2AuthenticationMethod implements
    IWebAuthenticationMethod, IASLogout
{   
    /**
     * System logger.
     */
    protected Log _logger = null;
    
    /**
     * Event logger.
     */
    protected Log _eventLogger = null;
    
    /**
     * The configuration manager.
     */
    protected IConfigurationManager _configurationManager = null;
    
    /**
     * The current method ID, specified in config.
     */
    protected String _sMethodId = null;
    
    /**
     * Indicates if this method is enabled.
     */
    protected boolean _bIsEnabled = false;
    
    /**
     * Indicates if fallback is enabled.
     */
    protected boolean _bEnableFallback = false;
    
    /**
     * The friendly name of the current method.
     */
    protected String _sFriendlyName = null;
    
    /**
     * The current ID mapper.
     */
    protected IIDMapper _idMapper = null;
    
    /**
     * The organization selector.
     */
    protected ISAMLOrganizationSelector _oSelector = null;
    
    /**
     * The current attribute mapper.
     */
    protected Hashtable<String, String> _htAttributeMapper = null;

    /** TGT factory */
    protected ITGTFactory _tgtFactory;
    
    /** Organization Storage */
    protected IIDPStorage _organizationStorage;
    
    /** TGT Alias Store */
    protected ITGTAliasStore _aliasStoreIDPRole;
    
    /** SAML2 Conditions Window */
    protected SAML2ConditionsWindow _conditionsWindow;
    
    /** ASynchronous Logout Profile */
    private LogoutProfile _asynchronousLogoutProfile;
    
    /** Reason to be used during asynchronous logout */
    private String _sTGTRemoveReason;
    
    /** TGT Event listener processing synchronous logouts */
    private LogoutManager _logoutManager;
    
    /**
     * Default constructor. Initializes loggers and attribute mapper.
     * @throws OAException If OpenSAML could not be initialized.
     */
    public BaseSAML2AuthenticationMethod() throws OAException
    {
        _logger = LogFactory.getLog(this.getClass());
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
        
        _htAttributeMapper = new Hashtable<String, String>();
        
        try
        {
            CustomOpenSAMLBootstrap.bootstrap();
        }
        catch (ConfigurationException e)
        {
            _logger.error("Could not initialize OpenSAML", e);
            throw new OAException(SystemErrors.ERROR_INIT);
        }
    }

    /**
     * @see com.alfaariss.oa.api.IManagebleItem#getID()
     */
    public String getID()
    {
        return _sMethodId;
    }
    
    /**
     * @see com.alfaariss.oa.api.IManagebleItem#isEnabled()
     */
    public boolean isEnabled() 
    {
        return _bIsEnabled;
    }
    
    /**
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }
    
    /**
     * Initializes the component.
     *
     * @param oConfigurationManager The configuration manager
     * @param eConfig The configuration section of this component
     * @param idpStorage the organization storage to be used
     * @throws OAException If configuration is invalid
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig, IIDPStorage idpStorage) throws OAException 
    {
        try
        {
            _configurationManager = oConfigurationManager;
            _organizationStorage = idpStorage;
            _tgtFactory = Engine.getInstance().getTGTFactory();
                  
            _aliasStoreIDPRole = _tgtFactory.getAliasStoreIDP();
            if (_aliasStoreIDPRole == null)
            {
                _logger.error("IDP Role TGT Alias Store is disabled");
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            _sMethodId = _configurationManager.getParam(eConfig, "id");
            if (_sMethodId == null)
            {
                _logger.error("No 'id' parameter found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _sFriendlyName = _configurationManager.getParam(eConfig, "friendlyname");
            if (_sFriendlyName == null)
            {
                _logger.error("No 'friendlyname' parameter found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _bIsEnabled = true;
            String sEnabled = _configurationManager.getParam(eConfig, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    _bIsEnabled = false;
                else if (!sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _logger.error("Unknown value in 'enabled' configuration item: " 
                        + sEnabled);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            if (_bIsEnabled)
            {
                Element eConditions = _configurationManager.getSection(eConfig, "Conditions");
                if (eConditions == null)
                    _conditionsWindow = new SAML2ConditionsWindow();
                else
                    _conditionsWindow = new SAML2ConditionsWindow(
                        _configurationManager, eConditions);
                
                Element eIDMapper = _configurationManager.getSection(eConfig, "idmapper");
                if (eIDMapper != null)
                    _idMapper = createMapper(_configurationManager, eIDMapper);
                                
                Element eSelector = _configurationManager.getSection(eConfig, "selector");
                if (eSelector == null)
                    _logger.info("No optional 'selector' section found in configuration");
                else
                    _oSelector = createSelector(eSelector);
                                
                Element eMapper = oConfigurationManager.getSection(eConfig, "attributemapper");
                if (eMapper == null)
                    _logger.info("No optional 'attributemapper' section found in configuration");
                else
                    readMapperConfiguration(eMapper);
                
                try
                {
                    SAML2Exchange.getEntityDescriptor();
                }
                catch(OAException e)
                {
                    _logger.error("Cannot start: SAML2 Profile with Response Endpoint is disabled");
                    throw new OAException(SystemErrors.ERROR_INIT);   
                }
                
                _logoutManager = new LogoutManager(_configurationManager, 
                    eConfig, _sMethodId, _organizationStorage, _idMapper);
                if (_logoutManager.isEnabled())
                {
                    _logger.info("Logout: enabled");
                    _tgtFactory.addListener(_logoutManager);
                    _asynchronousLogoutProfile = createASynchronousLogoutProfile(eConfig);
                }
                else
                {
                    _logger.info("Logout: disabled");
                }
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
     * Stops the method.
     */
    public void stop() 
    {   
        _bIsEnabled = false;

        if (_asynchronousLogoutProfile != null)
            _asynchronousLogoutProfile.destroy();
        
        if (_logoutManager != null)
        {
            if (_tgtFactory != null)
                _tgtFactory.removeListener(_logoutManager);
            
            _logoutManager.destroy();
            _logoutManager = null;
        }
        
        if (_idMapper != null)
            _idMapper.stop();
        
        if (_oSelector != null)
            _oSelector.stop();
        _oSelector = null;
        
        if (_htAttributeMapper != null)
            _htAttributeMapper.clear();
    }
    /**
     * @see com.alfaariss.oa.api.sso.logout.IASLogout#logout(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, com.alfaariss.oa.api.tgt.ITGT, com.alfaariss.oa.api.session.ISession)
     */
    public UserEvent logout(HttpServletRequest request,
        HttpServletResponse response, ITGT tgt, ISession session)
        throws OAException
    {
        if (_asynchronousLogoutProfile == null)
        {
            _logger.error("Logout disabled");
            return UserEvent.INTERNAL_ERROR;
        }
        
        if (tgt == null)
        {
            _logger.error("No TGT supplied");
            _eventLogger.info(new UserEventLogItem(session, 
                request.getRemoteAddr(), UserEvent.INTERNAL_ERROR, this, 
                "no tgt"));
            return UserEvent.INTERNAL_ERROR;
        }
        
        IUser user = session.getUser();
        if (user == null)
        {
            _logger.error("No user available in TGT");
            _eventLogger.info(new UserEventLogItem(session, 
                request.getRemoteAddr(), UserEvent.INTERNAL_ERROR, this, 
                "invalid tgt"));
            return UserEvent.INTERNAL_ERROR;
        }
            
        UserEvent logoutEvent = UserEvent.USER_LOGOUT_FAILED;
        if (_asynchronousLogoutProfile != null)
        {
            SAML2IDP organization = null;
            
            ISessionAttributes sessionAttributes = session.getAttributes();
            if (sessionAttributes.contains(this.getClass(), 
                _sMethodId, LogoutProfile.SESSION_LOGOUT_ORGANIZATION))
            {
                organization = (SAML2IDP)sessionAttributes.get(
                    this.getClass(), _sMethodId, LogoutProfile.SESSION_LOGOUT_ORGANIZATION);
            }
            else
            {
                SAMLRemoteUser samlUser = (SAMLRemoteUser)user;
                organization = (SAML2IDP)_organizationStorage.getIDP(samlUser.getIDP());
                
                if (organization != null)
                    sessionAttributes.put(this.getClass(), _sMethodId, 
                        LogoutProfile.SESSION_LOGOUT_ORGANIZATION, organization);
            }
            
            String sessionIndex = 
                _aliasStoreIDPRole.getAlias(
                    NameIDFormatter.TYPE_ALIAS_TGT, organization.getID(), tgt.getId());
            if (sessionIndex != null)
            {   
                logoutEvent = _asynchronousLogoutProfile.processASynchronous(
                    request, response, session, organization, 
                    _sTGTRemoveReason, sessionIndex);
                if (logoutEvent == UserEvent.USER_LOGGED_OUT)
                {
                    tgt.getAttributes().put(BaseSAML2AuthenticationMethod.class, 
                        _sMethodId, LogoutProfile.TGT_LOGOUT_ORGANIZATION, organization);
                    tgt.persist();
                }
            }
            
            _eventLogger.info(new UserEventLogItem(session, 
                request.getRemoteAddr(), logoutEvent, this, null));
        }
  
        return logoutEvent;
    }

    /**
     * @see com.alfaariss.oa.api.sso.logout.IASLogout#canLogout(com.alfaariss.oa.api.tgt.ITGT)
     */
    public boolean canLogout(ITGT tgt) throws OAException
    {   
        if (_asynchronousLogoutProfile == null)
            return false;
        
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
        
        if (user instanceof SAMLRemoteUser)
        {    
            SAMLRemoteUser samlUser = (SAMLRemoteUser)user;
            if (_organizationStorage.exists(samlUser.getIDP()))
            {
                SAML2IDP orgLogout = (SAML2IDP)_organizationStorage.getIDP(samlUser.getIDP());
                if (orgLogout != null)
                {
                    SingleLogoutService sloService = 
                        _asynchronousLogoutProfile.getService(orgLogout);
                    if (sloService != null)
                    {
                        String sessionIndex = 
                            _aliasStoreIDPRole.getAlias(
                                NameIDFormatter.TYPE_ALIAS_TGT, 
                                orgLogout.getID(), tgt.getId());
                        
                        return sessionIndex != null;
                    }
                }
            }
        }
        
        return false;
    }
    
    private LogoutProfile createASynchronousLogoutProfile(Element config) throws OAException
    {
        Element eLogout = _configurationManager.getSection(config, "logout");
        if (eLogout != null)
        {
            Element eEvent = _configurationManager.getSection(config, "event");
            while (eEvent != null)
            {
                String id = _configurationManager.getParam(eEvent, "id");
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
                
                if (event == TGTListenerEvent.ON_REMOVE)
                {
                    _sTGTRemoveReason = _configurationManager.getParam(eEvent, "reason");
                    if (_sTGTRemoveReason == null)
                    {
                        _logger.error("No 'reason' parameter in 'event' section found in configuration");
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                }
                
                eEvent = _configurationManager.getNextSection(eEvent);
            }
        }
        
        LogoutProfile logoutProfile = new LogoutProfile(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        logoutProfile.init(SAML2Exchange.getEntityDescriptor(), _idMapper, 
            _organizationStorage, _sMethodId, _conditionsWindow);
        
        return logoutProfile;
    }
    
    private void readMapperConfiguration(Element eConfig) throws OAException
    {
        Element eMap = _configurationManager.getSection(eConfig, "map");
        while (eMap != null)
        {
            String sExt = _configurationManager.getParam(eMap, "ext");
            if (sExt == null)
            {
                _logger.error("No 'ext' item found in 'map' section");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sInt = _configurationManager.getParam(eMap, "int");
            if (sInt == null)
            {
                _logger.error("No 'int' item found in 'map' section");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            if (_htAttributeMapper.containsKey(sExt))
            {
                _logger.error("Ext name not unique in map with 'ext' value: " + sExt);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            if (_htAttributeMapper.contains(sInt))
            {
                _logger.error("Int name not unique in map with 'int' value: " + sInt);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            _htAttributeMapper.put(sExt, sInt);
            
            eMap = _configurationManager.getNextSection(eMap);
        }
    }
    
    private ISAMLOrganizationSelector createSelector(Element eConfig) throws OAException
    {
        String sSelectorClass = _configurationManager.getParam(eConfig, "class");
        if (sSelectorClass == null)
        {
            _logger.error("No 'class' item in 'selector' section found");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        ISAMLOrganizationSelector selector = null;
        try
        {
            selector = (ISAMLOrganizationSelector)Class.forName(sSelectorClass).newInstance();
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
            _logger.error("Configured class isn't of type 'ISAMLRequestorSelector': " + sSelectorClass, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ, e);
        }
        
        selector.start(_configurationManager, eConfig);
        
        return selector;
    }

    private IIDMapper createMapper(IConfigurationManager configManager, 
        Element eConfig) throws OAException
    {
        IIDMapper oMapper = null;
        try
        {
            String sClass = configManager.getParam(eConfig, "class");
            if (sClass == null)
            {
                _logger.error("No 'class' parameter found in 'idmapper' section in configuration");
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
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            try
            {
                oMapper = (IIDMapper)cMapper.newInstance();
            }
            catch (Exception e)
            {
                _logger.error("Could not create an 'IIDMapper' instance of the configured 'class' found with name: " 
                    + sClass, e);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            oMapper.start(configManager, eConfig);
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
