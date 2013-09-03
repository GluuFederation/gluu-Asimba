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

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.IDPEntry;
import org.opensaml.saml2.core.IDPList;
import org.opensaml.util.resource.ResourceException;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.authentication.remote.saml2.beans.SAMLRemoteUser;
import com.alfaariss.oa.authentication.remote.saml2.profile.sso.WebBrowserSSOProfile;
import com.alfaariss.oa.authentication.remote.saml2.util.RemoteIDPListEntry;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.idp.IDPStorageManager;
import com.alfaariss.oa.engine.core.idp.storage.IIDPStorage;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.saml2.SAML2Exchange;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;
import com.alfaariss.oa.util.saml2.proxy.ProxyAttributes;
import com.alfaariss.oa.util.saml2.proxy.SAML2IDPEntry;

/**
 * Implementation of an authentication method based on the SAML2 Web browser SSO profile.
 * 
 * This method can only be used in the SP-initiated scenarios.
 *
 * @author MHO
 * @author JRE
 * @author Alfa & Ariss
 * @since 1.0
 * 
 */
public class SAML2AuthenticationMethod extends BaseSAML2AuthenticationMethod
{
    private final static String AUTHORITY_NAME = "SAML2AuthenticationMethod_";
    
    /** Session variable key for retrieving available organizations. */
    private final static String LIST_AVAILABLE_ORGANIZATIONS = "SAML2_Organizations";
    
    /** Session variable key for retrieving the selected organization. */
    private final static String SELECTED_ORGANIZATION = "SAML2_Selected_organization";
    
    /** Cache for remote IDP lists. */
    private Map<String, RemoteIDPListEntry> _mRemoteIDPLists = null;
    
    private WebBrowserSSOProfile _profileWebBrowserSSO;
        
    /**
     * default constructor
     * 
     * @throws OAException If initialization of the base class fails.
     */
    public SAML2AuthenticationMethod() throws OAException
    {
        super();
        _logger = LogFactory.getLog(SAML2AuthenticationMethod.class);
        _mRemoteIDPLists = new HashMap<String, RemoteIDPListEntry>();
    }
    
    /**
     * @see com.alfaariss.oa.api.IComponent#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws OAException 
    {
        try
        {
            //read organizations config
            Element eOrganizations = oConfigurationManager.getSection(eConfig, "idps");
            if (eOrganizations == null)
            {
                _logger.error("No 'idps' section found in 'method' section in configuration from SAML authentication method");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            IIDPStorage idpStorage = createStorage(oConfigurationManager, eOrganizations);
            idpStorage.start(oConfigurationManager, eOrganizations);
            
            IDPStorageManager idpStorageManager = Engine.getInstance().getIDPStorageManager();
            if (idpStorageManager.existStorage(idpStorage.getID()))
            {
                _logger.error("Storage not unique: " + idpStorage.getID());
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            idpStorageManager.addStorage(idpStorage);
            
            //to start the super class, first an organization storage must be created
            super.start(oConfigurationManager, eConfig, idpStorage);
            
            if (_bIsEnabled)
            {
                String sFallback = _configurationManager.getParam(eOrganizations, "fallback");
                if (sFallback != null)
                {
                    if (sFallback.equalsIgnoreCase("TRUE"))
                        _bEnableFallback = true;
                    else if (!sFallback.equalsIgnoreCase("FALSE"))
                    {
                        _logger.error("Unknown value in 'fallback' configuration item (in organizations): " 
                            + sFallback);
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    _logger.debug("Optional organization fallback set to " + _bEnableFallback);
                }
                                
                _profileWebBrowserSSO = new WebBrowserSSOProfile();
                _profileWebBrowserSSO.init(_configurationManager, eConfig, 
                    SAML2Exchange.getEntityDescriptor(_sLinkedIDPProfile), _idMapper, 
                    _organizationStorage, _sMethodId, _sLinkedIDPProfile,
                    _conditionsWindow, _oAuthnInstantWindow,
                    _oRemoteSAMLUserProvisioningProfile);
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
     * Requestor selection based on RemoteASelectMethod.authenticate.
     * 
     * When implementing Synchronous (querying) authentication, this method should be adapted.
     *  - Warnings
     * 
     * @see com.alfaariss.oa.sso.authentication.web.IWebAuthenticationMethod#authenticate(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, com.alfaariss.oa.api.session.ISession)
     */
    @SuppressWarnings("unchecked")
    public UserEvent authenticate(HttpServletRequest request,
        HttpServletResponse response, ISession session) throws OAException
    {
        try
        {
            ISessionAttributes oAttributes = session.getAttributes();
            
            //check proxy att:
            Integer intCnt = (Integer)oAttributes.get(ProxyAttributes.class, ProxyAttributes.PROXYCOUNT);
            if (intCnt != null && intCnt <= 0)
            {
                _logger.debug("No more authentication proxying allowed: " + intCnt);
                _eventLogger.info(new UserEventLogItem(session, 
                    request.getRemoteAddr(), UserEvent.AUTHN_METHOD_FAILED, 
                    this, "ProxyCount <= 0"));
                return UserEvent.AUTHN_METHOD_FAILED;
            }
            
            SAML2IDP organization = null;
            List<Warnings> warnings = null;
            
            if (oAttributes.contains(SAML2AuthenticationMethod.class, 
                _sMethodId + "." + SELECTED_ORGANIZATION))
            {
                organization = (SAML2IDP)oAttributes.get(SAML2AuthenticationMethod.class, 
                    _sMethodId + "." + SELECTED_ORGANIZATION);
            }
            else
            {
                List<SAML2IDP> listSelectableOrganizations = null;
                
                if (oAttributes.contains(SAML2AuthenticationMethod.class, 
                    _sMethodId + "." + LIST_AVAILABLE_ORGANIZATIONS))
                {
                    //The selected organization was not available, select again:
                    listSelectableOrganizations = (List<SAML2IDP>)oAttributes
                        .get(SAML2AuthenticationMethod.class, 
                            _sMethodId + "." + LIST_AVAILABLE_ORGANIZATIONS);
                    
                    warnings = new Vector<Warnings>();
                    warnings.add(Warnings.WARNING_ORGANIZATION_UNAVAILABLE);
                }
                else
                {
                    IUser oUser = session.getUser();
                    if (oUser != null)
                    {
                        //verify if user that was identified in previous authn method may use this SAML2 authn method
                        if (!oUser.isAuthenticationRegistered(_sMethodId))
                        {
                            _eventLogger.info(new UserEventLogItem(session, 
                                request.getRemoteAddr(), 
                                UserEvent.AUTHN_METHOD_NOT_REGISTERED, this, null));
                            
                            return UserEvent.AUTHN_METHOD_NOT_REGISTERED;
                        }
                    }
                    
                    listSelectableOrganizations = new Vector<SAML2IDP>();
                    Vector fallbackList = new Vector<String>();
                    
                    Collection<String> cForcedOrganizations = getForcedIDPs(session);
                    if (cForcedOrganizations != null && !cForcedOrganizations.isEmpty())
                        oAttributes.put(SAML2AuthNConstants.class,
                            SAML2AuthNConstants.FORCED_ORGANIZATIONS, cForcedOrganizations);
                    
                    List<SAML2IDP> listIDPs = _organizationStorage.getAll();
                    for (SAML2IDP saml2IDP : listIDPs)
                    {
                        fallbackList.add(saml2IDP);
                        if (cForcedOrganizations == null || cForcedOrganizations.contains(saml2IDP.getID()))
                        {
                            //if no forced organizations are defined or organization is in the forced
                            //organization list: Add to select organization list.
                            listSelectableOrganizations.add(saml2IDP);
                        }
                    }
                    
                    if (listSelectableOrganizations.isEmpty())
                    {
                        //DD if no forced orgs are known locally, add all and let user decide.
                        //Make sure proxy orgs are send with AuthN request
                        listSelectableOrganizations = fallbackList;
                    }
                }
                
                if (listSelectableOrganizations.size() == 0)
                {
                    _logger.debug("No organizations available to choose from");
                    _eventLogger.info(new UserEventLogItem(session, 
                        request.getRemoteAddr(), UserEvent.AUTHN_METHOD_NOT_SUPPORTED, 
                        this, null));
              
                    return UserEvent.AUTHN_METHOD_NOT_SUPPORTED;
                }
          
                if (_oSelector == null)
                {
                    organization = listSelectableOrganizations.get(0);
                                          
                    _logger.debug("No selector configured, using: " + organization.getID());
                }
                else
                {
                    try
                    {
                        //Select requestor
                        organization = _oSelector.resolve(
                            request, response, session, listSelectableOrganizations, 
                            _sFriendlyName, warnings);
                    }
                    catch (OAException e)
                    {
                        _eventLogger.info(new UserEventLogItem(session, 
                            request.getRemoteAddr(), UserEvent.INTERNAL_ERROR, 
                            this, "selecting organization"));
                        throw e;
                    }
                }
          
                if (organization == null)
                {
                    //Page is shown
                    _eventLogger.info(new UserEventLogItem(session, 
                        request.getRemoteAddr(), UserEvent.AUTHN_METHOD_IN_PROGRESS, 
                        this, null));
              
                    return UserEvent.AUTHN_METHOD_IN_PROGRESS;
                }
          
                oAttributes.put(SAML2AuthenticationMethod.class, 
                    _sMethodId, SELECTED_ORGANIZATION, organization);
                
                listSelectableOrganizations.remove(organization);
                oAttributes.put(SAML2AuthenticationMethod.class, _sMethodId,  
                    LIST_AVAILABLE_ORGANIZATIONS, listSelectableOrganizations);
            }

            UserEvent event = null;
            
            if (_profileWebBrowserSSO != null)
            {
                event = _profileWebBrowserSSO.process(request, response,
                    session, organization, _htAttributeMapper);
                
                _eventLogger.info(new UserEventLogItem(session, 
                    request.getRemoteAddr(), event, 
                    this, null));
            }
            else
            {
                _eventLogger.info(new UserEventLogItem(session, 
                    request.getRemoteAddr(), UserEvent.AUTHN_METHOD_FAILED, 
                    this, "No suitable SAML2 profile could be found for authentication"));
                event = UserEvent.AUTHN_METHOD_FAILED;
            }
            
            if (event == UserEvent.AUTHN_METHOD_FAILED && _bEnableFallback)
            {
                //fallback
                event = UserEvent.AUTHN_METHOD_IN_PROGRESS;
                oAttributes.remove(SAML2AuthenticationMethod.class, 
                    _sMethodId + "." + SELECTED_ORGANIZATION);
                
                _eventLogger.info(new UserEventLogItem(session, 
                    request.getRemoteAddr(), UserEvent.AUTHN_METHOD_IN_PROGRESS, 
                    this, "Fallback mechanism activated"));
                
                event = authenticate(request, response, session);
            }

            return event;
        }
        catch (OAException oae)
        {
            _eventLogger.info(new UserEventLogItem(session, 
                request.getRemoteAddr(), UserEvent.AUTHN_METHOD_FAILED, 
                this, oae.getLocalizedMessage()));
            
            throw oae;
        }
    }

    /**
     * @see com.alfaariss.oa.api.logging.IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return AUTHORITY_NAME + _sMethodId;
    }
    
    /**
     * @see com.alfaariss.oa.authentication.remote.saml2.BaseSAML2AuthenticationMethod#stop()
     */
    public void stop()
    {
        if (_profileWebBrowserSSO != null)
            _profileWebBrowserSSO.destroy();
        
        if (_mRemoteIDPLists != null)
            _mRemoteIDPLists.clear();
        
        if (_organizationStorage != null)
        {
            Engine.getInstance().getIDPStorageManager().removeStorage(_organizationStorage.getID());
            _organizationStorage.stop();
        }
        
        super.stop();
    }
    
    /**
     * Extracts the forced IDP list from the session.
     *
     * @param session The authentication session.
     * @return The forced IDPs.
     * @throws OAException If organization storage exist check can't be performed.
     */
    @SuppressWarnings("unchecked")
    private List<String> getForcedIDPs(ISession session) throws OAException
    {   
        List<String> retval = new Vector<String>();
        
        IUser oUser = session.getUser();
        if (oUser instanceof SAMLRemoteUser)
        {
            SAMLRemoteUser remoteUser = (SAMLRemoteUser)oUser;
            String sRemoteIdP = remoteUser.getOrganization();
            if (sRemoteIdP != null && _organizationStorage.exists(sRemoteIdP))
            {
                StringBuffer sbDebug = new StringBuffer();
                sbDebug.append("There is a Remote SAML User available in session with ID '");
                sbDebug.append(session.getId());
                sbDebug.append("' that is known at remote IdP '");
                sbDebug.append(sRemoteIdP);
                sbDebug.append("' so this IdP will be forced");
                _logger.debug(sbDebug.toString());
                retval.add(sRemoteIdP);
                return retval;
            }
        }
        
        ISessionAttributes atts = session.getAttributes();
        String sGetComplete = (String)
            atts.get(ProxyAttributes.class, ProxyAttributes.IDPLIST_GETCOMPLETE);
        
        if (sGetComplete != null)
        {
            _logger.debug("Using proxy attribute: " + ProxyAttributes.IDPLIST_GETCOMPLETE + ": " + sGetComplete);
            //getcomplete
            IDPList idpList = null;
            try
            {
                if (_mRemoteIDPLists.containsKey(sGetComplete))
                {
                    idpList = _mRemoteIDPLists.get(sGetComplete).getList();
                }
                else
                {
                    RemoteIDPListEntry entry = new RemoteIDPListEntry(sGetComplete, 1000);
                    idpList = entry.getList();
                    
                    //DD Add the RemoteIDPListEntry to a map for caching purposes; The getEntry() retrieves the list from the url. 
                    _mRemoteIDPLists.put(sGetComplete, entry);
                }
                
                if (idpList != null)
                {
                    for (IDPEntry entry : idpList.getIDPEntrys())
                    {
                        retval.add(entry.getProviderID());
                    }
                }
            }
            catch(ResourceException e)
            {
                _logger.warn("Failed retrieval of IDPList from GetComplete URL: " + sGetComplete, e);
            }
        }
        
        List<SAML2IDPEntry> idpList = (List<SAML2IDPEntry>)atts.get(
            ProxyAttributes.class, ProxyAttributes.IDPLIST);
        if (idpList != null)
        {
            if(_logger.isDebugEnabled())
            {
                StringBuffer sbMessage = new StringBuffer("Using proxy attribute ");
                sbMessage.append(ProxyAttributes.IDPLIST);
                sbMessage.append(": ").append(idpList);                                
                _logger.debug(sbMessage);
            }
           
            for (SAML2IDPEntry entry: idpList)
            {
                //DD We currently ignore the proxied SAML2IDPEntry.getName() (friendlyname) and SAML2IDPEntry.getLoc()
                String sID = entry.getProviderID();
                if (sID != null)
                {
                    if (!retval.contains(sID))
                        retval.add(sID);
                }
            }
        }
        
        Collection cForcedOrganizations = (Collection)atts.get(
            com.alfaariss.oa.util.session.ProxyAttributes.class, 
            com.alfaariss.oa.util.session.ProxyAttributes.FORCED_ORGANIZATIONS);
        if (cForcedOrganizations != null)
        {
            if(_logger.isDebugEnabled())
            {
                StringBuffer sbMessage = new StringBuffer("Using proxy attribute ");
                sbMessage.append(com.alfaariss.oa.util.session.ProxyAttributes.FORCED_ORGANIZATIONS);
                sbMessage.append(": ").append(cForcedOrganizations);                                
                _logger.debug(sbMessage);
            }
            for(Object oForceOrganization : cForcedOrganizations)
            {
                String sForceOrganization = (String)oForceOrganization; 
                if (!retval.contains(sForceOrganization))
                    retval.add(sForceOrganization);
            } 
        }
        
        return retval;
    }
    
    private IIDPStorage createStorage(
        IConfigurationManager oConfigurationManager, Element config) throws OAException
    {
        IIDPStorage storage = null;
        try
        {
            String sClass = oConfigurationManager.getParam(config, "class");
            if (sClass == null)
            {
                _logger.error("No 'class' item found in 'storage' section in configuration");
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
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            try
            {
                storage = (IIDPStorage)oClass.newInstance();
            }
            catch (Exception e)
            {
                _logger.error("Could not create an 'IIDPStorage' instance of the configured 'class' found with name: " 
                    + sClass, e);
                throw new OAException(SystemErrors.ERROR_INIT);
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
}
