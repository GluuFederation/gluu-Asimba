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
package com.alfaariss.oa.profile.saml2.listener;

import java.util.List;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.tgt.ITGTListener;
import com.alfaariss.oa.api.tgt.TGTEventError;
import com.alfaariss.oa.api.tgt.TGTListenerEvent;
import com.alfaariss.oa.api.tgt.TGTListenerException;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.profile.saml2.listener.slo.SynchronousSingleLogout;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.saml2.NameIDFormatter;
import com.alfaariss.oa.util.saml2.SAML2Requestor;
import com.alfaariss.oa.util.saml2.SAML2Requestors;

/**
 * Sends logout requests to SPs, when TGT factory indicates that a TGT has expired.
 * 
 * Sends logout messages during the following events:
 * <ul>
 * <li>ON_EXPIRE: TGT time-out</li>
 * <li>ON_REMOVE: user-initiated TGT removal</li>.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class SAML2TGTListener implements ITGTListener, IAuthority
{
    private final static String AUTHORITY_NAME = "SAML2ProfileTGTListener_";
    private static Log _logger;
    private static Log _eventLogger;
    private boolean _bEnabled;
    private String _sProfileID;
    private ITGTAliasStore _spAliasStore;
    private SAML2Requestors _saml2Requestors;
    private IRequestorPoolFactory _requestorPoolFactory;
    private SynchronousSingleLogout _singleLogout;
    
    /**
     * Constructor.
     * 
     * @param configurationManager The configuration manager
     * @param config The configuration section for this component
     * @param profileID The ID of the SAML2 profile.
     * @param requestors SAML2 Requestors
     * @param entityDescriptor Entity Descriptor
     * @throws OAException If configuration is invalid
     */
    public SAML2TGTListener(IConfigurationManager configurationManager, 
        Element config, String profileID, SAML2Requestors requestors, 
        EntityDescriptor entityDescriptor) throws OAException
    {
        _logger = LogFactory.getLog(SAML2TGTListener.class);
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
            _sProfileID = profileID;
            _saml2Requestors = requestors;
            
            Engine engine = Engine.getInstance();
            _requestorPoolFactory = engine.getRequestorPoolFactory();
            
            _spAliasStore = engine.getTGTFactory().getAliasStoreSP();
            if (_spAliasStore == null)
            {
                _logger.error("Required SP Role TGT alias storage is disabled");
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            _singleLogout = new SynchronousSingleLogout(entityDescriptor);
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
                //DD Currently the nameid format or session id doesn't have to be stored in the alias store in here, because it's already stored during authentication (specific info in WebSSOProfile as tgt attributes and aliasses in NameIDFormatter 
                break;
            }
            case ON_EXPIRE:
            {
                List<TGTEventError> listEventErrors = new Vector<TGTEventError>();
                listEventErrors.addAll(processRemove(tgt, LogoutResponse.GLOBAL_TIMEOUT_URI));
                
                if (!listEventErrors.isEmpty())
                    throw new TGTListenerException(listEventErrors);
                
                break;
            }
            case ON_REMOVE:
            {
                List<TGTEventError> listEventErrors = new Vector<TGTEventError>();
                listEventErrors.addAll(processRemove(tgt, LogoutResponse.USER_LOGOUT_URI));
                
                if (!listEventErrors.isEmpty())
                    throw new TGTListenerException(listEventErrors);
                
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
        return AUTHORITY_NAME + _sProfileID;
    }

    /**
     * @return TRUE if this logout manager is enabled
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }
    
    private List<TGTEventError> processRemove(ITGT tgt, String reason) 
    {
        List<TGTEventError> listEventErrors = new Vector<TGTEventError>();
        IRequestor requestor = null;
        IUser user = tgt.getUser();
        for (String sRequestor: tgt.getRequestorIDs())
        {
            try
            {
                String sSessionIndex = _spAliasStore.getAlias(
                    NameIDFormatter.TYPE_ALIAS_TGT, sRequestor, tgt.getId());
                if (sSessionIndex != null)
                {
                    requestor = _requestorPoolFactory.getRequestor(sRequestor);
                    SAML2Requestor saml2Requestor = _saml2Requestors.getRequestor(requestor);
                    if (saml2Requestor != null)
                    {
                        SingleLogoutService ssoService = resolveSPSSOService(saml2Requestor);
                        if (ssoService != null)
                        {
                            UserEvent result = _singleLogout.processSynchronous(
                                user, saml2Requestor, ssoService, reason, 
                                tgt.getAttributes(), sSessionIndex, 
                                tgt.getId());
                            
                            if (result != UserEvent.USER_LOGGED_OUT)
                            {
                                listEventErrors.add(new TGTEventError(
                                    result, requestor.getFriendlyName()));
                            }
                            
                            UserEventLogItem logItem = new UserEventLogItem(null, 
                                tgt.getId(), null, result, 
                                user.getID(), user.getOrganization(), null, 
                                sRequestor, this, null);
                            
                            _eventLogger.info(logItem);
                        }
                    }
                }
            }
            catch (OAException e)
            {
                TGTEventError error = null;
                if (requestor != null)
                    error = new TGTEventError(UserEvent.INTERNAL_ERROR, requestor.getFriendlyName());
                else
                    error = new TGTEventError(UserEvent.INTERNAL_ERROR);
                
                listEventErrors.add(error);
                
                UserEventLogItem logItem = new UserEventLogItem(null, 
                    tgt.getId(), null, UserEvent.INTERNAL_ERROR, 
                    tgt.getUser().getID(), 
                    tgt.getUser().getOrganization(), null, 
                    sRequestor, this, null);
                
                _eventLogger.info(logItem);
            }
        }
        return listEventErrors;
    }
    
    private SingleLogoutService resolveSPSSOService(SAML2Requestor saml2Requestor) 
    {
        try
        {    
            MetadataProvider _oMP = saml2Requestor.getMetadataProvider();
            if (_oMP != null)
            {
                SPSSODescriptor spSSODescriptor = 
                    (SPSSODescriptor)_oMP.getRole(saml2Requestor.getID(), 
                        SPSSODescriptor.DEFAULT_ELEMENT_NAME, 
                        SAMLConstants.SAML20P_NS);
                if (spSSODescriptor != null)
                {
                    List<SingleLogoutService> listSSOServices = 
                        spSSODescriptor.getSingleLogoutServices();
                    if (listSSOServices != null && !listSSOServices.isEmpty())
                    {
                        for (SingleLogoutService ssoService: listSSOServices)
                        {//DD Currently only synchronous bindings are supported
                            if (SAMLConstants.SAML2_SOAP11_BINDING_URI.equals(ssoService.getBinding()))
                            {
                                return ssoService;
                            }
                        }
                    }                
                }
            }
        }
        catch (MetadataProviderException e)
        {
            _logger.debug("No SPSSODescriptor found in metadata for requestor : " 
                + saml2Requestor.getID(), e);
        }
        
        return null;
    }

}
