/*
 * Asimba Server
 * 
 * Copyright (c) 2015, Gluu
 * Copyright (C) 2013 Asimba
 * Copyright (C) 2007-2008 Alfa & Ariss B.V.
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
 * gluu-Asimba - Serious Open Source SSO - More information on www.gluu.org
 * 
 */
package org.gluu.asimba.engine.requestor.ldap;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.requestor.RequestorException;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import org.gluu.asimba.util.ldap.LDAPUtility;
import org.gluu.site.ldap.LDAPConnectionProvider;
import org.gluu.site.ldap.OperationsFacade;
import org.gluu.site.ldap.persistence.LdapEntryManager;
import org.gluu.asimba.util.ldap.sp.LDAPRequestorPoolEntry;

/**
 * The requestor pool factory.
 *
 * Reads factory information from LDAP items.
 *
 * @author Dmitry Ognyannikov
 */
public class LDAPFactory implements IRequestorPoolFactory, IComponent {

    private static Log _logger;
    private IConfigurationManager _configurationManager;
    private Element _eConfig;

    private HashMap<String, RequestorPool> _mapPools;
    private HashMap<String, IRequestor> _mapRequestors;

    /**
     * Creates the object.
     */
    public LDAPFactory() {
        _logger = LogFactory.getLog(LDAPFactory.class);
        _mapPools = new HashMap<>();
        _mapRequestors = new HashMap<>();
        _eConfig = null;
    }

    /**
     * Returns the requestor pool were the supplied request id is part of.
     *
     * @see IRequestorPoolFactory#getRequestorPool(java.lang.String)
     */
    @Override
    public RequestorPool getRequestorPool(String sRequestor) throws RequestorException {
        for (RequestorPool oRequestorPool : _mapPools.values()) {
            if (oRequestorPool.existRequestor(sRequestor)) {
                return oRequestorPool;
            }
        }
        return null;
    }

    /**
     * Returns the requestor specified by its ID.
     *
     * @see
     * com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getRequestor(java.lang.String)
     */
    @Override
    public IRequestor getRequestor(String sRequestor) throws RequestorException {
        return _mapRequestors.get(sRequestor);
    }

    /**
     * @see
     * com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#isPool(java.lang.String)
     */
    @Override
    public boolean isPool(String sPoolID) {
        if (_mapPools != null) {
            return _mapPools.containsKey(sPoolID);
        }

        return false;
    }

    /**
     * Starts the component.
     *
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void start(IConfigurationManager oConfigurationManager, Element eConfig) throws OAException {
        try {
            _configurationManager = oConfigurationManager;
            _eConfig = eConfig;
            
            final LdapEntryManager ldapEntryManager = LDAPUtility.getLDAPEntryManager();

            try {
                HashMap<String, RequestorPool> pools = new HashMap<>();
                HashMap<String, IRequestor> requestors = new HashMap<>();
                
                final LDAPRequestorPoolEntry template = new LDAPRequestorPoolEntry();
                List<LDAPRequestorPoolEntry> entries = ldapEntryManager.findEntries(template);
                
                // load LDAP entries
                for (LDAPRequestorPoolEntry entry : entries) {

                    String entityId = entry.getId();

                    if (!entry.getEntry().isEnabled()) {
                        _logger.info("RequestorPool is disabled. Id: " + entityId + ", friendlyName: " + entry.getEntry().getFriendlyName());
                        continue;
                    }

                    if (pools.containsKey(entityId)) {
                        _logger.error("Dublicated RequestorPool. Id: " + entityId + ", friendlyName: " + entry.getEntry().getFriendlyName());
                        continue;
                    }
                    
                    //TODO: convert JSON to List<String> _listAuthenticationProfileIDs
                    List<String> authenticationProfileIDs = new ArrayList<>();
                    //TODO: convert JSON to Set<IRequestor> _setRequestors
                    Set<IRequestor> poolRequestors = new HashSet<>();
                    
                    for (IRequestor requestor : poolRequestors)
                        requestors.put(requestor.getID(), requestor);
                    
                    _logger.info("RequestorPool loaded. Id: " + entityId + ", friendlyName: " + entry.getEntry().getFriendlyName());
                    
                    RequestorPool oRequestorPool = new RequestorPool(entry.getId(), entry.getEntry().getFriendlyName(), entry.getEntry().isEnabled(), entry.getEntry().isForcedAuthenticate(), 
                            entry.getEntry().getPreAuthorizationProfileID(), entry.getEntry().getPostAuthorizationProfileID(), entry.getEntry().getAttributeReleasePolicyID(), 
                            poolRequestors, authenticationProfileIDs);
                    pools.put(oRequestorPool.getID(), oRequestorPool);
                    
                }
                
                _mapPools = pools;
                _mapRequestors = requestors;
            } catch (Exception e) {
                _logger.error("cannot load LDAP settings", e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            } finally {
                ldapEntryManager.destroy();
            }
        } catch (RequestorException e) {
            _logger.error("Internal error during initialization", e);
            throw e;
        } catch (Exception e) {
            _logger.fatal("Internal error during initialization", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Restarts the component.
     *
     * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
     */
    @Override
    public void restart(Element eConfig) throws OAException {
        synchronized (this) {
            stop();
            start(_configurationManager, eConfig);
        }
    }

    /**
     * Stops the component.
     *
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    @Override
    public void stop() {
        if (_mapPools != null) {
            _mapPools.clear();
        }

        if (_mapRequestors != null) {
            _mapRequestors.clear();
        }

        _eConfig = null;
    }

    /**
     * @see
     * com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getAllEnabledRequestorPools()
     */
    @Override
    public Collection<RequestorPool> getAllEnabledRequestorPools()
            throws RequestorException {
        Collection<RequestorPool> collPools = new ArrayList<>();
        if (_mapPools != null) {
            for (RequestorPool pool : _mapPools.values()) {
                if (pool.isEnabled()) {
                    collPools.add(pool);
                }
            }
        }
        return Collections.unmodifiableCollection(collPools);
    }

    /**
     * @see
     * com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getAllRequestorPools()
     */
    @Override
    public Collection<RequestorPool> getAllRequestorPools() throws RequestorException {
        if (_mapPools == null) 
            return Collections.unmodifiableCollection(new ArrayList<RequestorPool>());
        else
            return Collections.unmodifiableCollection(_mapPools.values());
    }

    /**
     * @see
     * com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getAllEnabledRequestors()
     */
    @Override
    public Collection<IRequestor> getAllEnabledRequestors() throws RequestorException {
        Collection<IRequestor> collRequestors = new ArrayList<>();
        if (_mapRequestors != null) {
            for (IRequestor requestor : _mapRequestors.values()) {
                if (requestor.isEnabled()) {
                    collRequestors.add(requestor);
                }
            }
        }
        return Collections.unmodifiableCollection(collRequestors);
    }

    /**
     * @see
     * com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getAllRequestors()
     */
    @Override
    public Collection<IRequestor> getAllRequestors() throws RequestorException {
        if (_mapRequestors == null) 
            return Collections.unmodifiableCollection(new ArrayList<IRequestor>());
        else
            return Collections.unmodifiableCollection(_mapRequestors.values());
    }

    /**
     * @see
     * com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#isRequestor(java.lang.String)
     */
    @Override
    public boolean isRequestor(String requestorID) throws RequestorException {
        if (_mapRequestors != null)
            return _mapRequestors.containsKey(requestorID);
        else
            return false;
    }

    /**
     * @see
     * com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getRequestor(java.lang.Object,
     * java.lang.String)
     */
    @Override
    public IRequestor getRequestor(Object id, String type)
            throws RequestorException {
        for (IRequestor requestor : _mapRequestors.values())
            if (requestor.isProperty(type) && id.equals(requestor.getProperty(type)))
                return requestor;

        return null;
    }

    /**
     * @see
     * com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#isRequestorIDSupported(java.lang.String)
     */
    @Override
    public boolean isRequestorIDSupported(String type)
            throws RequestorException {
        // The requestor ID type is supported if the type is available as param within a requestor
        
        for (IRequestor requestor : _mapRequestors.values())
            if (requestor.isProperty(type))
                return true;

        return false;
    }

}
