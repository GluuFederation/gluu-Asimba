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
import com.alfaariss.oa.engine.requestor.configuration.ConfigurationFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.gluu.asimba.util.ldap.LDAPUtility;
import org.gluu.asimba.util.ldap.sp.RequestorPoolEntry;

/**
 * The requestor pool factory.
 *
 * Reads factory information from LDAP items.
 *
 * @author Dmitry Ognyannikov
 */
public class LDAPFactory extends ConfigurationFactory {

    private static final Log _logger = LogFactory.getLog(LDAPFactory.class);

    private HashMap<String, RequestorPool> _mapPools;
    private HashMap<String, IRequestor> _mapRequestors;

    /**
     * Creates the object.
     */
    public LDAPFactory() {
        _mapPools = new HashMap<>();
        _mapRequestors = new HashMap<>();
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
        return super.getRequestorPool(sRequestor);
    }

    /**
     * Returns the requestor specified by its ID.
     *
     * @see
     * com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getRequestor(java.lang.String)
     */
    @Override
    public IRequestor getRequestor(String sRequestor) throws RequestorException {
        if (_mapRequestors.containsKey(sRequestor)) {
            return _mapRequestors.get(sRequestor);
        } else {
            return super.getRequestor(sRequestor);
        }
    }

    /**
     * @see
     * com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#isPool(java.lang.String)
     */
    @Override
    public boolean isPool(String sPoolID) {
        return _mapPools.containsKey(sPoolID) || super.isPool(sPoolID);
    }

    /**
     * Starts the component.
     *
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void start(IConfigurationManager oConfigurationManager, Element eConfig) throws OAException {
        super.start(oConfigurationManager, eConfig);
        
        try {
            HashMap<String, RequestorPool> pools = new HashMap<>();
            HashMap<String, IRequestor> requestors = new HashMap<>();

            // load LDAP pools
            List<RequestorPoolEntry> poolEntries = LDAPUtility.loadRequestorPools();

            for (RequestorPoolEntry entry : poolEntries) {
                try {
                    String entityId = entry.getId();

                    if (!entry.isEnabled()) {
                        _logger.info("RequestorPool is disabled. Id: " + entityId + ", friendlyName: " + entry.getFriendlyName());
                        continue;
                    }

                    if (pools.containsKey(entityId)) {
                        _logger.error("Dublicated RequestorPool. Id: " + entityId + ", friendlyName: " + entry.getFriendlyName());
                        continue;
                    }

                    _logger.info("RequestorPool loaded. Id: " + entityId + ", friendlyName: " + entry.getFriendlyName());

                    RequestorPool oRequestorPool = new LDAPRequestorPool(entry);

                    // add pool
                    pools.put(oRequestorPool.getID(), oRequestorPool);
                    _logger.info("RequestorPool has been loded to LDAPFactory, id: " + entry.getId());

                    // add pool's requestors
                    Set<IRequestor> poolRequestors = oRequestorPool.getRequestors();
                    for (IRequestor requestor : poolRequestors) {
                        if (!requestor.isEnabled()) {
                            _logger.info("Requestor is disabled. Id: " + requestor.getID() + ", friendlyName: " + requestor.getFriendlyName());
                        }

                        if (requestors.containsKey(requestor.getID())) {
                            _logger.info("Dublicated Requestor. Id: " + requestor.getID() + ", friendlyName: " + requestor.getFriendlyName());
                        }
                        
                        _logger.info("Requestor has been registered to LDAPRequestorPool, id: " + requestor.getID());
                        requestors.put(requestor.getID(), requestor);
                    }
                } catch (Exception e) {
                    _logger.error("LDAPFactory Internal error while reading requestor pool: " + entry.getId());
                }
            }              

            _mapPools = pools;
            _mapRequestors = requestors;
        } catch (Exception e) {
            _logger.fatal("Internal error during initialization from LDAP settings", e);
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
        super.restart(eConfig);
    }

    /**
     * Stops the component.
     *
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    @Override
    public void stop() {
        super.stop();
        
        if (_mapPools != null) {
            _mapPools.clear();
        }

        if (_mapRequestors != null) {
            _mapRequestors.clear();
        }
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
        
        Collection<RequestorPool> parentPools = super.getAllEnabledRequestorPools();
        if (parentPools != null)
            for (RequestorPool pool : parentPools) {
                if (pool.isEnabled() && !_mapPools.containsKey(pool.getID())) {
                    collPools.add(pool);
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
        Collection<RequestorPool> collPools = new ArrayList<>();
        if (_mapPools != null) {
            for (RequestorPool pool : _mapPools.values()) {
                    collPools.add(pool);
            }
        }
        
        Collection<RequestorPool> parentPools = super.getAllEnabledRequestorPools();
        if (parentPools != null)
            for (RequestorPool pool : parentPools) {
                if (!_mapPools.containsKey(pool.getID())) {
                    collPools.add(pool);
                }
            }
        
        return Collections.unmodifiableCollection(collPools);
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
        
        Collection<IRequestor> parentRequestors = super.getAllEnabledRequestors();
        if (parentRequestors != null)
            for (IRequestor requestor : parentRequestors) {
                if (requestor.isEnabled() && !_mapRequestors.containsKey(requestor.getID())) {
                    collRequestors.add(requestor);
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
        Collection<IRequestor> collRequestors = new ArrayList<>();
        if (_mapRequestors != null) {
            for (IRequestor requestor : _mapRequestors.values()) {
                collRequestors.add(requestor);
            }
        }
        
        Collection<IRequestor> parentRequestors = super.getAllEnabledRequestors();
        if (parentRequestors != null)
            for (IRequestor requestor : parentRequestors) {
                if (!_mapRequestors.containsKey(requestor.getID())) {
                    collRequestors.add(requestor);
                }
            }
        
        return Collections.unmodifiableCollection(collRequestors);
    }

    /**
     * @see
     * com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#isRequestor(java.lang.String)
     */
    @Override
    public boolean isRequestor(String requestorID) throws RequestorException {
        if (_mapRequestors != null)
            return _mapRequestors.containsKey(requestorID) || super.isRequestor(requestorID);
        else
            return super.isRequestor(requestorID);
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

        return super.getRequestor(id, type);
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

        return super.isRequestorIDSupported(type);
    }

}
