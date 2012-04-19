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
package com.alfaariss.oa.engine.requestor.configuration;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.requestor.RequestorException;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;

/**
 * The requestor pool factory.
 *
 * Reads factory information from configuration items.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ConfigurationFactory implements IRequestorPoolFactory, IComponent 
{
    private static Log _logger;
    private IConfigurationManager _configurationManager;
    private Element _eConfig;
    
    private HashMap<String, RequestorPool> _mapPools;
    private HashMap<String, IRequestor> _mapRequestors;
    
	/**
	 * Creates the object.
	 */
	public ConfigurationFactory()
    {
        _logger = LogFactory.getLog(ConfigurationFactory.class);
        _mapPools = new HashMap<String, RequestorPool>();
        _mapRequestors = new HashMap<String, IRequestor>();
        _eConfig = null;
	}

    /**
     * Returns the requestor pool were the supplied request id is part of.
     * @see IRequestorPoolFactory#getRequestorPool(java.lang.String)
     */
    public RequestorPool getRequestorPool(String sRequestor) throws RequestorException
    {
        for (RequestorPool oRequestorPool:_mapPools.values())
        {
            if (oRequestorPool.existRequestor(sRequestor))
                return oRequestorPool;
        }
        return null;
    }

    /**
     * Returns the requestor specified by its ID.
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getRequestor(java.lang.String)
     */
    public IRequestor getRequestor(String sRequestor) throws RequestorException
    {
        return _mapRequestors.get(sRequestor);
    }

    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#isPool(java.lang.String)
     */
    public boolean isPool(String sPoolID)
    {
        if (_mapPools != null)
            return _mapPools.containsKey(sPoolID);
    
        return false;
    }

    /**
     * Starts the component.
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager, Element eConfig) throws OAException
    {
        try
        {
            _configurationManager = oConfigurationManager;
            _eConfig = eConfig;
            Element ePool = _configurationManager.getSection(eConfig, "pool");
            while (ePool != null)
            {
                RequestorPool oRequestorPool = new ConfigurationPool(_configurationManager, ePool);
                
                for (IRequestor oRequestor: oRequestorPool.getRequestors())
                {
                    if (_mapRequestors.containsKey(oRequestor.getID()))
                    {
                        StringBuffer sbError = new StringBuffer("Duplicate entry for requestor with id '");
                        sbError.append(oRequestor.getID());
                        sbError.append("' in pool: ");
                        sbError.append(oRequestorPool.getID());
                        _logger.error(sbError.toString());
                        
                        throw new RequestorException(SystemErrors.ERROR_INIT);
                    }
                    _mapRequestors.put(oRequestor.getID(), oRequestor);
                }
                
                if (_mapPools.containsKey(oRequestorPool.getID()))
                {

                    _logger.error("Duplicate entry for requestorpool with id: " 
                        + oRequestorPool.getID());
                    throw new RequestorException(SystemErrors.ERROR_INIT);
                }
                
                _mapPools.put(oRequestorPool.getID(), oRequestorPool);
                ePool = _configurationManager.getNextSection(ePool);
            }
            
        }
        catch(RequestorException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Restarts the component.
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
     * Stops the component.
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    public void stop()
    {
        if (_mapPools != null)
            _mapPools.clear();
        
        if (_mapRequestors != null)
            _mapRequestors.clear();
        
        _eConfig = null;
    }

    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getAllEnabledRequestorPools()
     */
    public Collection<RequestorPool> getAllEnabledRequestorPools()
        throws RequestorException
    {
        Collection<RequestorPool> collPools = new Vector<RequestorPool>();
        if (_mapPools != null)
        {
            for (RequestorPool pool: _mapPools.values())
            {
                if (pool.isEnabled())
                    collPools.add(pool);
            }
        }
        return Collections.unmodifiableCollection(collPools);
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getAllRequestorPools()
     */
    public Collection<RequestorPool> getAllRequestorPools() throws RequestorException
    {
        if (_mapPools == null)
            return Collections.unmodifiableCollection(new Vector<RequestorPool>());
        
        return Collections.unmodifiableCollection(_mapPools.values());
    }

    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getAllEnabledRequestors()
     */
    public Collection<IRequestor> getAllEnabledRequestors() throws RequestorException
    {
        Collection<IRequestor> collRequestors = new Vector<IRequestor>();
        if (_mapRequestors != null)
        {
            for (IRequestor requestor: _mapRequestors.values())
            {
                if (requestor.isEnabled())
                    collRequestors.add(requestor);
            }
        }
        return Collections.unmodifiableCollection(collRequestors);
    }

    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getAllRequestors()
     */
    public Collection<IRequestor> getAllRequestors() throws RequestorException
    {
        if (_mapRequestors == null)
            return Collections.unmodifiableCollection(new Vector<IRequestor>());
        
        return Collections.unmodifiableCollection(_mapRequestors.values());
    }

    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#isRequestor(java.lang.String)
     */
    public boolean isRequestor(String requestorID) throws RequestorException
    {
        if (_mapRequestors != null)
            return _mapRequestors.containsKey(requestorID);
    
        return false;
    }

    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getRequestor(java.lang.Object, java.lang.String)
     */
    public IRequestor getRequestor(Object id, String type)
        throws RequestorException
    {
        try
        {
            Element ePool = _configurationManager.getSection(_eConfig, "pool");
            while (ePool != null)
            {
                Element eRequestors = _configurationManager.getSection(ePool, "requestors");
                if (eRequestors != null)
                {
                    Element eRequestor = _configurationManager.getSection(eRequestors, "requestor");
                    while (eRequestor != null)
                    {
                        String sType = _configurationManager.getParam(eRequestor, type);
                        if (sType != null && sType.equals(String.valueOf(id)))
                        {
                            String sID = _configurationManager.getParam(eRequestor, "id");
                            if (sID != null)
                            {
                                return _mapRequestors.get(sID);
                            }
                        }
                        
                        eRequestor = _configurationManager.getNextSection(eRequestor);
                    }
                }
                
                ePool = _configurationManager.getNextSection(ePool);
            }
            return null;
        }
        catch (ConfigurationException e)
        {
            throw new RequestorException(SystemErrors.ERROR_CONFIG_READ);
        }
    }

    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#isRequestorIDSupported(java.lang.String)
     */
    public boolean isRequestorIDSupported(String type)
        throws RequestorException
    {//DD The requestor ID type is supported if the type is available as configuration param within a requestor section
        try
        {
            Element ePool = _configurationManager.getSection(_eConfig, "pool");
            while (ePool != null)
            {
                Element eRequestors = _configurationManager.getSection(ePool, "requestors");
                if (eRequestors != null)
                {
                    Element eRequestor = _configurationManager.getSection(eRequestors, "requestor");
                    while (eRequestor != null)
                    {
                        String sType = _configurationManager.getParam(eRequestor, type);
                        if (sType != null)
                        {
                            return true;
                        }
                        
                        eRequestor = _configurationManager.getNextSection(eRequestor);
                    }
                }
                
                ePool = _configurationManager.getNextSection(ePool);
            }
        }
        catch (ConfigurationException e)
        {
            throw new RequestorException(SystemErrors.ERROR_CONFIG_READ);
        }

        return false;
    }

}