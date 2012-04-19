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
package com.alfaariss.oa.engine.core.idp;

import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.engine.core.idp.storage.IIDPStorage;

/**
 * IDP Storage manager.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @param <IDP> The IDP Storage type.
 * @since 1.4
 */
public class IDPStorageManager<IDP extends IIDPStorage> implements IComponent
{
    private static Log _logger;
    private Hashtable<String, IIDPStorage> _htStorages;
    private IConfigurationManager _configurationManager;
    
    /**
     * Default constructor. 
     */
    public IDPStorageManager()
    {
        _logger = LogFactory.getLog(this.getClass());
        _htStorages = new Hashtable<String, IIDPStorage>();
    }
    
    /**
     * Starts the object by reading configuration. 
     * @see com.alfaariss.oa.api.IComponent#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager configManager, Element config) throws OAException
    {
        _configurationManager = configManager;
        
        if (config != null)
        {
            Element eStorage = configManager.getSection(config, "storage");
            while (eStorage != null)
            {
                IIDPStorage storage = createStorage(configManager, eStorage);
                
                if (_htStorages.containsKey(storage.getID()))
                {
                    _logger.error("Storage id is not unique: " + storage.getID());
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
                
                _htStorages.put(storage.getID(), storage);
                
                eStorage = configManager.getNextSection(eStorage);
            }
        }

        _logger.info("IDP Storage started");
    }
    
    /**
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    public void stop()
    {
        for (IIDPStorage storage: _htStorages.values())
            storage.stop();
        
        _htStorages.clear();
    }
    
    /**
     * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
     */
    public void restart(Element config) throws OAException
    {
        synchronized(this)
        {
            stop();
            start(_configurationManager, config);
        }
    }
    
    /**
     * Returns the IDP Storage by ID. 
     * @param id The ID of the storage.
     * @return The requested storage or NULL when not available.
     */
    public IIDPStorage getStorage(String id)
    {
        return _htStorages.get(id);
    }
    
    /**
     * Returns all IDP storage ID's that are available.
     * @return An unmodifiable collection with storage ID's.
     */
    public Collection<String> getStorageIDs()
    {
        return Collections.unmodifiableCollection(_htStorages.keySet());
    }
    
    /**
     * Add an IDP storage.
     * 
     * @param storage The storage to be added.
     * @throws OAException If storage could not be added.
     */
    public void addStorage(IIDPStorage storage) throws OAException
    {
        if (_htStorages.containsKey(storage.getID()))
        {
            _logger.error("Storage id is not unique: " + storage.getID());
            throw new OAException(SystemErrors.ERROR_INIT);
        }
        
        _htStorages.put(storage.getID(), storage);
        
        _logger.info("IDP Storage added: " + storage.getID());
    }
    
    /**
     * Remove the IDP storage with the specified ID.
     * 
     * @param id The ID of the storage to be removed.
     */
    public void removeStorage(String id)
    {
        _htStorages.remove(id);
    }
    
    /**
     * Checks if a storage with the supplied ID exists. 
     * @param id The ID of the storage.
     * @return TRUE if a storage with the specified ID exists. 
     */
    public boolean existStorage(String id)
    {
        return _htStorages.containsKey(id);
    }
    
    /**
     * Returns the IDP specified by the supplied ID. 
     * <br>
     * Tries to retrieve the first IDP that matches the supplied ID in one of 
     * the storages.
     * @param id The ID of the IDP.
     * @return The IDP or <code>null</code> if none found.
     * @throws OAException  If retrieval fails.
     */
    public IIDP getIDP(String id) throws OAException
    {
        IIDP idp = null;
        
        Enumeration<IIDPStorage> enumStorages = _htStorages.elements();
        while (enumStorages.hasMoreElements())
        {
            IIDPStorage storage = enumStorages.nextElement();
            
            idp = storage.getIDP(id);
            if (idp != null)
                break;
        }
        
        return idp;
    }
    
    /**
     * Returns the IDP specified by the supplied ID where the ID has a specific type.
     * <br>
     * Tries to retrieve the first IDP that matches the supplied ID in one of 
     * the storages.
     * @param id The ID of the IDP.
     * @param type The type of ID that is supplied.
     * @return The IDP or <code>null</code> if none found.
     * @throws OAException  If retrieval fails.
     */
    public IIDP getIDP(Object id, String type) throws OAException
    {
        Enumeration<IIDPStorage> enumStorages = _htStorages.elements();
        while (enumStorages.hasMoreElements())
        {
            IIDPStorage storage = enumStorages.nextElement();
            
            IIDP idp = storage.getIDP(id, type);
            if (idp != null)
                return idp;
        }
        
        return null;
    }
    
    private IIDPStorage createStorage(IConfigurationManager configManager, 
        Element config) throws OAException
    {
        IIDPStorage storage = null;
        String sClass = null;
        try
        {
            sClass = configManager.getParam(config, "class");
            if (sClass == null)
            {
                _logger.error("No 'class' item in 'storage' section found in configuration");
                throw new OAException (SystemErrors.ERROR_CONFIG_READ);
            }
            
            Class cStorage = Class.forName(sClass);
            if (cStorage == null)
            {
                _logger.error("No class found with name: " + sClass);
                throw new OAException (SystemErrors.ERROR_CONFIG_READ);
            }
            
            storage = (IIDPStorage)cStorage.newInstance();
            
            storage.start(configManager, config);
        }
        catch (ClassNotFoundException e)
        {
            _logger.error("No class found with name: " + sClass, e);
            throw new OAException (SystemErrors.ERROR_CONFIG_READ);
        }        
        catch (ClassCastException e)
        {
            _logger.error("Configured 'class' is not an 'IIDPStorage': " + sClass, e);
            throw new OAException (SystemErrors.ERROR_CONFIG_READ);
        }
        catch (InstantiationException e)
        {
            _logger.error("Could not create instance of: " + sClass, e);
            throw new OAException (SystemErrors.ERROR_CONFIG_READ);
        }
        catch (IllegalAccessException e)
        {
            _logger.error("Illegal access when creating: " + sClass, e);
            throw new OAException (SystemErrors.ERROR_CONFIG_READ);
        }

        return storage;
    }


}
