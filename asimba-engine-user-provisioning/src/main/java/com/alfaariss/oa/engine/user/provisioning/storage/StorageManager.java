/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
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
 * Asimba - Serious Open Source SSO - More information on www.asimba.org
 * 
 */
package com.alfaariss.oa.engine.user.provisioning.storage;

import java.util.Enumeration;
import java.util.Hashtable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.user.UserException;

/**
 * Storage manager.
 *
 * Manages classes that implement the IStorage interface.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class StorageManager
{   
    private static String PACKAGENAME = StorageManager.class.getPackage().getName();
    private Log _logger;
    private Hashtable<String, IStorage> _htStorages;
    
    /**
     * Creates the object.
     */
    public StorageManager ()
    {
        _logger = LogFactory.getLog(StorageManager.class);
        _htStorages = new Hashtable<String, IStorage>();
    }
    
    /**
     * Starts the object.
     * <br>
     * Reads the configured storages. 
     * @param oConfigurationManager the configuration manager
     * @param eConfig the configuration section containing the configuration of 
     * this object
     * @throws UserException if starting fails
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws UserException
    {
        try
        {
            Element eStorage = oConfigurationManager.getSection(eConfig, "storage");
            if (eStorage == null)
            {
                _logger.error("Not one 'storage' section found in configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            while (eStorage != null)
            {
                String sStorageID = oConfigurationManager.getParam(eStorage, "id");
                if (sStorageID == null)
                {
                    _logger.error("No 'id' parameter found in 'storage' section");
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                if (_htStorages.containsKey(sStorageID))
                {
                    StringBuffer sbError = new StringBuffer("The storage with id '");
                    sbError.append(sStorageID);
                    sbError.append("' is not unique");
                    
                    _logger.error(sbError.toString());
                    
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                String sStorageClass = oConfigurationManager.getParam(eStorage, "class");
                if (sStorageClass == null)
                {
                    _logger.error("No 'class' parameter found in 'storage' section with id: " 
                        + sStorageID);
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                if (sStorageClass.startsWith("."))
                    sStorageClass = PACKAGENAME + sStorageClass;
                
                Class oStorageClass = null;
                try
                {
                    oStorageClass = Class.forName(sStorageClass);
                }
                catch (Exception e)
                {
                    _logger.error("No 'class' found with name: " + sStorageClass, e);
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                IStorage oStorage = null;
                try
                {
                    oStorage = (IStorage)oStorageClass.newInstance();
                }
                catch (Exception e)
                {
                    _logger.error("Could not create an 'IStorage' instance of the configured 'class' found with name: " 
                        + sStorageClass, e);
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                oStorage.start(oConfigurationManager, eStorage);
                
                _htStorages.put(sStorageID, oStorage);
                
                eStorage = oConfigurationManager.getNextSection(eStorage);
            }
        }
        catch (UserException e)
        {
            stop();
            throw e;
        }
        catch(Exception e)
        {
            stop();
            _logger.fatal("Could not initialize object", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Returns the storage object for the supplied id.
     * @param sID storage id
     * @return the storage object
     */
    public IStorage getStorage(String sID)
    {
        return _htStorages.get(sID); 
    }
    
    /**
     * Stops the storage manager.
     * <br>
     * Stops all storages that this manager manages. 
     */
    public void stop()
    {
        Enumeration enumStorages = _htStorages.elements();
        while (enumStorages.hasMoreElements())
        {
            IStorage oStorage = (IStorage)enumStorages.nextElement();
            if (oStorage != null)
                oStorage.stop();
        }
        _htStorages.clear();
    }

}
