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
package com.alfaariss.oa.engine.user.provisioning;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.engine.core.user.factory.IUserFactory;
import com.alfaariss.oa.engine.user.provisioning.storage.IStorage;
import com.alfaariss.oa.engine.user.provisioning.storage.StorageManager;
import com.alfaariss.oa.engine.user.provisioning.storage.internal.IInternalStorage;
import com.alfaariss.oa.engine.user.provisioning.translator.ITranslator;

/**
 * Provisioning factory.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.0
 */
public class ProvisioningFactory implements IUserFactory, IComponent 
{
    /** The package name */
    public static String PACKAGENAME = 
        ProvisioningFactory.class.getPackage().getName();
    
    /** Authority name */
    public final static String AUTHORITY_NAME = "UserProvisioningFactory";
    
    private Log _logger;
    private IConfigurationManager _configurationManager;
    
    private boolean _bEnabled;
    
    private ITranslator _oTranslator;
    private IInternalStorage _oInternalStorage;
    private StorageManager _oStorageManager;
    
	/**
	 * Constructor creates the object.
	 */
	public ProvisioningFactory()
    {
        _logger = LogFactory.getLog(ProvisioningFactory.class);
        _bEnabled = false;
	}

	/**
	 * Starts the object.
	 * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
	 */
	public void start(IConfigurationManager oConfigurationManager
        , Element eConfig) throws OAException
    {
	    try
        {
            _configurationManager = oConfigurationManager;
            
            _bEnabled = true;
            String sEnabled = _configurationManager.getParam(eConfig, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    _bEnabled = false;
                else if (!sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _logger.error("Unknown value in 'enabled' configuration item: " 
                        + sEnabled);
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            if (_bEnabled)
            {
                Element eMain = _configurationManager.getSection(eConfig, "main");
                if (eMain == null)
                {
                    _logger.error("No 'main' section found in configuration");
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                String sInternalStorage = _configurationManager.getParam(
                    eMain, "internalstorage");
                if(sInternalStorage == null)
                {
                    _logger.info("No (optional) 'internalstorage' parameter found in 'main' section");

                    _oInternalStorage = null;
                }
                else
                    _logger.info("Using internal storage with id: " + sInternalStorage);
    
                String sTranslator = _configurationManager.getParam(
                    eMain, "translator");
                if(sTranslator == null)
                {
                    _logger.error("No 'translator' parameter found in 'main' section");
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                Element eStorageManager = _configurationManager.getSection(
                    eConfig, "storagemanager");
                if(eStorageManager == null)
                {
                    _logger.error("No 'storagemanager' section found");
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                _oStorageManager = new StorageManager();
                _oStorageManager.start(_configurationManager, eStorageManager);
                        
                if (sInternalStorage != null)
                {
                    IStorage oStorage = _oStorageManager.getStorage(sInternalStorage);
                    if (oStorage instanceof IInternalStorage)
                        _oInternalStorage = (IInternalStorage)oStorage;
                    else
                    {
                        _logger.error(
                            "Configured internalstorage is not of type IInternalStorage: " 
                            + sInternalStorage);
                        throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                    }
                }
                
                Element eTranslator = _configurationManager.getSection(
                    eConfig, "translator"
                        , "id=" + sTranslator);
                if(eTranslator == null)
                {
                    _logger.error("No 'translator' section found with id: " 
                        + sTranslator);
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
                            
                String sTranslatorClass = _configurationManager.getParam(
                    eTranslator, "class");
                if(sTranslatorClass == null)
                {
                    _logger.error(
                        "No 'class' parameter found in 'translator' section with id: " 
                        + sTranslator);
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
    
                if (sTranslatorClass.startsWith("."))
                    sTranslatorClass = PACKAGENAME + sTranslatorClass;
                
                Class oTranslatorClass = null;
                try
                {
                    oTranslatorClass = Class.forName(sTranslatorClass);
                }
                catch (Exception e)
                {
                    _logger.error("No 'class' found with name: " 
                        + sTranslatorClass, e);
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                try
                {
                    _oTranslator = (ITranslator)oTranslatorClass.newInstance();
                }
                catch (Exception e)
                {
                    _logger.error(
                        "Could not create an 'IInternalStorage' instance of the configured 'class' found with name: " 
                        + sTranslatorClass, e);
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                _oTranslator.start(_configurationManager, eTranslator, 
                    _oStorageManager, _oInternalStorage);
            }
        }
        catch (UserException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialize", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
	}

	/**
	 * Restarts the object.
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
     * Stops the object.
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    public void stop()
    {
        _bEnabled = false;
        
        if (_oTranslator != null)
            _oTranslator.stop();
        
        if (_oStorageManager != null)
            _oStorageManager.stop();
    }

	/**
	 * Returns TRUE if the object is enabled.
	 * @see com.alfaariss.oa.api.IOptional#isEnabled()
	 */
	public boolean isEnabled()
    {
		return _bEnabled;
	}

	/**
	 * Returns the user.
	 * @see IUserFactory#getUser(java.lang.String)
	 */
	public IUser getUser(String sID) throws UserException
    {
        ProvisioningUser oProvisioningUser = null;
        try
        {
            if (_oTranslator == null)
            {
                _logger.error("No translator object available");
                throw new UserException(SystemErrors.ERROR_NOT_INITIALIZED);
            }
            oProvisioningUser = _oTranslator.translate(sID);
        }
        catch (UserException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Could not retrieve user with id: " + sID, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        return oProvisioningUser;
	}
}