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
package com.alfaariss.oa.engine.user.provisioning.translator.standard;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.engine.user.provisioning.ProvisioningFactory;
import com.alfaariss.oa.engine.user.provisioning.ProvisioningUser;
import com.alfaariss.oa.engine.user.provisioning.storage.IStorage;
import com.alfaariss.oa.engine.user.provisioning.storage.StorageManager;
import com.alfaariss.oa.engine.user.provisioning.storage.external.IExternalStorage;
import com.alfaariss.oa.engine.user.provisioning.storage.internal.IInternalStorage;
import com.alfaariss.oa.engine.user.provisioning.translator.ITranslator;
import com.alfaariss.oa.engine.user.provisioning.translator.profile.IProfile;
import com.alfaariss.oa.util.logging.UserEventLogItem;

/**
 * The standard translator object that creates a user.
 * <br>
 * Based on his existence in the external storage.
 * @author MHO
 * @author Alfa & Ariss
 */
public class StandardTranslator implements ITranslator, IAuthority
{   
    /** The eventlogger name. */
    public static final String EVENT_LOGGER = 
        "com.alfaariss.oa.UserProvisioningEventLogger";
    
    private static String PACKAGENAME = 
        StandardTranslator.class.getPackage().getName();
    private Log _logger;
    private Log _eventLogger;
    private IInternalStorage _oInternalStorage; 
    private IExternalStorage _oExternalStorage;
    private IProfile _oProfile;
    private String _sOrganizationID;
    
	/**
	 * Creates the standard translator object.
	 */
	public StandardTranslator()
    {
        _logger = LogFactory.getLog(StandardTranslator.class);
        _eventLogger = LogFactory.getLog(EVENT_LOGGER);
	}

	/**
	 * Starts the object.
	 * @see ITranslator#start(IConfigurationManager, org.w3c.dom.Element, 
     *  StorageManager, IInternalStorage)
	 */
	public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig, StorageManager oStorageManager, 
        IInternalStorage oInternalStorage) throws UserException
    {
        try
        {
            _oInternalStorage = oInternalStorage;
            
            Element eMain = oConfigurationManager.getSection(eConfig, "main");
            if(eMain == null)
            {
                _logger.error("No 'main' section found in configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sExternalStorage = oConfigurationManager.getParam(
                eMain, "externalstorage");
            if(sExternalStorage == null)
            {
                _logger.error(
                    "No 'externalstorage' parameter found in 'main' section");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            _logger.info("Using external storage with id: " + sExternalStorage);

            IStorage oStorage = oStorageManager.getStorage(sExternalStorage);
            if (oStorage instanceof IExternalStorage)
            {
                _oExternalStorage = (IExternalStorage)oStorage;
            }
            else
            {
                _logger.error(
                    "Configured externalstorage is not of type IExternalStorage: " 
                    + sExternalStorage);
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sProfile = null;
            try
            {
                sProfile = oConfigurationManager.getParam(eMain, "profile");
            }
            catch(Exception e)
            {
                _logger.fatal("No 'profile' parameter found in 'main' section");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eProfile = oConfigurationManager.getSection(eConfig
                    , "profile", "id=" + sProfile);
            if (eProfile == null)
            {
                StringBuffer sbError = new StringBuffer(
                    "No 'profile' section found with id '");
                sbError.append(sProfile);
                sbError.append("' in 'translator' section");
                
                _logger.error(sbError.toString());
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sProfileClass = oConfigurationManager.getParam(
                eProfile, "class");
            if(sProfileClass == null)
            {
                _logger.error(
                    "No 'class' parameter found in 'profile' section with id: " 
                    + sProfile);
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            if (sProfileClass.startsWith("."))
                sProfileClass = PACKAGENAME + sProfileClass;
            
            Class oProfileClass = null;
            try
            {
                oProfileClass = Class.forName(sProfileClass);
            }
            catch (Exception e)
            {
                _logger.error("No 'class' found with name: " + sProfileClass, e);
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            try
            {
                _oProfile = (IProfile)oProfileClass.newInstance();
            }
            catch (Exception e)
            {
                _logger.error(
                    "Could not create an 'IProfile' instance of the configured 'class' found with name: " 
                    + sProfileClass, e);
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _sOrganizationID = Engine.getInstance().getServer().getOrganization().getID();
            
            _oProfile.start(oConfigurationManager, eProfile, _oExternalStorage);            
        }
        catch (UserException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not initialize object", e);
            throw new UserException(SystemErrors.ERROR_CONFIG_READ);
        }
	}

	/**
     * Translates the user object by his existence in the external storage.
     * <br>
     * Adds a user in the internal storage if he exists in the external 
     * storage and not yet exist in the internal storage. Removes a user from 
     * the internal storage if he doesn't exist in the external storage.
     * <br><br>
     * Returns the user object or <code>null</code> if user not found.
	 * @see ITranslator#translate(java.lang.String)
	 */
	public ProvisioningUser translate(String sUserID) throws UserException
    {
        ProvisioningUser oInternalUser = null;
        ProvisioningUser oExternalUser = null;
        try
        {
            if (!_oExternalStorage.exists(sUserID))
            {
                if (_oInternalStorage != null && _oInternalStorage.exists(sUserID))
                {
                    _oInternalStorage.remove(sUserID);
                    
                    _eventLogger.info(new UserEventLogItem(null, null, 
                        SessionState.AUTHN_IN_PROGRESS, UserEvent.USER_REMOVED, 
                        sUserID, _sOrganizationID, null, null, this, null));
                    
                    _logger.debug("User removed from internal storage: " + sUserID);
                }
                return null; //no user found
            }
            
            oExternalUser = _oProfile.getUser(_sOrganizationID, sUserID);
            
            if (_oInternalStorage == null)
            {//no internal user db configured, so external db is leading
                oInternalUser = oExternalUser;
            }
            else if (_oInternalStorage.exists(sUserID))
            {
                _oInternalStorage.update(oExternalUser);
                
                _eventLogger.info(new UserEventLogItem(null, null, 
                    SessionState.AUTHN_IN_PROGRESS, UserEvent.USER_UPDATED, 
                    sUserID, _sOrganizationID, null, null, this, null));
                
                oInternalUser = _oInternalStorage.getUser(_sOrganizationID, sUserID);
            }
            else
            {
                oInternalUser = new ProvisioningUser(
                    _sOrganizationID, sUserID, oExternalUser.isEnabled());
                
                for (String sMethod: oExternalUser.getAuthenticationMethods())
                    oInternalUser.putRegistered(
                        sMethod, oExternalUser.isAuthenticationRegistered(sMethod));
                
                _oInternalStorage.add(oInternalUser);
                
                _eventLogger.info(new UserEventLogItem(null, null, 
                    SessionState.AUTHN_IN_PROGRESS, UserEvent.USER_ADDED, 
                    sUserID, _sOrganizationID, null, null, this, null));
            }
        }
        catch (UserException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not translate user information for user with id: " 
                + sUserID, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        
        return oInternalUser;
	}

    /**
     * Stops the translator object.
     * @see com.alfaariss.oa.engine.user.provisioning.translator.ITranslator#stop()
     */
    public void stop()
    {
        if (_oExternalStorage != null)
            _oExternalStorage.stop();
    }
    
    /**
     * @see com.alfaariss.oa.api.logging.IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return ProvisioningFactory.AUTHORITY_NAME;
    }
}