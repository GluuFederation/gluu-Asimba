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
package com.alfaariss.oa.engine.user.provisioning.translator.standard;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.engine.user.provisioning.ProvisioningUser;
import com.alfaariss.oa.engine.user.provisioning.storage.external.IExternalStorage;
import com.alfaariss.oa.engine.user.provisioning.translator.profile.IProfile;
import com.alfaariss.oa.engine.user.provisioning.translator.standard.common.ProfileItem;
import com.alfaariss.oa.engine.user.provisioning.translator.standard.converter.ConverterManager;
import com.alfaariss.oa.engine.user.provisioning.translator.standard.converter.IConverter;

/**
 * The simple profile class.
 *
 * Creates a user object by converting fields from an external storage.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class StandardProfile implements IProfile
{
    private Log _logger;
    private ConverterManager _oConverterManager;
    private IExternalStorage _oExternalStorage;
    private ProfileItem _itemEnabled;
    private Hashtable<String, ProfileItem> _htProfile;
    private Vector<String> _vAllFields;
        
    /**
     * Creates the object.
     */
    public StandardProfile()
    {
        _logger = LogFactory.getLog(StandardProfile.class);
        _htProfile = new Hashtable<String, ProfileItem>();
    }

    /**
     * Starts the object.
     * @see IProfile#start(
     *  IConfigurationManager, org.w3c.dom.Element, IExternalStorage)
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig, IExternalStorage oExternalStorage) throws UserException
    {
        try
        {
            _oExternalStorage = oExternalStorage;
            
            Element eConverterManager = oConfigurationManager.getSection(
                eConfig, "convertermanager");
            if (eConverterManager == null)
                _logger.info(
                    "Disabled converter manager: No 'convertermanager' section found");
            else
                _oConverterManager = new ConverterManager(
                    oConfigurationManager, eConverterManager);
            
            Element eAccount = oConfigurationManager.getSection(
                eConfig, "account");
            if (eAccount == null)
            {
                _logger.error(
                    "No 'account' section found in 'profile' section");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eEnabled = oConfigurationManager.getSection(
                eAccount, "enabled");
            if (eEnabled == null)
            {
                _logger.error("No 'enabled' section found in 'account' section");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            _itemEnabled = new ProfileItem(
                oConfigurationManager, eEnabled, _oConverterManager);
            
            Element eAuthentication = oConfigurationManager.getSection(
                eAccount, "authentication");
            if (eAuthentication == null)
            {
                _logger.error(
                    "No 'authentication' section found in 'profile' section in configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eMethod = oConfigurationManager.getSection(
                eAuthentication, "method");
            if (eMethod == null)
            {
                _logger.error(
                    "Not even one 'method' section found in 'authentication' section configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            while (eMethod != null)
            {
                String sID = oConfigurationManager.getParam(eMethod, "id");
                if (sID == null)
                {
                    _logger.error(
                        "No 'id' param found in 'method' section configuration");
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                Element eRegistered = oConfigurationManager.getSection(
                    eMethod, "registered");
                if (eRegistered == null)
                {
                    _logger.error("No 'registered' section found in 'method' section");
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
                ProfileItem itemRegistered = new ProfileItem(
                    oConfigurationManager, eRegistered, _oConverterManager);
                
                if (_htProfile.containsKey(sID))
                {
                    StringBuffer sbWarning = new StringBuffer(
                        "Configured method with id '");
                    sbWarning.append(sID);
                    sbWarning.append("' is not unique");
                    _logger.error(sbWarning.toString());
                    throw new UserException(SystemErrors.ERROR_INIT);
                }
                
                _htProfile.put(sID, itemRegistered);
                
                eMethod = oConfigurationManager.getNextSection(eMethod);
            }
            
            _vAllFields = getAllFields();
        }
        catch (UserException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not initialize object", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Returns the user object.
     * (Wrapper for getUser(IExternalStorage, String, String))
     * @see IProfile#getUser(java.lang.String, java.lang.String)
     */
    public ProvisioningUser getUser(
        String sOrganization, String id) throws UserException
    {
    	return getUser(_oExternalStorage, sOrganization, id);
    }
    
    /**
     * Returns the user object, using the provided ExternalStorage
     * as userstore
     */
    public ProvisioningUser getUser(IExternalStorage oExternalStorage,
        String sOrganization, String id) throws UserException
    {
        ProvisioningUser oProvisioningUser = null;
        try
        {
            Hashtable<String, Object> htFields = oExternalStorage.getFields(
                id, _vAllFields);
            
            Boolean boolEnabled = (Boolean)getValue(_itemEnabled, htFields);
            oProvisioningUser = new ProvisioningUser(
                sOrganization, id, boolEnabled);
            
            /* 2011/03/10; dopey adds: */ 
            // Remember fetched attributes from _itemEnabled-list to oProvisioningUser's
            // attributes collection:
            Iterator<String> itFields = htFields.keySet().iterator();
            String sCurrentField;
            while (itFields.hasNext()) {
            	sCurrentField = itFields.next();
            	oProvisioningUser.getAttributes().put(sCurrentField, htFields.get(sCurrentField));
            }

            
            Enumeration enumMethodIDs = _htProfile.keys();
            while(enumMethodIDs.hasMoreElements())
            {
                String sMethodID = (String)enumMethodIDs.nextElement();

                ProfileItem itemRegistered = _htProfile.get(sMethodID);
                Boolean boolRegistered = (Boolean)getValue(
                    itemRegistered, htFields);
                oProvisioningUser.putRegistered(sMethodID, boolRegistered);
            }  
        }
        catch (UserException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal(
                "Could not retrieve user information for user with id: " 
                + id, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        
        return oProvisioningUser;
    }

    
    /**
     * Stops the object.
     * @see IProfile#stop()
     */
    public void stop()
    {
        if (_oConverterManager != null)
            _oConverterManager.stop();
    }
    
    private Vector<String> getAllFields() throws UserException
    {
        Vector<String> vReturn = new Vector<String>();
        try
        {
            String sField = _itemEnabled.getField();
            if (sField != null)
                vReturn.add(sField);
            
            Enumeration enumAuthSPs = _htProfile.elements();
            while(enumAuthSPs.hasMoreElements())
            {
                ProfileItem itemRegistered = (ProfileItem)enumAuthSPs.nextElement();
                
                String sRegisteredField = itemRegistered.getField();
                if (sRegisteredField != null && !vReturn.contains(sRegisteredField))
                    vReturn.add(sRegisteredField);
            }  
        }
        catch(Exception e)
        {
            _logger.fatal("Could not retrieve all configured fields", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        
        return vReturn;
    }
    
    private Object getValue(ProfileItem oItem, 
        Hashtable<String, Object> htFields) throws UserException
    {
        Object oValue = null;
        try
        {
            if (oItem == null)
                return Boolean.FALSE;
            
            oValue = oItem.getDefault();
            if (oValue == null)
                oValue = Boolean.FALSE;
            
            String sField = oItem.getField();
            if (sField != null)
            {
                Object oFieldValue = htFields.get(sField);
                if (oFieldValue != null)
                    oValue = oFieldValue;
            }
            
            IConverter oConverter = oItem.getConverter();
            if (oConverter != null)
                oValue = oConverter.convert(oValue);
            
            if (oValue instanceof String)
                oValue = new Boolean((String)oValue);
        }
        catch(Exception e)
        {
            _logger.fatal("Could not retrieve value", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        return oValue;
    }
}
