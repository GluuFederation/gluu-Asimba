/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
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

/* 
 * Changes
 * 
 * - support for relative paths based on mounting-points (2012/03)
 * 
 * Copyright Asimba - www.asimba.org
 * 
 */

package com.alfaariss.oa.engine.user.provisioning.storage.external.file;

import java.io.File;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.utility.filesystem.PathTranslator;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.engine.user.provisioning.storage.IStorage;
import com.alfaariss.oa.engine.user.provisioning.storage.external.IExternalStorage;
import com.alfaariss.oa.util.configuration.ConfigurationManager;
import com.alfaariss.oa.util.configuration.handler.file.FileConfigurationHandler;

/**
 * External storage based on Asimba-Users.xml file format
 * 
 * Userfile is read on demand, so changes in the file are reflected
 * in real time.
 * 
 * See www.asimba.org for more information about this document format
 * 
 * <b>Note</b>: This implementation is not meant to work with real life data!
 * @author mdobrinic@asimba
 *
 */
public class FileExternalStorage implements IExternalStorage
{
    private Log _logger;
    private Properties _pConfig;

    /**
     * Creates the object.
     */
    public FileExternalStorage()
    {
        _logger = LogFactory.getLog(FileExternalStorage.class);
        _pConfig = new Properties();
    }
    
    /**
     * Starts the object.
     * <br>
     * Creates a ExternalStorage instance, requiring the following configuration
     * <br>
     * &lt;file&gt;[full path to the file]&lt;/file&gt;
     * <br>
     * Mounting points are supported, so to refer to a file in user-directory, use
     * <b>${user.dir}/mydir/myfile</b> 
     */
    public void start(IConfigurationManager oConfigurationManager, Element eConfig) throws UserException
    {
        try
        {
            String sFile = oConfigurationManager.getParam(eConfig, "file");
            if(sFile == null)
            {
                _logger.error("No 'file' parameter found in configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sTrimmedFile = sFile.trim();
            if (sFile.length() > sTrimmedFile.length())
            {
                sFile = sTrimmedFile;
                StringBuffer sbInfo = new StringBuffer("Configured 'file' has been trimmed, using '");
                sbInfo.append(sFile);
                sbInfo.append("'");
                _logger.info(sbInfo.toString());
            }
            
            // Establish real filename:
            sFile = PathTranslator.getInstance().map(sFile);
            
            File fUsers = new File(sFile);
            if (!fUsers.exists())
            {
                _logger.warn("Configured 'file' parameter value not found at: " + fUsers.getAbsolutePath());
                
                String sUserDir = System.getProperty("user.dir");
                StringBuffer sbFile = new StringBuffer(sUserDir);
                if (!sUserDir.endsWith(File.separator))
                    sbFile.append(File.separator);
                sbFile.append(sFile);
                
                fUsers = new File(sbFile.toString());
                if (!fUsers.exists())
                {
                    _logger.error("Configured 'file' parameter not found at: " + fUsers.getAbsolutePath());
                    throw new UserException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            sFile = fUsers.getAbsolutePath();
            _pConfig.put("configuration.handler.filename", sFile);
            _logger.info("Using file: " + sFile);
            
            getConfiguration();
        }
        catch (UserException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialize", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
        }
    }

    /**
     * Retrieves the field values where id is the user id.
     * <br>
     * Reads the following information from the XML file:<br>
     * &lt;user id='[id]'&gt;<br>
     *  &lt;[field]&gt;[value]&lt;/[field]&gt;<br>
     * &lt;/user&gt;
     * @see IExternalStorage#getField(java.lang.String, java.lang.String)
     */
    public Object getField(String id, String field) throws UserException
    {
        Object oValue = null;
        try
        {
            ConfigurationManager externalConfig = getConfiguration();
            Element eUser = externalConfig.getSection(null, "user", "id=" + id);
            if (eUser != null)
                oValue = externalConfig.getParam(eUser, field);
        }
        catch(Exception e)
        {
            StringBuffer sbError = new StringBuffer(
                "Internal error during retrieve of '");
            sbError.append(field);
            sbError.append("' for id: ");
            sbError.append(id);
            _logger.fatal(sbError.toString(), e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
        }
        return oValue;
    }

    /**
     * Retrieves the field values where id is the user id.
     * <br>
     * Reads the following information from the XML file:<br>
     * &lt;user id='[id]'&gt;<br>
     *  &lt;[field]&gt;[value]&lt;/[field]&gt;<br>
     * &lt;/user&gt;
     * @see IExternalStorage#getFields(java.lang.String, java.util.List)
     */
    public Hashtable<String, Object> getFields(
        String id, List<String> fields) throws UserException
    {
        Hashtable<String, Object> htValues = new Hashtable<String, Object>();
        try
        {
            ConfigurationManager externalConfig = getConfiguration();
            Element eUser = externalConfig.getSection(null, "user", "id=" + id);
            if (eUser != null)
            {
                for (String sField: fields)
                {
                    String sValue = externalConfig.getParam(eUser, sField);
                    if (sValue != null)
                        htValues.put(sField, sValue);
                }
            }
        }
        catch(Exception e)
        {
            StringBuffer sbError = new StringBuffer("Internal error during retrieve of '");
            sbError.append(fields);
            sbError.append("' for id: ");
            sbError.append(id);
            _logger.fatal(sbError.toString(), e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
        }
        return htValues;
    }

    /**
     * Verifies if the supplied id exists in the file.
     * @see IStorage#exists(java.lang.String)
     */
    public boolean exists(String id) throws UserException
    {
        try
        {
            ConfigurationManager externalConfig = getConfiguration();
            Element eUser = externalConfig.getSection(null, "user", "id=" + id);
            if (eUser != null)
                return true;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not verify if user exists: " + id, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        return false;
    }

    /**
     * Stops the file storage.
     * @see com.alfaariss.oa.engine.user.provisioning.storage.IStorage#stop()
     */
    public void stop()
    {
        //do nothing
    }

    //returns the configuration manager
    private ConfigurationManager getConfiguration() throws OAException
    {
        ConfigurationManager externalConfiguration = null;
        try
        {
            FileConfigurationHandler confighandler = new FileConfigurationHandler();
            confighandler.init(_pConfig);
            
            externalConfiguration = new ConfigurationManager();
            externalConfiguration.init(confighandler);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during configuration manager creation", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
        }
        
        return externalConfiguration;
    }
}
