/*
 * Asimba Baseline Server
 * 
 * Copyright (C) Asimba - www.asimba.org
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
 */

package org.asimba.engine.user.provisioning.external.storage.file;

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
 * External storage based on asimba-users.xml file format
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

public class AsimbaUsersXml implements IExternalStorage
{
	/**
	 * Internal logger instance
	 */
    private Log _oLogger;

    /**
     * Local context for creating ConfigManager instance
     */
    protected Properties _pConfig;

    
    /**
     * Default constructor, initializes local context
     */
    public AsimbaUsersXml()
    {
        _oLogger = LogFactory.getLog(AsimbaUsersXml.class);
        _pConfig = new Properties();
    }
    
    /**
     * Start ExternalStorage component
     * 
     * Create from configuration:<br/>
     * &lt;file&gt; configures the full qualified filename of the asimba-users.xml file<br/>
     * <br/>
     * Mounting points are supported, so to refer to a file in user-directory, use
     * <b>${user.dir}/mydir/myfile</b><br/>
     * or to refer to file inside Servlet application directory:
     * <b>${webapp.root}/WEB-INF/data/myfile</b> (from OAContextListener.MP_WEBAPP_ROOT)<br/>
     */
    public void start(IConfigurationManager oConfigurationManager, Element eConfig) throws UserException
    {
        try
        {
            String sFile = oConfigurationManager.getParam(eConfig, "file");
            if(sFile == null)
            {
                _oLogger.error("No 'file' parameter found in configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            // Trim contents
            sFile = sFile.trim();
            
            // Establish real filename:
            sFile = PathTranslator.getInstance().map(sFile);
            
            File oAsimbaUsersFile = new File(sFile);
            if (!oAsimbaUsersFile.exists())
            {
	            _oLogger.error("The 'file' parameter was not found: " + oAsimbaUsersFile.getAbsolutePath());
	            throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            // Initialize context so ConfigManager can find the file: 
            sFile = oAsimbaUsersFile.getAbsolutePath();
            _pConfig.put("configuration.handler.filename", sFile);
            _oLogger.info("Using asimba-users.xml file: " + sFile);
            
            getConfiguration();
        }
        catch (UserException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _oLogger.fatal("Internal error during initialize", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
        }
    }

    /**
     * Establish attribute value for user with provided id
     * <br>
     * Attribute value is resolved in the following source format:<br>
     * &lt;user id='[sUserId]'&gt;<br>
     *  &lt;[sKey]&gt;[value]&lt;/[sKey]&gt;<br>
     * &lt;/user&gt;
     * @see IExternalStorage#getField(java.lang.String, java.lang.String)
     */
    public Object getField(String sUserId, String sKey) throws UserException
    {
        Object oValue = null;
        try
        {
            ConfigurationManager oCM = getConfiguration();
            Element elUser = oCM.getSection(null, "user", "id=" + sUserId);
            if (elUser != null)
                oValue = oCM.getParam(elUser, sKey);
        }
        catch(Exception e)
        {
        	String s = _pConfig.getProperty("configuration.handler.filename");
            _oLogger.error("Error when retrieving attribute '"+sKey+"' for user '"+sUserId+"' in file "+s, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
        }
        return oValue;
    }

    /**
     * Establish attribute values for user with provided id
     * <br>
     * Reads the following information from the XML file:<br>
     * &lt;user id='[sUserId]'&gt;<br>
     *  &lt;[sKey]&gt;[value]&lt;/[sKey]&gt;<br>
     * &lt;/user&gt;
     * @see IExternalStorage#getFields(java.lang.String, java.util.List)
     */
    public Hashtable<String, Object> getFields(
        String sUserId, List<String> lFields) throws UserException
    {
        Hashtable<String, Object> htValues = new Hashtable<String, Object>();
        try
        {
            ConfigurationManager oCM = getConfiguration();
            Element elUser = oCM.getSection(null, "user", "id=" + sUserId);
            if (elUser != null)
            {
                for (String sField: lFields)
                {
                    String sValue = oCM.getParam(elUser, sField);
                    if (sValue != null)
                        htValues.put(sField, sValue);
                }
            }
        }
        catch(Exception e)
        {
        	String s = _pConfig.getProperty("configuration.handler.filename");
            _oLogger.error("Error when retrieving attributes for user '"+sUserId+"' in file "+s, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
        }
        return htValues;
    }

    
    /**
     * Verifies if the supplied id exists in the file.
     * @see IStorage#exists(java.lang.String)
     */
    public boolean exists(String sUserId) throws UserException
    {
        try
        {
            ConfigurationManager oCM = getConfiguration();
            Element elUser = oCM.getSection(null, "user", "id=" + sUserId);
            if (elUser != null)
                return true;
        }
        catch(Exception e)
        {
        	String s = _pConfig.getProperty("configuration.handler.filename");
            _oLogger.error("Error with lookup of user '"+sUserId+"' in file "+s, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
        }
        return false;
    }

    /**
     * Stops the file storage.
     * @see com.alfaariss.oa.engine.user.provisioning.storage.IStorage#stop()
     */
    public void stop()
    {
    }

    /**
     * Instantiate a new ConfigurationManager object, that is using the configured
     * Asimba-users.xml file
     * @return Initialized ConfigurationManager instance
     * @throws OAException
     */
    private ConfigurationManager getConfiguration() throws OAException
    {
        ConfigurationManager oCM = null;
        try
        {
            FileConfigurationHandler oFCHandler = new FileConfigurationHandler();
            oFCHandler.init(_pConfig);
            
            oCM = new ConfigurationManager();
            oCM.init(oFCHandler);
        }
        catch (OAException e)
        {
        	// Rethrow exception
            throw e;
        }
        catch(Exception e)
        {
        	// Something system related occurred
        	String s = _pConfig.getProperty("configuration.handler.filename");
            _oLogger.error("Error when establishing ConfigManager using Asimba-users file "+s, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
        }
        
        return oCM;
    }
}
