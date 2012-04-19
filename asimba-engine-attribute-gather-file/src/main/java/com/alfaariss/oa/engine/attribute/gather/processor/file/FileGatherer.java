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
package com.alfaariss.oa.engine.attribute.gather.processor.file;
import java.io.File;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.attribute.AttributeException;
import com.alfaariss.oa.engine.core.attribute.gather.processor.IProcessor;
import com.alfaariss.oa.util.configuration.ConfigurationManager;
import com.alfaariss.oa.util.configuration.handler.file.FileConfigurationHandler;

/**
 * Attribute gatherer that resolves attributes from file.
 *
 * Reads attributes from an XML file.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class FileGatherer implements IProcessor 
{
    private Log _logger;
    
    private boolean _bEnabled;
    private String _sID;
    private String _sFriendlyName;
    
    private Properties _pConfig;
    private Hashtable<String, FileAttribute> _htGlobal;
    private Hashtable<String, String> _htMapper;
    private List<String> _listGather;
    
    /**
     * Creates the object.
     */
    public FileGatherer()
    {
        _logger = LogFactory.getLog(FileGatherer.class);
        _sID = null;
        _sFriendlyName = null;
        _bEnabled = false;
        _pConfig = new Properties();
        _htGlobal = new Hashtable<String, FileAttribute>();
        _htMapper = new Hashtable<String, String>();
        _listGather = new Vector<String>();
	}

    /**
     * Starts the gatherer and reads the global attributes from file.
     * @see IProcessor#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws AttributeException
    {
        try
        {
            if(oConfigurationManager == null) 
            {
                _logger.error("No configuration manager supplied");
                throw new AttributeException(SystemErrors.ERROR_INIT);
            }
            
            if(eConfig == null) 
            {
                _logger.error("No configuration element supplied");
                throw new AttributeException(SystemErrors.ERROR_INIT);
            }
            
            _bEnabled = true;
            String sEnabled = oConfigurationManager.getParam(eConfig, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    _bEnabled = false;
                else if (!sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _logger.error("Unknown value in 'enabled' configuration item: " + sEnabled);
                    throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            _sID = oConfigurationManager.getParam(eConfig, "id");
            if (_sID == null)
            {
                _logger.error("No 'id' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            if (_sID.trim().length() == 0)
            {
                _logger.error("Empty 'id' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _sFriendlyName = oConfigurationManager.getParam(eConfig, "friendlyname");
            if (_sFriendlyName == null)
            {
                _logger.error("No 'friendlyname' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sFile = oConfigurationManager.getParam(eConfig, "file");
            if(sFile == null)
            {
                _logger.error("No 'file' parameter found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
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
            
            File fAttributes = new File(sFile);
            if (!fAttributes.exists())
            {
                _logger.error("Configured 'file' parameter value not found at: " + sFile);
                sFile = System.getProperty("user.dir") + sFile;
                fAttributes = new File(sFile);
                if (!fAttributes.exists())
                {
                    _logger.error("Configured 'file' parameter value not found at: " + sFile);
                    throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            _logger.info("Using attributes file: " + sFile);
            
            _pConfig.put("configuration.handler.filename", sFile);
            
            ConfigurationManager fileConfig = getConfiguration();
            Element eGlobal = fileConfig.getSection(null, "global");
            if (eGlobal == null)
                _logger.info("No optional 'global' config section configured");
            else
                _htGlobal = getFileAttributes(fileConfig, eGlobal);
            
            Element eMapper = oConfigurationManager.getSection(eConfig, "mapper");
            if (eMapper == null)
                _logger.info("No optional 'mapper' section found in configuration");
            else
            {
                Element eMap = oConfigurationManager.getSection(eMapper, "map");
                while (eMap != null)
                {
                    String sExt = oConfigurationManager.getParam(eMap, "ext");
                    if (sExt == null)
                    {
                        _logger.error("No 'ext' item found in 'map' section");
                        throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    if (sExt.trim().length() == 0)
                    {
                        _logger.error("Empty 'ext' item found in 'map' section");
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    String sInt = oConfigurationManager.getParam(eMap, "int");
                    if (sInt == null)
                    {
                        _logger.error("No 'int' item found in 'map' section");
                        throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    if (sInt.trim().length() == 0)
                    {
                        _logger.error("Empty 'int' item found in 'map' section");
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    if (_htMapper.containsKey(sExt))
                    {
                        _logger.error("Ext name not unique in map with 'ext' value: " + sExt);
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    if (_htMapper.contains(sInt))
                    {
                        _logger.error("Int name not unique in map with 'int' value: " + sInt);
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    _htMapper.put(sExt, sInt);
                    
                    eMap = oConfigurationManager.getNextSection(eMap);
                }
            }      
            
            Element eGather = oConfigurationManager.getSection(eConfig, "gather");
            if (eGather == null)
                _logger.info("No optional 'gather' section found in configuration");
            else
            {
                Element eAttribute = oConfigurationManager.getSection(eGather, "attribute");
                while (eAttribute != null)
                {
                    String sName = oConfigurationManager.getParam(eAttribute, "name");
                    if (sName == null)
                    {
                        _logger.error("No 'name' item found in 'attribute' section");
                        throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    if (sName.trim().length() == 0)
                    {
                        _logger.error("Empty 'name' item found in 'attribute' section");
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    if (_listGather.contains(sName))
                    {
                        _logger.error("Attribute name not unique: " + sName);
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    _listGather.add(sName);
                    
                    eAttribute = oConfigurationManager.getNextSection(eAttribute);
                }
                
                _logger.info("Configured to gather only the following subset: " 
                    + _listGather.toString());
            }
           
            _logger.info("Started: File Attribute Gatherer");
        }
        catch (AttributeException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialize", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Gathers attributes from file.
     * 
     * First adds the optionaly configured global attributes then updates with 
     * the specific user attributes. 
     * @see com.alfaariss.oa.engine.core.attribute.gather.processor.IProcessor#process(java.lang.String, com.alfaariss.oa.api.attribute.IAttributes)
     */
    public void process(String id, IAttributes attributes) throws AttributeException
    {
        if(attributes == null) 
            throw new IllegalArgumentException("Suplied attributes parameter is empty");
        try
        {
            ConfigurationManager fileConfig = getConfiguration();
            
            Enumeration enumGlobal = _htGlobal.elements();
            while (enumGlobal.hasMoreElements())
            {
                FileAttribute fAttr = (FileAttribute)enumGlobal.nextElement();
                String sName = fAttr.getName();
                List<?> listValues = fAttr.getValues(); 
                String sMappedName = _htMapper.get(sName);
                if (sMappedName != null)
                    sName = sMappedName;
                
                if (_listGather.isEmpty() || _listGather.contains(sName))
                {
                    if (listValues.size() > 1) 
                        attributes.put(sName, fAttr.getFormat(), listValues);
                    else
                        attributes.put(sName, fAttr.getFormat(), listValues.get(0));
                }
            }
            
            Element eUser = fileConfig.getSection(null, "user", "id=" + id);
            if (eUser != null)
            {
                Hashtable htAttributes = getFileAttributes(fileConfig, eUser);
                if (!htAttributes.isEmpty())
                {
                    Enumeration enumAttributes = htAttributes.elements();
                    while (enumAttributes.hasMoreElements())
                    {
                        FileAttribute fAttr = (FileAttribute)enumAttributes.nextElement();
                        String sName = fAttr.getName();
                        List<?> listValues = fAttr.getValues();                        
                        String sMappedName = _htMapper.get(sName);
                        if (sMappedName != null)
                            sName = sMappedName;
                        
                        if (_listGather.isEmpty() || _listGather.contains(sName))
                        {
                            if (listValues.size() > 1) 
                                attributes.put(sName, fAttr.getFormat(), listValues);
                            else
                                attributes.put(sName, fAttr.getFormat(), listValues.get(0));
                                
                        }
                    }
                }
                else
                    _logger.debug("No user specific attributes found");
            }
            else
                _logger.debug("No user found in attributes file");
        }
        catch (AttributeException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during attribute processing", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Stops the gatherer.
     * @see com.alfaariss.oa.engine.core.attribute.gather.processor.IProcessor#stop()
     */
    public void stop()
    {
        if (_htMapper != null)
            _htMapper.clear();
        if (_htGlobal != null)
            _htGlobal.clear();
        if (_listGather != null)
            _listGather.clear();
    }

    /**
     * Returns the unique gatherer ID.
     * @see com.alfaariss.oa.api.IManagebleItem#getID()
     */
    public String getID()
    {
        return _sID;
    }

    /**
     * Returns the human readable gatherer name.
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }

    /**
     * Returns TRUE if this gatherer is enabled.
     * @see com.alfaariss.oa.api.IManagebleItem#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }

    private ConfigurationManager getConfiguration() throws AttributeException
    {
        ConfigurationManager fileConfiguration = null;
        try
        {
            FileConfigurationHandler confighandler = new FileConfigurationHandler();
            confighandler.init(_pConfig);
            
            fileConfiguration = new ConfigurationManager();
            fileConfiguration.init(confighandler);
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during configuration manager creation", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
        }
        
        return fileConfiguration;
    }
    
    private Hashtable<String, FileAttribute> getFileAttributes(
        ConfigurationManager fileConfig, Element eSection) 
        throws AttributeException
    {
        Hashtable<String, FileAttribute> htAttributes = 
            new Hashtable<String, FileAttribute>();
        
        try
        {
            Element eAttribute = fileConfig.getSection(eSection, "attribute");
            while (eAttribute != null)
            {
                String sNameID = fileConfig.getParam(eAttribute, "id");
                if (sNameID == null)
                {
                    _logger.error("No 'id' parameter in 'attribute' section found");
                    throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                if (htAttributes.containsKey(sNameID))
                {
                    _logger.error("Duplicatie 'id' parameter in 'attribute' section found: " 
                        + sNameID);
                    throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                String sFormat = fileConfig.getParam(eAttribute, "format");
                
                FileAttribute fAttr = new FileAttribute(sNameID, sFormat);
                
                Element eValue = fileConfig.getSection(eAttribute, "value");
                while (eValue != null)
                {
                    String sValueID = fileConfig.getParam(eValue, "id");
                    if (sValueID == null)
                    {
                        _logger.error("No 'id' parameter in 'value' section found");
                        throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    fAttr.addValue(sValueID);
                    
                    eValue = fileConfig.getNextSection(eValue);
                }
                                    
                htAttributes.put(sNameID, fAttr);
                
                eAttribute = fileConfig.getNextSection(eAttribute);
            }
        }
        catch (AttributeException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during attribute reading", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
        }
        return htAttributes;
    }
}