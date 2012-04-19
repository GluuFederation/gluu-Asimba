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
package org.asimba.engine.attribute.gather.processor.file;

import java.io.File;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.utility.filesystem.PathTranslator;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.attribute.gather.processor.file.FileAttribute;
import com.alfaariss.oa.engine.core.attribute.AttributeException;
import com.alfaariss.oa.engine.core.attribute.gather.processor.IProcessor;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.util.configuration.ConfigurationManager;
import com.alfaariss.oa.util.configuration.handler.file.FileConfigurationHandler;


/**
 * AttributeGatherer based on asimba-users.xml file format
 * 
 * Attribute-file is read on demand, so changes will be reflected
 * in real-time.
 * 
 * See www.asimba.org for more information about this document format
 * 
 * <b>Note</b>: This implementation is not meant to work with real life data!
 * 
 * @author mdobrinic@asimba
 */

public class AsimbaUsersXmlGatherer implements IProcessor {

    protected Log _oLogger;
    
    private boolean _bEnabled;
    private String _sID;
    private String _sFriendlyName;
    
    private Properties _pConfig;
    private Hashtable<String, FileAttribute> _htGlobal;
    private Hashtable<String, String> _htMapper;
    private List<String> _listGather;

	
    public AsimbaUsersXmlGatherer() {
    	_oLogger = LogFactory.getLog(AsimbaUsersXmlGatherer.class);
        _sID = null;
        _sFriendlyName = null;
        
        _bEnabled = false;
        _pConfig = new Properties();
        _htGlobal = new Hashtable<String, FileAttribute>();
        _htMapper = new Hashtable<String, String>();
        _listGather = new Vector<String>();
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

	public void start(IConfigurationManager oConfigManager,
			Element eConfig) throws AttributeException 
	{
        try
        {
            if(oConfigManager == null) 
            {
                _oLogger.error("No configuration manager supplied");
                throw new AttributeException(SystemErrors.ERROR_INIT);
            }
            
            if(eConfig == null) 
            {
                _oLogger.error("No configuration element supplied");
                throw new AttributeException(SystemErrors.ERROR_INIT);
            }
            
            _bEnabled = true;
            String sEnabled = oConfigManager.getParam(eConfig, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    _bEnabled = false;
                else if (!sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _oLogger.error("Unknown value in 'enabled' configuration item: " + sEnabled);
                    throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            _sID = oConfigManager.getParam(eConfig, "id");
            if (_sID == null)
            {
                _oLogger.error("No 'id' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            if (_sID.trim().length() == 0)
            {
                _oLogger.error("Empty 'id' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _sFriendlyName = oConfigManager.getParam(eConfig, "friendlyname");
            if (_sFriendlyName == null)
            {
                _oLogger.error("No 'friendlyname' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sFile = oConfigManager.getParam(eConfig, "file");
            if(sFile == null)
            {
                _oLogger.error("No 'file' parameter found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            sFile = PathTranslator.getInstance().map(sFile);
            
            File fAttributes = new File(sFile);
            if (!fAttributes.exists())
            {
                _oLogger.error("Configured 'file' parameter value not found at: " + sFile);
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            _oLogger.info("Using attributes file: " + sFile);
            
            _pConfig.put("configuration.handler.filename", sFile);
            
            ConfigurationManager fileConfig = getConfiguration();
            Element eGlobal = fileConfig.getSection(null, "global");
            if (eGlobal == null)
                _oLogger.info("No optional 'global' config section configured");
            else
                _htGlobal = getFileAttributes(fileConfig, eGlobal);
            
            Element eMapper = oConfigManager.getSection(eConfig, "mapper");
            if (eMapper == null)
                _oLogger.info("No optional 'mapper' section found in configuration");
            else
            {
                Element eMap = oConfigManager.getSection(eMapper, "map");
                while (eMap != null)
                {
                    String sExt = oConfigManager.getParam(eMap, "ext");
                    if (sExt == null)
                    {
                        _oLogger.error("No 'ext' item found in 'map' section");
                        throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    if (sExt.trim().length() == 0)
                    {
                        _oLogger.error("Empty 'ext' item found in 'map' section");
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    String sInt = oConfigManager.getParam(eMap, "int");
                    if (sInt == null)
                    {
                        _oLogger.error("No 'int' item found in 'map' section");
                        throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    if (sInt.trim().length() == 0)
                    {
                        _oLogger.error("Empty 'int' item found in 'map' section");
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    if (_htMapper.containsKey(sExt))
                    {
                        _oLogger.error("Ext name not unique in map with 'ext' value: " + sExt);
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    if (_htMapper.contains(sInt))
                    {
                        _oLogger.error("Int name not unique in map with 'int' value: " + sInt);
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    _htMapper.put(sExt, sInt);
                    
                    eMap = oConfigManager.getNextSection(eMap);
                }
            }      
            
            Element eGather = oConfigManager.getSection(eConfig, "gather");
            if (eGather == null)
                _oLogger.info("No optional 'gather' section found in configuration");
            else
            {
                Element eAttribute = oConfigManager.getSection(eGather, "attribute");
                while (eAttribute != null)
                {
                    String sName = oConfigManager.getParam(eAttribute, "name");
                    if (sName == null)
                    {
                        _oLogger.error("No 'name' item found in 'attribute' section");
                        throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    if (sName.trim().length() == 0)
                    {
                        _oLogger.error("Empty 'name' item found in 'attribute' section");
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    if (_listGather.contains(sName))
                    {
                        _oLogger.error("Attribute name not unique: " + sName);
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    _listGather.add(sName);
                    
                    eAttribute = oConfigManager.getNextSection(eAttribute);
                }
                
                _oLogger.info("Configured to gather only the following subset: " 
                    + _listGather.toString());
            }
           
            _oLogger.info("Started: File Attribute Gatherer");
        }
        catch (AttributeException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _oLogger.fatal("Internal error during initialize", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
        }
	}

	
	public void process(String sUserId, IAttributes oAttributes)
			throws AttributeException 
	{
        if(oAttributes == null) 
            throw new IllegalArgumentException("IAttributes was not provided");
        try
        {
            ConfigurationManager oCM = getConfiguration();
            
            // First, process global attributes
            Enumeration<FileAttribute> oEnumGlobal = _htGlobal.elements();
            while (oEnumGlobal.hasMoreElements())
            {
                FileAttribute fAttr = oEnumGlobal.nextElement();
                String sName = fAttr.getName();
                List<?> listValues = fAttr.getValues(); 
                String sMappedName = _htMapper.get(sName);
                if (sMappedName != null)
                    sName = sMappedName;
                
                if (_listGather.isEmpty() || _listGather.contains(sName))
                {
                	// Ignore multi-value, only return the first value
                    if (listValues.size() > 1) 
                        oAttributes.put(sName, fAttr.getFormat(), listValues);
                    else
                        oAttributes.put(sName, fAttr.getFormat(), listValues.get(0));
                }
            }
            
            Element elUser = oCM.getSection(null, "user", "id=" + sUserId);
            if (elUser != null)
            {
                Hashtable<String, FileAttribute> htAttributes = getFileAttributes(oCM, elUser);
                if (!htAttributes.isEmpty())
                {
                    Enumeration<FileAttribute> enumAttributes = htAttributes.elements();
                    while (enumAttributes.hasMoreElements())
                    {
                        FileAttribute fAttr = enumAttributes.nextElement();
                        String sName = fAttr.getName();
                        List<?> listValues = fAttr.getValues();                        
                        String sMappedName = _htMapper.get(sName);
                        if (sMappedName != null)
                            sName = sMappedName;
                        
                        if (_listGather.isEmpty() || _listGather.contains(sName))
                        {
                        	// Ignore multi-value, only return the first value
                            if (listValues.size() > 1) 
                                oAttributes.put(sName, fAttr.getFormat(), listValues);
                            else
                                oAttributes.put(sName, fAttr.getFormat(), listValues.get(0));
                                
                        }
                    }
                }
                else
                    _oLogger.debug("No user specific attributes found");
            }
            else
                _oLogger.debug("No user found in attributes file");
        }
        catch (AttributeException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _oLogger.fatal("Internal error during attribute processing", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
        }
	}


	/**
     * Stop components and clean up
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
    
    
    /**
     * Retrieve attributes from a provided parent element; this could
     * be either <global> or a specific <user@id> element<br/>
     * All attributes are added with type "string".
     * @param oCM ConfigurationManager instance, initialized for the asimba-users.xml file
     * @param eSection Element that contains the attributes
     * @return Hashtable of Key-FileAttribute pairs, as defined in the file
     * @throws AttributeException Whenever something goes pretty wrong..
     */
    protected Hashtable<String, FileAttribute> getFileAttributes(
            ConfigurationManager oCM, Element eSection) 
            throws AttributeException
        {
            Hashtable<String, FileAttribute> htAttributes = 
                new Hashtable<String, FileAttribute>();
            
        	NodeList oNLAttributes = eSection.getChildNodes();
        	Node oNCurrent;
        	String sKey, sValue;
            for (int i = 0; i < oNLAttributes.getLength(); i++) {
                oNCurrent = oNLAttributes.item(i);
                if (oNCurrent.getNodeType() == Node.ELEMENT_NODE) {
                	sKey = oNCurrent.getNodeName();
                	sValue = oNCurrent.getTextContent();

                	FileAttribute oFileAttr = new FileAttribute(sKey, "string", sValue);
                	htAttributes.put(sKey, oFileAttr);
                }
            }
            return htAttributes;
        }
}
