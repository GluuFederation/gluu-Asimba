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
package com.alfaariss.oa.util.idmapper.file;


import java.io.File;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.idmapper.IIDMapper;
import com.alfaariss.oa.util.configuration.ConfigurationManager;
import com.alfaariss.oa.util.configuration.handler.file.FileConfigurationHandler;

/**
 * File User id mapper.
 * 
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class FileMapper implements IIDMapper
{
    private Log _logger;
    private Properties _pConfig;
    private String _sMapperParam;
    private String _sSection;
        
    /**
     * Constructor.
     */
    public FileMapper()
    {
        _logger = LogFactory.getLog(FileMapper.class);
        _pConfig = new Properties();
        _sMapperParam = null;
        _sSection = null;
    }
    /**
     * @see IIDMapper#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigManager, Element eConfig) 
        throws OAException
    {
        try
        {
            String sFile = oConfigManager.getParam(eConfig, "file");
            if(sFile == null)
            {
                _logger.error("No 'file' parameter found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            File fMapper = new File(sFile);
            if (!fMapper.exists())
            {
                _logger.warn("Configured 'file' parameter value not found at: " + fMapper.getAbsolutePath());
                
                String sUserDir = System.getProperty("user.dir");
                StringBuffer sbFile = new StringBuffer(sUserDir);
                if (!sUserDir.endsWith(File.separator))
                    sbFile.append(File.separator);
                sbFile.append(sFile);
                
                fMapper = new File(sbFile.toString());
                if (!fMapper.exists())
                {
                    _logger.error("Configured 'file' parameter not found at: " + fMapper.getAbsoluteFile());
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            sFile = fMapper.getAbsolutePath();
            _pConfig.put("configuration.handler.filename", sFile);    
            _logger.info("Using file: " + sFile);
            
            _sSection = oConfigManager.getParam(eConfig, "section");
            if (_sSection == null)
            {
                _sSection = "user";
                _logger.info("No optional 'section' parameter found in configuration; using default section");
            }
            _logger.info("Using 'section': " + _sSection);

            Element eMapper = oConfigManager.getSection(eConfig, "mapper");
            if(eMapper == null)
            {
                _logger.error("No 'mapper' section found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _sMapperParam = oConfigManager.getParam(eMapper, "param");
            if(_sMapperParam == null)
            {
                _logger.error("No 'param' parameter in 'mapper' section found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
                        
            getConfiguration();
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during object creation", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        } 
    }

    /**
     * @see IIDMapper#map(java.lang.String)
     */
    public String map(String sID) throws OAException
    {
        String sReturn = null;
        
        try
        {
            ConfigurationManager externalConfig = getConfiguration();
            Element eUser = externalConfig.getSection(null, _sSection, "id=" + sID);
            if (eUser!= null)
                sReturn = externalConfig.getParam(eUser, _sMapperParam);
            else
            {
                StringBuffer sbDebug = new StringBuffer("No '");
                sbDebug.append(_sSection);
                sbDebug.append("' section found with id: ");
                sbDebug.append(sID);
                _logger.debug(sbDebug.toString());
            }
        }
        catch (Exception e)
        {
            _logger.error("Internal error while mapping id: " + sID, e);
            throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }       
        
        return sReturn;
    }
    
    /**
     * @see IIDMapper#remap(java.lang.String)
     */
    public String remap(String sMappedID) throws OAException
    {
        String sReturn = null;
        
        try
        {
            ConfigurationManager externalConfig = getConfiguration();
            Element eSection = externalConfig.getSection(null, _sSection);
            while (eSection!= null)
            {
                String sMapped = externalConfig.getParam(eSection, _sMapperParam);
                if (sMapped != null && sMapped.equals(sMappedID))
                {
                    sReturn = externalConfig.getParam(eSection, "id");
                    break;
                }
                eSection = externalConfig.getNextSection(eSection);
            }
            
            if (_logger.isDebugEnabled() && sReturn == null)
            {
                StringBuffer sbDebug = new StringBuffer("Could not remap id; No '");
                sbDebug.append(_sMapperParam);
                sbDebug.append("' section found with value: ");
                sbDebug.append(sMappedID);
                _logger.debug(sbDebug.toString());
            }
        }
        catch (Exception e)
        {
            _logger.error("Internal error while remapping id: " + sMappedID, e);
            throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }       
        
        return sReturn;
    }

    /**
     * @see IIDMapper#stop()
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
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return externalConfiguration;
    }
}
