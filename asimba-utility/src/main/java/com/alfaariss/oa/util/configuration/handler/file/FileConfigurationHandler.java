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
package com.alfaariss.oa.util.configuration.handler.file;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.handler.IConfigurationHandler;

/**
 * A configuration handler for configuration files.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class FileConfigurationHandler implements IConfigurationHandler 
{

	private Log _logger;
	private File _fConfig;

    /**
     * Create a new <code>FileConfigHandler</code>.
     */
    public FileConfigurationHandler()
    {
        _logger = LogFactory.getLog(FileConfigurationHandler.class);
    }
	/**
	 * Initialize a new <code>FileConfigHandler</code>.
	 * @see IConfigurationHandler#init(java.util.Properties)
	 */
	public void init(Properties pConfig)
	  throws ConfigurationException
    {
        try
        {   
            String sFileName = pConfig.getProperty("configuration.handler.filename");
            if(sFileName == null)
            {
                _logger.error("Property with name 'configuration.handler.filename' not found");
                throw new ConfigurationException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _fConfig = new File(sFileName);
    
            if (_fConfig == null || !_fConfig.exists())
            {//only start initializing when config file exists
                _logger.error("Configuration file not found: " + sFileName);
                throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_CONNECT);
            }
        }
        catch (ConfigurationException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Internal error during initialization", e);
            throw new ConfigurationException(SystemErrors.ERROR_INTERNAL, e);
        }
	}

	/**
	 * Parse the configuration from the file.
	 * @see IConfigurationHandler#parseConfiguration()
	 */
	public Document parseConfiguration()
	  throws ConfigurationException
    {
        Document dRet = null;
        //create DocumentBuilderFactory to parse config file.
        DocumentBuilderFactory oDocumentBuilderFactory = 
            DocumentBuilderFactory.newInstance();

        try
        {
            //parser
            DocumentBuilder oDocumentBuilder = oDocumentBuilderFactory.newDocumentBuilder();
            //parse
            dRet = oDocumentBuilder.parse(_fConfig);
        }
        catch (ParserConfigurationException e)
        {
            _logger.error("Error reading configuration, parse error", e);
            throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
        }
        catch (SAXException e)
        {
            _logger.error("Error reading configuration, SAX parse error", e);
            throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
        }
        catch (IOException e)
        {
            _logger.error("Error reading configuration, I/O error", e);
            throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
        }
        
        return dRet;
	}
	
	/**
	 * Save the configuration to the file.
	 * @see IConfigurationHandler#saveConfiguration(org.w3c.dom.Document)
	 */
	public void saveConfiguration(Document oConfigurationDocument)
	  throws ConfigurationException
    {
        OutputStream os = null;
        try
        {
            os = new FileOutputStream(_fConfig);
            //create output format which uses new lines and tabs
            
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty(OutputKeys.VERSION, "1.0");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.transform(new DOMSource(oConfigurationDocument), new StreamResult(os));
        }
        catch (FileNotFoundException e)
        {
            _logger.error("Error writing configuration, file not found", e);
            throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_CONNECT);
        }
        catch (TransformerException e)
        {
            _logger.error("Error while transforming document", e);
            throw new ConfigurationException(SystemErrors.ERROR_CONFIG_WRITE);
        }
        finally
        {
        
            try
            {
                if(os!= null)
                    os.close();
            }
            catch (IOException e)
            {
               _logger.debug("Error closing configuration outputstream", e);
            }
        }        
	}

}