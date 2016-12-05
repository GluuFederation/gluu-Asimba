/*
 * Asimba Server
 * 
 * Copyright (C) 2016 Gluu
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
package com.alfaariss.oa.util.configuration.handler.context;

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
import java.io.InputStream;

/**
 * A configuration handler for configuration XML resource file.
 *
 * @author Dmitry Ognyannikov
 */
public class ContextResourceConfigurationHandler implements IConfigurationHandler {

    private Log _logger;
    private String resourceFileName;
    
    /**
     * Create a new <code>FileConfigHandler</code>.
     */
    public ContextResourceConfigurationHandler() {
        _logger = LogFactory.getLog(ContextResourceConfigurationHandler.class);
    }

    /**
     * Initialize a new <code>ContextResourceConfigurationHandler</code>.
     *
     * @see IConfigurationHandler#init(java.util.Properties)
     */
    @Override
    public void init(Properties pConfig)
            throws ConfigurationException {
        InputStream inputStream = null;
        try {
            String sFileName = pConfig.getProperty("configuration.handler.context_resource_file");
            if (sFileName == null) {
                _logger.error("Property with name 'configuration.handler.context_resource_file' not found");
                throw new ConfigurationException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            inputStream = openContextResourceFile(sFileName);

            if (inputStream == null) {//only start initializing when config file exists
                _logger.error("Configuration file not found: " + sFileName);
                throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_CONNECT);
            }
            
            resourceFileName = sFileName;
        } catch (ConfigurationException e) {
            throw e;
        } catch (Exception e) {
            _logger.error("Internal error during initialization", e);
            throw new ConfigurationException(SystemErrors.ERROR_INTERNAL, e);
        } finally {
            if (inputStream != null) {
                try { inputStream.close(); } catch (Exception e) {}
            }
        }
    }

    /**
     * Parse the configuration from the file.
     *
     * @see IConfigurationHandler#parseConfiguration()
     */
    @Override
    public Document parseConfiguration()
            throws ConfigurationException {
        if (resourceFileName == null) {
            _logger.error("Property with name 'configuration.handler.context_resource_file' not found");
            throw new ConfigurationException(SystemErrors.ERROR_CONFIG_READ);
        }
            
        Document dRet = null;
        //create DocumentBuilderFactory to parse config file.
        DocumentBuilderFactory oDocumentBuilderFactory
                = DocumentBuilderFactory.newInstance();

        try (InputStream inputStream = openContextResourceFile(resourceFileName)) {
            //parser
            DocumentBuilder oDocumentBuilder = oDocumentBuilderFactory.newDocumentBuilder();
            //parse
            dRet = oDocumentBuilder.parse(inputStream);
        } catch (ParserConfigurationException e) {
            _logger.error("Error reading configuration, parse error", e);
            throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
        } catch (SAXException e) {
            _logger.error("Error reading configuration, SAX parse error", e);
            throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
        } catch (IOException e) {
            _logger.error("Error reading configuration, I/O error", e);
            throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
        }

        return dRet;
    }

    /**
     * Save the configuration to the file.
     *
     * @see IConfigurationHandler#saveConfiguration(org.w3c.dom.Document)
     */
    @Override
    public void saveConfiguration(Document oConfigurationDocument)
            throws ConfigurationException {
        // Not applicable for context resource
        _logger.error("saveConfiguration() is not applicable for context resource");
        throw new ConfigurationException(SystemErrors.ERROR_CONFIG_WRITE);
    }
    
    private InputStream openContextResourceFile(String fileName) throws IOException {
        InputStream inputStream = null;
        try {
            inputStream = getClass().getClassLoader().getResourceAsStream(fileName);
        } catch (Exception e) {
            inputStream = null;
        }
        if (inputStream != null)
            return inputStream;
        
        try {
            inputStream = getClass().getResourceAsStream(fileName);
        } catch (Exception e) {
            inputStream = null;
        }
        if (inputStream != null)
            return inputStream;
        
        try {
            inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileName); 
        } catch (Exception e) {
            inputStream = null;
        }
        
        return inputStream;
    }
}
