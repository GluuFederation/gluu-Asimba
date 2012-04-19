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
package com.alfaariss.oa.util.configuration.handler.dummy;
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
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.handler.IConfigurationHandler;

/**
 * A dummy configuration handler for use in junit tests.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class DummyConfigurationHandler implements IConfigurationHandler 
{

	private Log _logger;
	private String _root;

    /**
     * Create a new <code>FileConfigHandler</code>.
     */
    public DummyConfigurationHandler()
    {
        _logger = LogFactory.getLog(DummyConfigurationHandler.class);
    }
	/**
	 * Initialize a new <code>FileConfigHandler</code>.
     * 
	 * @see IConfigurationHandler#init(java.util.Properties)
	 */
	public void init(Properties pConfig)
	  throws ConfigurationException
    {
        try
        {         
            _root = pConfig.getProperty("root_element");
            if(_root == null)
            {
                _logger.error("Property with name 'root_element' not found");
                throw new ConfigurationException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        catch (ConfigurationException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Internal error during initialization", e);
            throw new ConfigurationException(SystemErrors.ERROR_INTERNAL);
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
        DocumentBuilderFactory oDocumentBuilderFactory = DocumentBuilderFactory
            .newInstance();

        //Create parser
        DocumentBuilder oDocumentBuilder = null;
        try
        {
            oDocumentBuilder = oDocumentBuilderFactory
                .newDocumentBuilder();
            //parse
            dRet = oDocumentBuilder.newDocument();
            
            Element eRoot = dRet.createElement("config");
            eRoot.appendChild(dRet.createElement(_root));
            dRet.appendChild(eRoot);
        }
        catch (ParserConfigurationException e)
        {
            _logger.error("Error reading configuration, parse error", e);
            throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        return dRet;
	}
	
    /**
     * Save the configuration to the screen.
     * @see IConfigurationHandler#saveConfiguration(org.w3c.dom.Document)
     */
    public void saveConfiguration(Document oConfigurationDocument)
      throws ConfigurationException
    {
        try
        {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty(OutputKeys.VERSION, "1.0");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.transform(new DOMSource(oConfigurationDocument), new StreamResult(System.out));
        }
        catch (TransformerException e)
        {
            _logger.error("Error while transforming document", e);
            throw new ConfigurationException(SystemErrors.ERROR_CONFIG_WRITE);
        }
    }

}