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

/* 
 * Changes
 * 
 * - filenames placed in static variables (2012/03)
 * - lifecycle: manage mounting-point of webapp-root directory (2012/03)
 * 
 * Copyright Asimba - www.asimba.org
 * 
 */

package com.alfaariss.oa;

import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.util.Enumeration;
import java.util.Properties;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.utility.filesystem.PathTranslator;

import com.alfaariss.oa.engine.core.EngineLauncher;

/**
 * Starts the Engine with the start of the context.
 * 
 * Initializes from a file "asimba.properties", or accepts a system property 
 * "asimba.properties.file" that specifies the full qualified path to a file that is processed
 * as asimba.properties file. This overrules the search for an asimba.properties file.
 *
 * <b>PathTranslator: ${webapp.root}</b><br/>
 * On startup, a mounting-point with the absolute location of the webapp root
 * is added to PathTranslator, making paths relative to ${webapp.root} available
 * in configurable file locations
 * 
 * 
 * @author mdobrinic / Asimba
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class OAContextListener implements ServletContextListener
{
	/** Name of the file that contains property-list for configuring server */
	public static final String PROPERTIES_FILENAME = "asimba.properties";
	
	/** Name of the system property that specified the asimba.properties file location */
	public static final String PROPERTIES_FILENAME_PROPERTY = "asimba.properties.file";
	
	/**
	 * PathTranslator: Key for the mounting point for WebApp root directory
	 * See: org.asimba.utility.filesystem.PathTranslator
	 */
	public static final String MP_WEBAPP_ROOT = "webapp.root";
	

    private EngineLauncher _oEngineLauncher;
    private static Log _logger;
    
    /**
     * Starts the Core engine.
     */
    public OAContextListener()
    {
        try
        {
            _logger = LogFactory.getLog(OAContextListener.class);            
            _oEngineLauncher = new EngineLauncher();
        }
        catch (Exception e)
        {
            _logger.error("Internal error while creating object", e);
        }
    }
    /**
     * Starts the engine before all servlets are initialized.
     * 
     * Searches for the properties needed for the configuration in:
     * <code>[Servlet context dir]/WEB-INF/[PROPERTIES_FILENAME]</code>
     * @see javax.servlet.ServletContextListener#contextInitialized(javax.servlet.ServletContextEvent)
     */
    public void contextInitialized(ServletContextEvent oServletContextEvent)
    {
        Properties pConfig = new Properties();
        try
        {
            _logger.info("Starting Asimba");
            
            Package pCurrent = OAContextListener.class.getPackage();
            
            String sSpecVersion = pCurrent.getSpecificationVersion();
            if (sSpecVersion != null)
                _logger.info("Specification-Version: " + sSpecVersion);
            
            String sImplVersion = pCurrent.getImplementationVersion();
            if (sImplVersion != null)
                _logger.info("Implementation-Version: " + sImplVersion);
            
            ServletContext oServletContext = oServletContextEvent.getServletContext();
            
            Enumeration enumContextAttribs = oServletContext.getInitParameterNames();
            while (enumContextAttribs.hasMoreElements())
            {
                String sName = (String)enumContextAttribs.nextElement();
                pConfig.put(sName, oServletContext.getInitParameter(sName));
            }
            
            if(pConfig.size() > 0)
            {
                _logger.info("Using configuration items found in servlet context: " + pConfig);
            }
            
            // Add MountingPoint to PathTranslator
            PathTranslator.getInstance().addKey(MP_WEBAPP_ROOT, oServletContext.getRealPath(""));
            
            // Try to see whether there is a system property with the location of the properties file:
            String sPropertiesFilename = System.getProperty(PROPERTIES_FILENAME_PROPERTY);
            if (null != sPropertiesFilename && ! "".equals(sPropertiesFilename)) {
            	File fConfig = new File(sPropertiesFilename);
            	if (fConfig.exists()) {
            		_logger.info("Reading Asimba properties from "+fConfig.getAbsolutePath());
            		pConfig.putAll(getProperties(fConfig));
            	}
            }
            
            String sWebInf = oServletContext.getRealPath("WEB-INF");
            StringBuffer sbConfigFile = new StringBuffer(sWebInf);
            if (!sbConfigFile.toString().endsWith(File.separator))
                sbConfigFile.append(File.separator);
            sbConfigFile.append(PROPERTIES_FILENAME);
            
            File fConfig = new File(sbConfigFile.toString());
            if (fConfig.exists())
            {
                _logger.info("Updating configuration items with the items in file: " 
                    + fConfig.toString());
                pConfig.putAll(getProperties(fConfig));
            }
            else
            {   
                _logger.info("No optional configuration properties ("+PROPERTIES_FILENAME+") file found at: " + fConfig.toString());
            }
            
            //Search for PROPERTIES_FILENAME file in servlet context classloader classpath 
            //it looks first at this location: ./<context>/web-inf/classes/[PROPERTIES_FILENAME]
            //if previous location didn't contain PROPERTIES_FILENAME then checking: 
            //./tomcat/common/classes/PROPERTIES_FILENAME
            URL urlProperties = oServletContext.getClass().getClassLoader().getResource(PROPERTIES_FILENAME);
            if (urlProperties != null)
            {
                String sProperties = urlProperties.getFile();
                _logger.debug("Found '"+PROPERTIES_FILENAME+"' file in classpath: " + sProperties);
                File fProperties = new File(sProperties);
                if (fProperties != null && fProperties.exists())
                {
                    _logger.info("Updating configuration items with the items in file: " 
                        + fProperties.getAbsolutePath());
                    pConfig.putAll(getProperties(fProperties));
                }
                else
                    _logger.info("Could not resolve: " + fProperties.getAbsolutePath());
            }
            else
                _logger.info("No optional '"+PROPERTIES_FILENAME+"' configuration file found in servlet context classpath");
            
            if (!pConfig.containsKey("configuration.handler.filename"))
            {
                StringBuffer sbOAConfigFile = new StringBuffer(sWebInf);
                if (!sbOAConfigFile.toString().endsWith(File.separator))
                    sbOAConfigFile.append(File.separator);
                sbOAConfigFile.append("conf");
                sbOAConfigFile.append(File.separator);
                sbOAConfigFile.append("asimba.xml");
                File fOAConfig = new File(sbOAConfigFile.toString());
                if (fOAConfig.exists())
                {
                    pConfig.put("configuration.handler.filename", sbOAConfigFile.toString());
                    _logger.info("Setting 'configuration.handler.filename' configuration property with configuration file found at: " + fOAConfig.toString());
                }
            }
            
            _oEngineLauncher.start(pConfig);
            
            _logger.info("Started Engine with OAContextListener");
        }
        catch (Exception e)
        {
            _logger.error("Can't start Engine with OAContextListener", e);
            
            _logger.debug("try stopping the server");
            _oEngineLauncher.stop();
        }
        
    }

    /**
     * Stops the launcher.
     * @see javax.servlet.ServletContextListener#contextDestroyed(javax.servlet.ServletContextEvent)
     */
    public void contextDestroyed(ServletContextEvent arg0)
    {
        // Clean up MountingPoint from PathTranslator
        PathTranslator.getInstance().removeKey(MP_WEBAPP_ROOT);
    	
        _oEngineLauncher.stop();
        _logger.info("Stopped Engine with OAContextListener");
    }
    
    private Properties getProperties(File oFile) throws OAException
    {
        Properties pConfig = new Properties();
        try
        {
            FileInputStream oFileInputStream = new FileInputStream(oFile);
            pConfig.load(oFileInputStream);
            oFileInputStream.close();
        }
        catch (Exception e)
        {
            _logger.error("Can't load properties file: " + oFile.toString(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
            
        return pConfig;
    }

}