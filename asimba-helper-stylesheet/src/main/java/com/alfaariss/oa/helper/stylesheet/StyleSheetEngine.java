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
package com.alfaariss.oa.helper.stylesheet;

import java.io.File;
import java.util.Hashtable;
import java.util.Vector;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sourceforge.wurfl.core.CustomWURFLHolder;
import net.sourceforge.wurfl.core.Device;
import net.sourceforge.wurfl.core.WURFLHolder;
import net.sourceforge.wurfl.core.WURFLManager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.helper.IHelper;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.session.factory.ISessionFactory;
import com.alfaariss.oa.helper.stylesheet.handler.IStyleSheetHandler;
import com.alfaariss.oa.util.validation.SessionValidator;

/**
 * StyleSheet engine.
 * Will provide the requested party with the requestor specific stylesheet.
 *  
 * @author JVG
 * @author MHO
 * @author Alfa & Ariss
 */
public class StyleSheetEngine
{
    private final static String DEFAULT_CSS = "/openaselect/etc/css/default.css";
    private final static String DEFAULT_MOBILE_CSS = "/openaselect/etc/css/mobile.css";
    private final static String WURFL_CAPABILITY_IS_WIRELESS_DEVICE = "is_wireless_device";
    
    private static Log _logger;
    private ISessionFactory _sessionFactory;
    private IConfigurationManager _configurationManager;
    private IStyleSheetHandler _oHandler;
    private String _sDefaultLocation;
    private String _sDefaultMobileLocation;
    private boolean _bEnabled;
    private Hashtable<String, String> _htDeviceSpecificStyleSheets;
    private WURFLManager _wurflManager;
    
    /**
     * Constructor.
     */
    public StyleSheetEngine()
    {
        _logger = LogFactory.getLog(StyleSheetEngine.class);
        _bEnabled = false;
        _htDeviceSpecificStyleSheets = new Hashtable<String, String>();
        _wurflManager = null;
    }

    /**
     * @return TRUE if this engine can be used.
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }

    /**
     * Reads following configuration and creates the optional handler object:
     * <pre>
     * &lt;helpers&gt;
     *  &lt;stylesheet&gt;
     *      &lt;default location="" /&gt;
     *      &lt;handler class="" /&gt;
     *  &lt;/stylesheet&gt;
     * &lt;/helpers&gt;
     * </pre>
     * 
     * @param configurationManager The configuration manager.
     * @param eStyleSheet The configuration section.
     * @param sHelperID The id of the helper.
     * @param context Servlet context.
     * @throws OAException If initialization fails.
     */
    public void start(IConfigurationManager configurationManager, 
        Element eStyleSheet, String sHelperID, ServletContext context) throws OAException
    {
        try
        {
            _configurationManager = configurationManager;
            
            Engine oEngine = Engine.getInstance();
            _sessionFactory = oEngine.getSessionFactory();
            
           _bEnabled = true;
            String sEnabled = _configurationManager.getParam(
                eStyleSheet, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    _bEnabled = false;
                else if (!sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _logger.error(
                        "Invalid 'enabled' item found in configuration: " + sEnabled);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            if (_bEnabled)
            {
                _sDefaultLocation = DEFAULT_CSS;
                _sDefaultMobileLocation = DEFAULT_MOBILE_CSS;
                
                Element eDefault = _configurationManager.getSection(
                    eStyleSheet, "default");
                if (eDefault == null)
                {
                    _logger.warn("No optional 'default' section found in configuration");
                }
                else
                {
                    _sDefaultLocation = _configurationManager.getParam(eDefault, "location");
                    _sDefaultMobileLocation = _configurationManager.getParam(eDefault, "mobile");
                    if (_sDefaultLocation == null && _sDefaultMobileLocation == null)
                    {
                        _logger.error("No 'location' or 'mobile' parameter in 'default' section found in configuration");
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    if (_sDefaultLocation == null)
                    {                      
                        _logger.info("No 'location' parameter in 'default' section found in configuration");
                        _sDefaultLocation = DEFAULT_CSS;
                    }
                    
                    if (_sDefaultMobileLocation == null)
                    {
                        _logger.info("No 'mobile' parameter in 'default' section found in configuration");
                        _sDefaultMobileLocation = DEFAULT_MOBILE_CSS;
                    }
                }
                _logger.info("Using default stylesheet location: " + _sDefaultLocation);
                _logger.info("Using default mobile stylesheet location: " + _sDefaultMobileLocation);
                                
                Element eHandler = _configurationManager.getSection(
                    eStyleSheet, "handler");
                if (eHandler == null)
                    _logger.info(
                        "No optional stylesheet handler configured, using default stylesheet");
                else
                    _oHandler = createHandler(eHandler, sHelperID);
                
                //instantiate optional wurflManager
                String rootPath = null;
                File rootFile = null;
                Element eWURFL = _configurationManager.getSection(
                    eStyleSheet, "wurfl");
                if (eWURFL != null)
                {
                    Element eLocation = _configurationManager.getSection(
                        eWURFL, "location");
                    if (eLocation == null)
                    {
                        _logger.error("No 'location' section in 'wurfl' section found in configuration");
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }

                    rootPath = _configurationManager.getParam(eLocation, "uri");
                    if (rootPath == null)
                    {
                        _logger.info("No 'uri' parameter in 'location' section found in configuration, trying file");
                        String sWURFLFile= _configurationManager.getParam(eLocation, "file");
                        if (sWURFLFile == null)
                        {
                            _logger.error("No 'file' parameter in 'location' section found in configuration");
                            throw new OAException(SystemErrors.ERROR_CONFIG_READ);                            
                        }
                        rootFile = resolveFile(sWURFLFile, context);                        
                    }
                   
                    //load optional patches                    
                    Vector<String> patchesPath = null;                    
                    Vector<File> patchesFile = null;
                    Element ePatch = _configurationManager.getSection(
                        eLocation, "patch");
                    while (ePatch != null)
                    {
                        if(rootFile != null) //Configured by file
                        {
                            String sWURFLPatchFile = _configurationManager.getParam(ePatch, "file"); 
                            if (sWURFLPatchFile == null)
                            {
                                _logger.error("No 'file' parameter in 'patch' section found in configuration");
                                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                            }
                            File patchFile = 
                                resolveFile(sWURFLPatchFile, context);
                            if (patchesFile == null)
                                patchesFile = new Vector<File>();
                            patchesFile.add(patchFile);
                        }
                        else //Configured by uri's
                        {
                            String sWURFLPatchURI = _configurationManager.getParam(ePatch, "uri"); 
                            if (sWURFLPatchURI == null)
                            {
                                _logger.error("No 'uri' parameter in 'patch' section found in configuration");
                                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                            }
                            if (patchesPath == null)
                                patchesPath = new Vector<String>();
                            patchesPath.add(sWURFLPatchURI);
                             
                        }
                        ePatch = _configurationManager.getNextSection(ePatch);                        
                    }
                    
                    //Create WURFLHolder
                    WURFLHolder wurflHolder = null;
                    if(rootFile != null) //File configured
                    {
                        if (patchesFile != null)
                        {
                            wurflHolder = new CustomWURFLHolder(
                                rootFile, patchesFile.toArray(new File[]{}));
                        }
                        else
                        {
                            _logger.info("No wurfl patches configured");
                            wurflHolder = new CustomWURFLHolder(rootFile);
                        }
                    }
                    else //uri configured
                    {
                        if (patchesPath != null)
                        {
                            wurflHolder = new CustomWURFLHolder(rootPath, 
                                patchesPath.toArray(new String[]{}));
                        }
                        else
                        {
                            _logger.info("No wurfl patches configured");
                            wurflHolder = new CustomWURFLHolder(rootPath);
                        }
                    }                    
                  
                    
                    _wurflManager = wurflHolder.getWURFLManager();                      
                    if (_wurflManager == null)
                    {
                        _logger.error("Could not instantiate WURFL Manager");
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    Element eDevices = _configurationManager.getSection(
                        eWURFL, "devices");
                    if (eDevices != null )
                    {
                        Element eDevice = _configurationManager.getSection(
                            eDevices, "device");
                        if (eDevice == null)
                        {
                            _logger.error(
                                "No 'device' parameter in 'device_specific' section found in configuration");
                            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                        }
                        while (eDevice!= null)
                        {
                            String sDeviceId = _configurationManager.getParam(eDevice, "id");
                            if (sDeviceId == null)
                            {
                                _logger.error(
                                    "No 'id' parameter in 'device' section found in configuration");
                                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                            }
                            String sDeviceCSSLocation = _configurationManager.getParam(eDevice, "location");
                            if (sDeviceCSSLocation == null)
                            {
                                _logger.error(
                                    "No 'location' parameter in 'device' section found in configuration");
                                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                            }
                            _htDeviceSpecificStyleSheets.put(sDeviceId, sDeviceCSSLocation);
                            eDevice = _configurationManager.getNextSection(eDevice);
                        }
                    }
                    else
                    {
                        _logger.info("No device specific stylesheet defined");
                    }
                }
                else
                {
                    _logger.info("No 'wurfl' configuration section found in configuration, disabling wurfl");
                }
            }             
            _logger.info("StyleSheet engine: " + (_bEnabled ? "enabled" : "disabled"));
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Error during start", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
    }
    
    /**
     * Let the request be processed by the configured handler.
     *
     * If the request could not be processed by the handler or there is no 
     * handler configured then the requestor will be redirected to the default 
     * css.
     * 
     * @param oRequest the servlet request
     * @param oResponse the servlet response
     * @throws OAException If processing fails.
     */
    public void process(HttpServletRequest oRequest, 
        HttpServletResponse oResponse) throws OAException
    {
        try
        {
            String sSessionID = oRequest.getParameter(ISession.ID_NAME);
            if (sSessionID == null || sSessionID.trim().length() == 0)
            {
                _logger.debug("No session id in request");
                throw new StyleSheetException(SystemErrors.ERROR_INTERNAL);
            }
            
            if (!SessionValidator.validateDefaultSessionId(sSessionID))
            {
                _logger.warn("Invalid session id in request: " + sSessionID);
                throw new StyleSheetException(SystemErrors.ERROR_INTERNAL);
            }
            
            ISession oSession = _sessionFactory.retrieve(sSessionID);
            if (oSession == null)
            {
                _logger.warn("Session not found: " + sSessionID);
                throw new StyleSheetException(SystemErrors.ERROR_INTERNAL);
            }
            
            if (_oHandler != null )
            {
                if(_wurflManager != null 
                    && _sDefaultMobileLocation != null 
                    && isWirelessDevice(oRequest))
                    _oHandler.process(oSession, oResponse, true);
                else
                    _oHandler.process(oSession, oResponse, false);
            }
        }
        catch (StyleSheetException e)
        {
            //do nothing, handled in finally
        }
        catch (OAException e)
        {
            _logger.error("Error during processing", e);
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Error during processing", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            if (!oResponse.isCommitted())
            {              
                if(_wurflManager != null 
                    && _htDeviceSpecificStyleSheets.size() > 0)
                    sendDeviceSpecific(oRequest, oResponse);
                else
                    sendDefault(oRequest,oResponse);
            }
        }
        
    }

    /**
     * Stop the stylesheet engine
     * @see IHelper#destroy()
     */
    public void stop()
    {
        _bEnabled = false;
        if (_oHandler != null)
            _oHandler.stop();
        _sessionFactory = null;
        
        _wurflManager = null;
        if (_htDeviceSpecificStyleSheets != null)
            _htDeviceSpecificStyleSheets.clear();
    }    
       
    //creates an IStyleSheetHandler object with class for name
    private IStyleSheetHandler createHandler(Element eHandler, String sHelperID) 
        throws OAException
    {
        IStyleSheetHandler oHandler = null;
        try
        {
            String sClass = _configurationManager.getParam(eHandler, "class");
            if (sClass == null)
            {
                _logger.error(
                    "No 'class' item found in 'handler' section found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Class cHandler = null;
            try
            {
                cHandler = Class.forName(sClass);
            }
            catch (Exception e)
            {
                _logger.error("Class not found: " + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
    
            try
            {
                oHandler = (IStyleSheetHandler)cHandler.newInstance();
            }
            catch(Exception e)
            {
                _logger.error("Could not create instance of " + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            oHandler.start(_configurationManager, eHandler, sHelperID);
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
        return oHandler;
    }

    //redirects to the default css
    private void sendDefault(HttpServletRequest oRequest,HttpServletResponse oResponse)
    {
        try
        {
            if (!oResponse.isCommitted())
            {
                if(_wurflManager != null && _sDefaultMobileLocation != null && isWirelessDevice(oRequest))
                        oResponse.sendRedirect(_sDefaultMobileLocation);
                else
                    oResponse.sendRedirect(_sDefaultLocation);    
            }  
            else
                _logger.debug("Could not send default response");
        }
        catch(Exception e)
        {
            _logger.warn("Internal error during sending the default response", e);
        }
    }

    private boolean isWirelessDevice(HttpServletRequest oRequest)
    {
        Device device = _wurflManager.getDeviceForRequest(oRequest);
        _logger.debug("Device detected with id: " + device.getId());
        return new Boolean(device.getCapability(WURFL_CAPABILITY_IS_WIRELESS_DEVICE));
    }
    
    private void sendDeviceSpecific(HttpServletRequest oRequest, HttpServletResponse oResponse)
    {
        try
        {            
            Device device = _wurflManager.getDeviceForRequest(oRequest);
            _logger.debug("Device detected with id: "+device.getId());
            if (_htDeviceSpecificStyleSheets.containsKey(device.getId()))
                oResponse.sendRedirect(_htDeviceSpecificStyleSheets.get(device.getId()));
            else
            {
                _logger.debug("No device specific stylesheet available");
                sendDefault(oRequest, oResponse);
            }
        }
        catch(Exception e)
        {
            _logger.warn("Internal error during sending the device specific response", e);
        }
    }

    //Read a file 
    private File resolveFile(
        String filename, ServletContext context) throws OAException
    {
        //Try absolute
        File file = new File(filename);
        if (!file.exists())
        {
            _logger.warn("File not found at: " + file.getAbsolutePath());
            
            //Try user directory
            String sUserDir = System.getProperty("user.dir");
            StringBuffer sbFile = new StringBuffer(sUserDir);
            if (!sUserDir.endsWith(File.separator))
                sbFile.append(File.separator);
            sbFile.append(file);            
            file = new File(sbFile.toString());
            if (!file.exists())
            {
                _logger.warn("File not found at: " + file.getAbsolutePath());
                                
                if(context != null)
                {
                    //Try WEB-INF/conf
                    String sWebInf = context.getRealPath("WEB-INF");
                    sbFile = new StringBuffer(sWebInf);
                    if (!sbFile.toString().endsWith(File.separator))
                        sbFile.append(File.separator);
                    sbFile.append("conf").append(File.separator);
                    sbFile.append(filename);
                    file = new File(sbFile.toString());
                    if (!file.exists())
                    {
                        _logger.error("File not found: " + filename);
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                }
                else
                {
                    _logger.error("File not found: " + filename);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
        }
        _logger.info("Using file: " + file.getAbsolutePath());
        return file;
        
    }
}
