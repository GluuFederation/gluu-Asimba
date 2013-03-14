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
package com.alfaariss.oa.helper.stylesheet.handler;

import java.util.Hashtable;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
import com.alfaariss.oa.helper.stylesheet.StyleSheetException;
import com.alfaariss.oa.util.session.ProxyAttributes;

/**
 * Returns a stylesheet by redirects.
 *
 * @author JVG
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.3
 */
abstract public class AbstractStyleSheetHandler implements IStyleSheetHandler
{
	private final static String SESSION_PROXY_ARP_TARGET = "arp_target";
    /** name of the location property */
    protected final static String PROPERTY_LOCATION = ".location";
    /** name of the mobile location property */
    protected final static String PROPERTY_LOCATION_MOBILE = ".location_mobile";
   
    /** requestor specific stylesheets */
    protected Hashtable<String, String> _htRequestorStyleSheets;
    /** requestor mobile specific stylesheets */
    protected Hashtable<String, String> _htMobileRequestorStyleSheets;
    /** requestorpool specific stylesheets */
    protected Hashtable<String, String> _htRequestorPoolStyleSheets;
    /** requestorpool mobile specific stylesheets */
    protected Hashtable<String, String> _htMobileRequestorPoolStyleSheets;
    /** requestorpool factory */
    protected IRequestorPoolFactory _oRequestorPoolFactory;
    /** id of this stylesheet helper */
    protected String _sHelperID;

    private Log _logger;
    
    /**
     * Contructor.
     */
    public AbstractStyleSheetHandler()
    {
        _logger = LogFactory.getLog(AbstractStyleSheetHandler.class);
        _sHelperID = null;
    }
    
    /**
     * @see com.alfaariss.oa.helper.stylesheet.handler.IStyleSheetHandler#process(com.alfaariss.oa.api.session.ISession, javax.servlet.http.HttpServletResponse, boolean)
     */
    abstract public void process(ISession session, HttpServletResponse response, boolean isWireless)
        throws StyleSheetException;

    /**
     * @see com.alfaariss.oa.helper.stylesheet.handler.IStyleSheetHandler#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element, java.lang.String)
     */
    public void start(IConfigurationManager configurationManager, 
        Element config, String sHelperID) throws OAException
    {
        try
        {
            _sHelperID = sHelperID;
            
            Engine oEngine = Engine.getInstance();
            _oRequestorPoolFactory = oEngine.getRequestorPoolFactory();
            
            readResourceConfig(configurationManager, config);
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
     * @see com.alfaariss.oa.helper.stylesheet.handler.IStyleSheetHandler#stop()
     */
    public void stop()
    {
        if (_htRequestorStyleSheets != null)
            _htRequestorStyleSheets.clear();
        if(_htMobileRequestorStyleSheets != null)
            _htMobileRequestorStyleSheets.clear();
        
        if (_htRequestorPoolStyleSheets != null)
            _htRequestorPoolStyleSheets.clear();
        if (_htMobileRequestorPoolStyleSheets != null)
            _htMobileRequestorPoolStyleSheets.clear();
        
        _oRequestorPoolFactory = null;
    }

    /**
     * Resolves the stylesheet location from config or model.
     * @param session authentication session
     * @param isWireless TRUE if the requestor is a wireless device.
     * @return stylesheet location
     * @throws StyleSheetException if stylesheet could not be resolved
     */
    protected String resolveStyleSheetLocation(ISession session, boolean isWireless)
        throws StyleSheetException
    {
        String sStyleSheet = null;
        try
        {
        	ISessionAttributes sessionAttributes = session.getAttributes();
        	
            String sRequestorID = session.getRequestorId();
            IRequestor requestor = _oRequestorPoolFactory.getRequestor(sRequestorID);
            if (requestor == null)
            {
                _logger.warn("No requestor found with id: " + sRequestorID);
                throw new StyleSheetException(SystemErrors.ERROR_INTERNAL);
            }
            
            String sArpTarget = (String)sessionAttributes.get(ProxyAttributes.class, SESSION_PROXY_ARP_TARGET);
            
            //resolve mobile location 
            if (isWireless)
            {
            	if (sArpTarget != null)
            	{//resolve location from config by with requestor id is the value of the arp_target
            		sArpTarget = sArpTarget.replaceAll("@", "_");
            		
            		StringBuffer sbArpTarget = new StringBuffer(_sHelperID);
            		sbArpTarget.append(PROPERTY_LOCATION_MOBILE);
            		sbArpTarget.append(".");
            		sbArpTarget.append(sArpTarget);
            		if (requestor.isProperty(sbArpTarget.toString()))
            		{//check if the [helper id].location.[arp_target] is configured as requestor property
            			sStyleSheet = (String)requestor.getProperty(sbArpTarget.toString());
            		}
            	}
            	if (sStyleSheet == null)
                {
            		if(_htMobileRequestorStyleSheets != null && _htMobileRequestorStyleSheets.containsKey(sRequestorID))
            			sStyleSheet = _htMobileRequestorStyleSheets.get(sRequestorID);
            		else if(requestor.isProperty(_sHelperID + PROPERTY_LOCATION_MOBILE))
            			sStyleSheet = (String)requestor.getProperty(_sHelperID + PROPERTY_LOCATION_MOBILE);
            		
            		if (sStyleSheet == null) {
            			RequestorPool oPool = _oRequestorPoolFactory.getRequestorPool(sRequestorID);
	                    if (oPool == null) {
	                        _logger.warn("No requestor pool found for requestor with id: " + sRequestorID);
	                        throw new StyleSheetException(SystemErrors.ERROR_INTERNAL);
	                    }
                    
	                    if (_htMobileRequestorPoolStyleSheets != null && _htMobileRequestorPoolStyleSheets.containsKey(oPool.getID()))
	                        sStyleSheet = _htMobileRequestorPoolStyleSheets.get(oPool.getID());
	                    else if (oPool.isProperty(_sHelperID + PROPERTY_LOCATION_MOBILE))
	                        sStyleSheet = (String)oPool.getProperty(_sHelperID + PROPERTY_LOCATION_MOBILE);
            		}
                }
            }
            else
            {
            	if (sArpTarget != null)
            	{//resolve location from config by with requestor id is the value of the arp_target
            		sArpTarget = sArpTarget.replaceAll("@", "_");
            		
            		StringBuffer sbArpTarget = new StringBuffer(_sHelperID);
            		sbArpTarget.append(PROPERTY_LOCATION);
            		sbArpTarget.append(".");
            		sbArpTarget.append(sArpTarget);
            		
            		if (requestor.isProperty(sbArpTarget.toString()))
            		{//check if the [helper id].location.[arp_target] is configured as requestor property
            			sStyleSheet = (String)requestor.getProperty(sbArpTarget.toString());
            			_logger.debug("Found specific stylesheet by 'arp_target': " + sStyleSheet);
            		}
            		else
            		{
            			_logger.debug("No requestor property found with name: " + sbArpTarget.toString());
            		}
            	}
            	
            	if (sStyleSheet == null)
            	{
            		if (_htRequestorStyleSheets != null && _htRequestorStyleSheets.containsKey(sRequestorID))
                        sStyleSheet = _htRequestorStyleSheets.get(sRequestorID);
                    else if (requestor.isProperty(_sHelperID + PROPERTY_LOCATION))
                        sStyleSheet = (String)requestor.getProperty(_sHelperID + PROPERTY_LOCATION);
            		
            		if (sStyleSheet == null)
            		{//resolve location from pool: first try configured; second try requestor pool property 
                        RequestorPool oPool = 
                                _oRequestorPoolFactory.getRequestorPool(sRequestorID);
            			
                        if (oPool == null)
                        {
                            _logger.warn("No requestor pool found for requestor with id: " 
                                + sRequestorID);
                            throw new StyleSheetException(SystemErrors.ERROR_INTERNAL);
                        }
                        
                        if (_htRequestorPoolStyleSheets != null && _htRequestorPoolStyleSheets.containsKey(oPool.getID()))
                            sStyleSheet = _htRequestorPoolStyleSheets.get(oPool.getID());
                        else if (oPool.isProperty(_sHelperID + PROPERTY_LOCATION))
                            sStyleSheet = (String)oPool.getProperty(_sHelperID + PROPERTY_LOCATION);
            		}
            	}
            }
        }
        catch (StyleSheetException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Unable to resolve stylesheet location", e);
            throw new StyleSheetException(SystemErrors.ERROR_INTERNAL);
        }
        
        return sStyleSheet;
    }

    //reads the css location configured per requestorpool
    private void readResourceConfig(IConfigurationManager configurationManager, 
        Element config) throws OAException
    {
        try
        {
            _htRequestorPoolStyleSheets = new Hashtable<String, String>();
            _htMobileRequestorPoolStyleSheets = new Hashtable<String, String>();
            
            Element eRequestorPools = configurationManager.getSection(config, "requestorpools");
            if (eRequestorPools == null)
            {
                _logger.warn("No 'requestorpools' section found in configuration");
            }
            else
            {
                Element eRequestorPool = configurationManager.getSection(eRequestorPools, "requestorpool");
                if (eRequestorPool == null)
                {
                    _logger.error("No 'requestorpool' section found in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                while (eRequestorPool != null)
                {
                    String sId = configurationManager.getParam(eRequestorPool, "id");
                    if (sId == null)
                    {
                        _logger.error("No 'id' parameter in 'requestorpool' section found in configuration");
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
    
                    String sLocation = configurationManager.getParam(eRequestorPool, "location");
                    if (sLocation == null)
                    {
                        _logger.error("No 'location' parameter in 'requestorpool' section found in configuration");
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    String sMobileLocation = configurationManager.getParam(eRequestorPool, "mobile");
                    if (sMobileLocation != null)
                    {
                        _htMobileRequestorPoolStyleSheets.put(sId, sMobileLocation);
                    }
                    else
                    {
                        _logger.info("No optional 'mobile' parameter in 'requestorpool' section found in configuration");        
                    }
                    
                    if (_htRequestorPoolStyleSheets.containsKey(sId))
                    {
                        _logger.error("Configured 'id' parameter is not unique: " + sId);
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    _htRequestorPoolStyleSheets.put(sId, sLocation);
                    
                    eRequestorPool = configurationManager.getNextSection(eRequestorPool);
                }
            }
            
            _htRequestorStyleSheets = new Hashtable<String, String>();
            _htMobileRequestorStyleSheets = new Hashtable<String, String>();
            
            Element eRequestors = configurationManager.getSection(config, "requestors");
            if (eRequestors == null)
            {
                _logger.warn("No 'requestors' section found in configuration");
            }
            else
            {
                Element eRequestor = configurationManager.getSection(eRequestors, "requestor");
                if (eRequestor == null)
                {
                    _logger.error("No 'requestor' section found in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                while (eRequestor != null)
                {
                    String sId = configurationManager.getParam(eRequestor, "id");
                    if (sId == null)
                    {
                        _logger.error("No 'id' parameter in 'requestor' section found in configuration");
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
    
                    String sLocation = configurationManager.getParam(eRequestor, "location");
                    if (sLocation == null)
                    {
                        _logger.error("No 'location' parameter in 'requestor' section found in configuration");
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    String sMobileLocation = configurationManager.getParam(eRequestor, "mobile");
                    if (sMobileLocation != null)
                    {
                        _htMobileRequestorStyleSheets.put(sId, sMobileLocation);
                    }
                    else
                    {
                        _logger.info("No optional 'mobile' parameter in 'requestor' section found in configuration");        
                    }
                    
                    if (_htRequestorStyleSheets.containsKey(sId))
                    {
                        _logger.error("Configured 'id' parameter is not unique: " + sId);
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    _htRequestorStyleSheets.put(sId, sLocation);

                    
                    eRequestor = configurationManager.getNextSection(eRequestor);
                }
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Error during config reading", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
}
