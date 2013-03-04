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
package com.alfaariss.oa;

import java.io.IOException;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.IService;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.helper.IHelper;
import com.alfaariss.oa.api.profile.IRequestorProfile;
import com.alfaariss.oa.engine.core.Engine;

/**
 * OA Main Servlet.
 * 
 * Starts the profiles and helpers.
 * 
 * All requests are dispatched to an appropriate helper or profile. 
 * If no helper or profile is found for the request a  
 * {@link HttpServletResponse#SC_NOT_FOUND} is sent.
 *
 * @author MHO
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class OAServlet extends HttpServlet implements IComponent
{
    /** serialVersionUID */
    private static final long serialVersionUID = 4028520551455105728L;
    
    private Map<String, IRequestorProfile> _profiles;
    private Map<String, IHelper> _helpers;
    private Log _logger;
    private ServletContext _context;
    private Engine _engine;
    
    /**
     * Starts the OA Servlet.
     */
    public OAServlet()
    {
        _logger = LogFactory.getLog(OAServlet.class);
        _engine = Engine.getInstance();
        _profiles = new Hashtable<String, IRequestorProfile>();
        _helpers = new Hashtable<String, IHelper>();                       
    }
    
    /**
     * Starts requestor profiles and helpers.
     * @see javax.servlet.Servlet#init(javax.servlet.ServletConfig)
     */
    public void init(ServletConfig oServletConfig) throws ServletException
    {
        try
        {
            _context = oServletConfig.getServletContext();    
            
            //Retrieve configuration manager            
            IConfigurationManager config = _engine.getConfigurationManager();
             
            //Start profiles and helpers
            start(config, null);
            
            //Add as listener           
            _engine.addComponent(this);            
        }
        catch(OAException e)
        {           
            _logger.fatal("Error starting Asimba Server", e);
            stop(); //Stop started profiles and helpers
            throw new ServletException(
                SystemErrors.toHexString(e.getCode()));
        }
        catch (Exception e)
        {           
            _logger.fatal("Error starting Asimba Server", e);
            stop(); //Stop started profiles and helpers
            throw new ServletException(
                SystemErrors.toHexString(SystemErrors.ERROR_INTERNAL));
        }
        
    }
    
    /**
     * Start the profiles and helpers
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager config, Element eConfig)
        throws OAException
    {
        //Load profiles
        Element eProfiles = config.getSection(null, "profiles");
        if(eProfiles == null)
        {
            _logger.warn("No 'profiles' section found in configuration");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        loadProfiles(config, eProfiles);
        
        //Load helpers
        Element eHelpers = config.getSection(null, "helpers");
        if(eHelpers == null)
        {
            _logger.warn("No 'helpers' section found in configuration");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        loadHelpers(config, eHelpers);
    }
    
    /**
     * Process HTTP requests.
     * 
     * Retrieve an enabled requestor profile or helper for the given request 
     * and delegate the request using the following algorithm:
     * 
     * <dl>
     *  <dt>type (helper or profile)</dt>
     *  <dd>{@link HttpServletRequest#getRequestURI()} from 
     *      {@link HttpServletRequest#getContextPath()} till '/' minus slashes</dd>
     *  <dt>id of helper or profile</dt>
     *  <dd>{@link HttpServletRequest#getRequestURI()} 
     *      first '/' till second '/' minus slashes</dd>
     * </dl>
     * 
     * @see javax.servlet.http.HttpServlet#service(
     *  javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    public void service(HttpServletRequest oRequest, 
        HttpServletResponse oResponse) throws ServletException, IOException
    {
        try
        {
            String sRequestURI = oRequest.getRequestURI();
            
            //Check if profiles are available
            if(_profiles.isEmpty() && _helpers.isEmpty())
                oResponse.sendError(
                    HttpServletResponse.SC_SERVICE_UNAVAILABLE, sRequestURI);
            
            //Retrieve profile
            String sContextPath = oRequest.getContextPath();
            String sServletPath = oRequest.getServletPath();
            
            
            //type = uri  - context
            String sType = sRequestURI.substring(sContextPath.length());
            if(sType.length() <= 1)
            {
                //No profile or helper requested
                oResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
            }
            else
            {
                //type minus slashes 
                sType = sType.substring(1, sType.length());
                int index = sType.indexOf('/');
                if(index <= 1)
                {
                    _logger.debug("Bad request: no id in path: " + sServletPath);
                    //No id requested
                    oResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);                                      
                }
                else
                {
                    
                    String sId = sType.substring(index+1, sType.length()); //id minus slashes 
                    sType = sType.substring(0, index);
                    if(_logger.isDebugEnabled())
                        _logger.debug("Processing: " + sType + " request");
                                                        
                    //sId = sId.substring(1, sId.length());
                    index = sId.indexOf('/');                   
                    if(index > 0)
                    {
                        //remove suffix
                        sId = sId.substring(0, index);
                    }
                                                           
                    try
                    {
                        ServiceTypes type = ServiceTypes.valueOf(sType);
                        switch (type)
                        {
                            case helpers:
                            {
                                IHelper helper = _helpers.get(sId);
                                if(helper == null || !(helper instanceof IService))
                                    oResponse.sendError(
                                        HttpServletResponse.SC_NOT_FOUND, 
                                        sRequestURI);
                                else if(!helper.isEnabled())
                                    oResponse.sendError(
                                        HttpServletResponse.SC_SERVICE_UNAVAILABLE, 
                                        sRequestURI);
                                else
                                    ((IService)helper).service(oRequest, oResponse);
                                break;
                            }
                            case profiles:
                            {
                                IRequestorProfile profile = _profiles.get(sId);
                                if(profile == null || !(profile instanceof IService))
                                    oResponse.sendError(
                                        HttpServletResponse.SC_NOT_FOUND, 
                                        sRequestURI);
                                else
                                    ((IService)profile).service(oRequest, oResponse);
                                break;
                            }
                        }
                    }
                    catch(IllegalArgumentException e)
                    {
                        _logger.debug("Bad request", e);
                        //Invalid type requested
                        oResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);    
                    }
                    catch(NullPointerException e)
                    {
                        _logger.debug("Bad request", e);
                        //No type requested
                        oResponse.sendError(HttpServletResponse.SC_BAD_REQUEST); 
                    }
                }
            }
          
            //send okay if no response is sent yet
            if (!oResponse.isCommitted())
                oResponse.sendError(HttpServletResponse.SC_OK);
        }
        catch (OAException e)
        {
            _logger.error("Could not process request", e);
            if (!oResponse.isCommitted())
                oResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
        catch (Exception e)
        {
            _logger.fatal("Could not process request due to internal error", e);
            if (!oResponse.isCommitted())
                oResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }      
    }

    /**
     * Restart. 
     * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
     */
    public void restart(Element eConfig) throws OAException
    {
        synchronized(this)
        {
            _logger.info("Restarting profiles");
            stop();                       
            IConfigurationManager config = _engine.getConfigurationManager();
            start(config, eConfig);
        }
    }
    
    /**
     * Stops the OAServlet.
     * @see javax.servlet.GenericServlet#destroy()
     */
    public void destroy()
    {
        stop();        
        _engine.removeComponent(this);
        _logger.info("Stopped OA Servlet");        
        super.destroy();       
    }

    /**
     * Stop all profiles and helpers.
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    public synchronized void stop()
    {
        //Stop profiles
        Collection<IRequestorProfile> profiles = _profiles.values();
        for(IRequestorProfile profile : profiles)
        {
            profile.destroy();
        } 
        //Clear profiles
        _profiles.clear();    
        _logger.info("Stopped profiles");
        
       //Stop profiles
        Collection<IHelper> helpers = _helpers.values();
        for(IHelper helper : helpers)
        {
            helper.destroy();
        } 
        //Clear profiles
        _helpers.clear();
        _logger.info("Stopped helpers");
    }

    //Start the profiles
    private void loadProfiles(
        IConfigurationManager config, Element eProfiles) throws OAException
    {
        try
        {
            Element eProfile = config.getSection(eProfiles, "profile");
            while(eProfile != null)
            {            
                String sClass = config.getParam(eProfile, "class");
                if (sClass == null)
                {
                    _logger.error(
                        "No 'class' parameter found in 'profile' section");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                IRequestorProfile profile = null;
                try
                {
                    Class profileClass = Class.forName(sClass);
                    profile = (IRequestorProfile)profileClass.newInstance();
                }
                catch (ClassNotFoundException e)
                {
                    _logger.error(
                        "Configured profile class could not be found: " 
                        + sClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);    
                }
                catch (InstantiationException e)
                {
                    _logger.error(
                        "Configured profile class could not be instantiated: " 
                        + sClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                catch (IllegalAccessException e)
                {
                    _logger.error(
                        "Configured profile class could not be accessed: " 
                        + sClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                catch (ClassCastException e)
                {
                    _logger.error(
                        "Configured profile class isn't of type 'IRequestorProfile': " 
                        + sClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }                        
               
                profile.init(_context, config, eProfile);
                _profiles.put(profile.getID(),profile);
                _logger.info("Started requestor profile: " + profile.getID());
               
                //Get next
                eProfile = config.getNextSection(eProfile);
            }
            
            if(_profiles.isEmpty())
                _logger.info("No requestor profiles configured");
            else
                _logger.info("Started Profiles");
        }
        catch(OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not load profiles", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    //Start the helpers
    private void loadHelpers(
        IConfigurationManager config, Element eHelpers) throws OAException
    {
        try
        {
            Element eHelper = config.getSection(eHelpers, "helper");
            while(eHelper != null)
            {            
                String sId = config.getParam(eHelper, "id");
                if (sId == null)
                {
                    _logger.error("No 'id' parameter found in 'helper' section");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                String sClass = config.getParam(eHelper, "class");
                if (sClass == null)
                {
                    _logger.error(
                        "No 'class' parameter found in 'helper' section: " + sId);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                IHelper helper = null;
                try
                {
                    Class helperClass = Class.forName(sClass);
                    helper = (IHelper)helperClass.newInstance();
                }
                catch (ClassNotFoundException e)
                {
                    _logger.error(
                        "Configured helper class could not be found: " 
                        + sClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);    
                }
                catch (InstantiationException e)
                {
                    _logger.error(
                        "Configured helper class could not be instantiated: " 
                        + sClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                catch (IllegalAccessException e)
                {
                    _logger.error(
                        "Configured helper class could not be accessed: " 
                        + sClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                catch (ClassCastException e)
                {
                    _logger.error(
                        "Configured helper class isn't of type 'IHelper': " 
                        + sClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }                        
               
                helper.init(_context, config, eHelper);
                _helpers.put(sId,helper);
                _logger.info("Started helper: " + sId);
               
                //Get next
                eHelper = config.getNextSection(eHelper);
            }
            
            if(_helpers.isEmpty())
                _logger.info("No helpers configured");
            else
                _logger.info("Started helpers");
        }
        catch(OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not load helpers", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    private enum ServiceTypes
    {
        /** helpers */
        helpers,
        /** profiles */
        profiles,
    }
}