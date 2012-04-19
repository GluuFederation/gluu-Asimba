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
package com.alfaariss.oa.sso.web;
import java.io.IOException;
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
import com.alfaariss.oa.api.sso.ISSOProfile;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.sso.SSOService;
import com.alfaariss.oa.sso.authentication.web.AuthenticationManager;
import com.alfaariss.oa.sso.authorization.web.PreAuthorizationManager;
import com.alfaariss.oa.sso.web.profile.logout.LogoutProfile;
import com.alfaariss.oa.sso.web.profile.user.UserProfile;
import com.alfaariss.oa.sso.web.profile.web.WebProfile;

/**
 * Web based Authentication and SSO Component.
 *
 * This Web SSO is part of OA. OA is a professionalized A-Select SSO product 
 * targeting existing and new A-Select customers.
 * <br><br>
 * The WebSSO is the controller servlet which uses JSP pages as view and
 * the {@link SSOService} as business service (model in MVC).
 * 
 * <h4>WebSSO functionality:</h4>
 * 
 * <dl>
 *  <dt>Display TGT</dt>
 *      <dd>Show the users TGT if available (No session required)</dd>
 *  <dt>Pre authorization</dt>
 *      <dd>{@link PreAuthorizationManager}</dd>
 *  <dt>SSO</dt>
 *      <dd>Check for a valid and sufficient SSO session</dd>
 *  <dt>Authentication selection</dt>
 *      <dd>Select a profile to authenticate with</dd>
 *  <dt>Authentication</dt>
 *      <dd>{@link AuthenticationManager}</dd>
 * </dl>
 * <br><br>
 * 
 * The WebSSO should be called by an authentication profile to perform the 
 * actual authentication process.
 * 
 * @author MHO
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class WebSSOServlet extends HttpServlet implements IComponent
{
    /** The name of the Web SSO TGT cookie.  */
    public static final String TGT_COOKIE_NAME = "oa_sso_id"; 
    
    /** serialVersionUID */
    private static final long serialVersionUID = -2883420193342476092L;
    
    private static Log _logger;
    
    private AuthenticationManager _authenticationManager;
    private ServletContext _context;
    private Engine _engine;
    private Map<String, ISSOProfile> _mapSSOProfiles;
    private WebProfile _defaultSSOProfile;
    
    /**
     * Create a new Web based Authentication and SSO Component.
     */
    public WebSSOServlet()
    {
        _logger = LogFactory.getLog(WebSSOServlet.class);
        _engine = Engine.getInstance();
        _authenticationManager = new AuthenticationManager();
        _mapSSOProfiles = new Hashtable<String, ISSOProfile>();
    }
    
    /**
     * Starts SSO profiles.
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
            _logger.fatal("Error starting WebSSO", e);
            stop(); //Stop started profiles and helpers
            throw new ServletException(
                SystemErrors.toHexString(e.getCode()));
        }
        catch (Exception e)
        {           
            _logger.fatal("Error starting WebSSO", e);
            stop(); //Stop started profiles and helpers
            throw new ServletException(
                SystemErrors.toHexString(SystemErrors.ERROR_INTERNAL));
        }
        
    }

    /**
     * Start the WebSSO.
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager configurationManager, 
        Element config) throws OAException
    {       
        Element eWebSSO = configurationManager.getSection(null, "websso");
        if(eWebSSO == null)
        {
            _logger.error("No 'websso' configuration found");
            throw new OAException(SystemErrors.ERROR_INIT);
        }
        
        //Authentication configuration
        Element eAuthentication = configurationManager.getSection(
            eWebSSO, "authentication");
        if(eAuthentication == null)
        {
            _logger.error("No authentication configuration found");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        _authenticationManager.start(configurationManager, eAuthentication);  
        
        _defaultSSOProfile = new WebProfile(_authenticationManager);
        _defaultSSOProfile.init(_context, configurationManager, eWebSSO, null);
        addSSOProfile(_defaultSSOProfile.getID(), _defaultSSOProfile);
        _logger.info("Started WebSSO Profile: " + _defaultSSOProfile.getID());
        
        UserProfile userProfile = new UserProfile();
        userProfile.init(_context, configurationManager, eWebSSO, null);
        addSSOProfile(userProfile.getID(), userProfile);
        
        LogoutProfile logoutProfile = new LogoutProfile(_authenticationManager);
        logoutProfile.init(_context, configurationManager, eWebSSO, null);
        addSSOProfile(logoutProfile.getID(), logoutProfile);
        
        Element eProfiles = configurationManager.getSection(eWebSSO, "profiles");
        if (eProfiles != null)
            loadProfiles(configurationManager, eWebSSO, eProfiles);
        
        _logger.info("Started SSO Profiles");
    }

    /**
     * Restart the WebSSO.
     * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
     */
    public void restart(Element eConfig) throws OAException
    {
        synchronized(this)
        {
            _logger.info("Restarting WebSSO");
            stop();                       
            IConfigurationManager config = _engine.getConfigurationManager();
            start(config, eConfig);
        }
    }

    /**
     * Process the WebSSO HTTP requests.
     * @throws IOException 
     * 
     * @see javax.servlet.http.HttpServlet#service(
     *  javax.servlet.http.HttpServletRequest, 
     *  javax.servlet.http.HttpServletResponse)
     *  
     */
    public void service(HttpServletRequest oRequest, 
        HttpServletResponse oResponse) throws ServletException, IOException
    {    
        try
        {
            if(_defaultSSOProfile == null)
                oResponse.sendError(
                    HttpServletResponse.SC_SERVICE_UNAVAILABLE, oRequest.getRequestURI());
            
            String sTarget = resolveTarget(oRequest);
            if (sTarget == null)
                _defaultSSOProfile.service(oRequest, oResponse);
            else
            {
                ISSOProfile ssoProfile = _mapSSOProfiles.get(sTarget);
                if (ssoProfile != null & (ssoProfile instanceof IService))
                {
                    ((IService)ssoProfile).service(oRequest, oResponse);
                }
                else
                {//if profile not found by target, then use default profile
                    _defaultSSOProfile.service(oRequest, oResponse);
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
     * Destroys the Servlet.
     * @see javax.servlet.Servlet#destroy()
     */
    public void destroy()
    {
        stop();               
        _engine.removeComponent(this);
        _logger.info("Stopped: WebSSO");
    }
    
    /**
     * Stop the WebSSO.
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    public synchronized void stop()
    {
        if(_authenticationManager != null)
            _authenticationManager.stop();
        
        //Stop profiles
        for(ISSOProfile profile : _mapSSOProfiles.values())
        {
            profile.destroy();
        } 
        //Clear profiles
        _mapSSOProfiles.clear();
        _logger.info("Stopped SSO Profiles");   
        
        if (_defaultSSOProfile != null)
        {
            _defaultSSOProfile.destroy();
            _logger.info("Stopped WebSSO Profile");  
        }
    }

    //Start the profiles
    private void loadProfiles(IConfigurationManager config, Element eWebSSO, 
        Element eProfiles) throws OAException
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
                
                ISSOProfile profile = null;
                try
                {
                    Class profileClass = Class.forName(sClass);
                    profile = (ISSOProfile)profileClass.newInstance();
                }
                catch (ClassNotFoundException e)
                {
                    _logger.error(
                        "Configured SSO profile class could not be found: " 
                        + sClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);    
                }
                catch (InstantiationException e)
                {
                    _logger.error(
                        "Configured SSO profile class could not be instantiated: " 
                        + sClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                catch (IllegalAccessException e)
                {
                    _logger.error(
                        "Configured SSO profile class could not be accessed: " 
                        + sClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                catch (ClassCastException e)
                {
                    _logger.error(
                        "Configured SSO profile class isn't of type 'ISSOProfile': " 
                        + sClass, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }                        
               
                profile.init(_context, config, eWebSSO, eProfile);
                if (_mapSSOProfiles.containsKey(profile.getID()))
                {
                    _logger.error("Configured SSO profile id is not unique: " 
                        + profile.getID());
                    throw new OAException(SystemErrors.ERROR_INIT);
                }
                
                addSSOProfile(profile.getID(), profile);
                _logger.info("Started SSO profile: " + profile.getID());
               
                //Get next
                eProfile = config.getNextSection(eProfile);
            }
        }
        catch(OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not load SSO profiles", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private String resolveTarget(HttpServletRequest servletRequest) 
    {
        String sRequestURI = servletRequest.getRequestURI();
        if (!sRequestURI.endsWith("/"))
            sRequestURI = sRequestURI + "/";
        sRequestURI = sRequestURI.toLowerCase();
        
        String sContextPath = servletRequest.getContextPath();
        String sServletPath = servletRequest.getServletPath();
        
        String target = sRequestURI.substring(sContextPath.length() + sServletPath.length() + 1);// +1 for trailing /
        if (target != null && target.length() > 1)// >1: target must be larger then '/'
        {
            int iIndex = target.indexOf("/");
            if (target.length() -1 > iIndex)
            {//target must be splitted to first /
                return target.substring(0, iIndex + 1);
            }
            return target;
        }
                
        return null;
    }
    
    private void addSSOProfile(String profileID, ISSOProfile profile)
    {
        String id = profileID;
        if (!profileID.endsWith("/"))
            id = id + "/";
        
        _mapSSOProfiles.put(id.toLowerCase(), profile);
    }
}