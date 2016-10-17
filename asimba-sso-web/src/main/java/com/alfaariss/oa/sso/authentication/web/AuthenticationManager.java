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
package com.alfaariss.oa.sso.authentication.web;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.authentication.IAuthenticationMethod;
import com.alfaariss.oa.api.authentication.IAuthenticationProfile;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.engine.core.authentication.AuthenticationMethod;
import com.alfaariss.oa.sso.SSOException;

/**
 * Manager for loading authentication methods and executing 
 * authentication profiles.
 *
 * This manager is called by the engine. At start-up, this manager
 * is responsible for loading the classes for the different authentication
 * methods that are defined in the OpenASelect main configuration
 * file. At run-time, the manager can be asked to run an authentication
 * profile. It will load the authentication profile details and delegate
 * the actual authentication steps to the corresponding authentication methods.
 * 
 * @author MHO
 * @author JRE
 * @author Alfa & Ariss
 *
 */
public class AuthenticationManager implements IComponent
{
    private final static String ATTRIBUTE_CURRENT_METHOD = "CURRENT_METHOD";
    private Map<String, IWebAuthenticationMethod> _mapAuthenticationMethods;
    private Log _logger;
    private IConfigurationManager _configManager;
    
    /**
     * AuthenticationManager default constructor.
     */
    public AuthenticationManager()
    {
        _logger = LogFactory.getLog(AuthenticationManager.class); 
        _mapAuthenticationMethods = new HashMap<String, IWebAuthenticationMethod>();
    }
    
    /**
     * Authenticates a user by an authentication profile.
     *
     * @param oSelectedAuthNProfile The Authentication profile selected by the user.
     * @param oRequest The servlet request.
     * @param oResponse The servlet response.
     * @param oSession The user session object.
     * @throws SSOException if authentication fails 
     *  due to internal error in manager itself.
     * @throws OAException if authentication fails due to internal error.
     */
    public void authenticate(IAuthenticationProfile oSelectedAuthNProfile,
        HttpServletRequest oRequest, HttpServletResponse oResponse,
        ISession oSession) throws SSOException, OAException
    {
        try
        {
            if (oSelectedAuthNProfile == null)
                throw new IllegalArgumentException("No selected authN profile supplied");
            
            if (!oSelectedAuthNProfile.isEnabled())
            {
                _logger.error("Authentication profile is disabled: " 
                    + oSelectedAuthNProfile.getID());
                throw new SSOException(SystemErrors.ERROR_INTERNAL);
            }
            
            List<IAuthenticationMethod> listMethods = oSelectedAuthNProfile.getAuthenticationMethods();
            
            IAuthenticationMethod oAuthMethodBean = null;
            ISessionAttributes oAttributes = oSession.getAttributes();

            SessionState oState = oSession.getState();
            if (oState == SessionState.AUTHN_SELECTION_OK)
            {//get first authentication method which is enabled
                oAuthMethodBean = getAuthenticationMethod(listMethods, 
                    oAuthMethodBean, oSelectedAuthNProfile.getID());   
                oAttributes.put(AuthenticationManager.class, 
                    ATTRIBUTE_CURRENT_METHOD, oAuthMethodBean);
                oSession.setState(SessionState.AUTHN_IN_PROGRESS);
            }
            else if (oState == SessionState.AUTHN_IN_PROGRESS)
            {//get authentication method which previously returned AUTHN_IN_PROGRESS
                oAuthMethodBean = (AuthenticationMethod)oAttributes.get(AuthenticationManager.class, ATTRIBUTE_CURRENT_METHOD);
            }
            else
            {
                _logger.error("Session state invalid: " + oState);
                throw new SSOException(SystemErrors.ERROR_INTERNAL);
            }
            
            IWebAuthenticationMethod oWebAuthMethod = _mapAuthenticationMethods.get(oAuthMethodBean.getID());
            if (oWebAuthMethod == null)
            {
                _logger.error("No authentication method found with id: " + oAuthMethodBean.getID());
                throw new SSOException(SystemErrors.ERROR_INTERNAL);
            }
            
            while (oSession.getState() == SessionState.AUTHN_IN_PROGRESS) 
            {
                if (!oWebAuthMethod.isEnabled())
                {
                    _logger.error("Authentication method is disabled: " + oWebAuthMethod.getID());
                    throw new SSOException(SystemErrors.ERROR_INTERNAL);
                }
                
                switch (oWebAuthMethod.authenticate(oRequest, oResponse, oSession))
                {
                    case AUTHN_METHOD_SUCCESSFUL:
                    {
                        oAuthMethodBean = getAuthenticationMethod(listMethods, 
                            oAuthMethodBean, oSelectedAuthNProfile.getID());
                        if (oAuthMethodBean != null)
                        {
                            oAttributes.put(AuthenticationManager.class, 
                                ATTRIBUTE_CURRENT_METHOD, oAuthMethodBean);
                            if (!_mapAuthenticationMethods.containsKey(oAuthMethodBean.getID()))
                            {
                                _logger.error("Authentication method not available: " 
                                    + oAuthMethodBean.getID());
                                throw new SSOException(SystemErrors.ERROR_INTERNAL);
                            }
                            oWebAuthMethod = _mapAuthenticationMethods.get(oAuthMethodBean.getID());
                        }
                        else
                            oSession.setState(SessionState.AUTHN_OK);
                        
                        break;
                    }
                    case AUTHN_METHOD_IN_PROGRESS:
                    {
                        return;
                    }
                    case USER_UNKNOWN:
                    {
                        oSession.setState(SessionState.USER_UNKNOWN);
                        break;
                    }
                    case USER_DISABLED:
                    {
                        oSession.setState(SessionState.USER_BLOCKED);
                        break;
                    }
                    case USER_CANCELLED:
                    {
                        oSession.setState(SessionState.USER_CANCELLED);
                        break;
                    }
                    case AUTHN_METHOD_NOT_REGISTERED:
                    case AUTHN_METHOD_NOT_SUPPORTED:
                    {
                        oSession.setState(SessionState.AUTHN_NOT_SUPPORTED);
                        break;
                    }
                    case REQUEST_INVALID:
                    default:
                    {
                        oSession.setState(SessionState.AUTHN_FAILED);
                    }
                }
            } 
        }
        catch(OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Internal error during authentication", e);
            throw new SSOException(SystemErrors.ERROR_INTERNAL);
        } 
    }

    /**
     * @see IComponent#restart(org.w3c.dom.Element)
     */
    @Override
    public void restart(Element eConfig) throws OAException
    {
        synchronized(this)
        {
            stop();
            start(_configManager, eConfig);
        }
    }

    /**
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws OAException
    {
        try
        {
            _configManager = oConfigurationManager;
            
            Element eMethods = _configManager.getSection(eConfig, "methods");
            if (eMethods == null)
            {
                _logger.error("No 'methods' section found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eMethod = _configManager.getSection(eMethods, "method");
            while (eMethod != null) 
            {
                IWebAuthenticationMethod oAuthenticationMethod = createAuthenticationMethod(eMethod);
                if (!oAuthenticationMethod.isEnabled())
                {
                    _logger.debug("Authentication method is disabled: " 
                        + oAuthenticationMethod.getID());
                }
                else
                {
                    if (_mapAuthenticationMethods.containsKey(oAuthenticationMethod.getID()))
                    {
                        _logger.error("Authentication method is not unique: " 
                            + oAuthenticationMethod.getID());
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    _mapAuthenticationMethods.put(oAuthenticationMethod.getID(), oAuthenticationMethod);    
                }
                
                eMethod = _configManager.getNextSection(eMethod);
            }
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
     * @see IComponent#stop()
     */
    public void stop()
    {
        if (_mapAuthenticationMethods != null)
        {
            for (IWebAuthenticationMethod oMethod: _mapAuthenticationMethods.values())
                oMethod.stop();
    
            _mapAuthenticationMethods.clear();
        }
    }
    
    /**
     * Returns all Authentication Methods. 
     * @return An unmodifyable collection with Authentication Methods.
     * @since 1.4
     */
    public Map<String, IWebAuthenticationMethod> getAuthenticationMethods()
    {
        return Collections.unmodifiableMap(_mapAuthenticationMethods);
    }
    
    private IWebAuthenticationMethod createAuthenticationMethod(Element eMethod) 
        throws SSOException
    {
        IWebAuthenticationMethod oAuthenticationMethod = null;
        try
        {
            String sClass = _configManager.getParam(eMethod, "class");
            if (sClass == null)
            {
                _logger.error("No 'class' item found in 'methods' section found in configuration");
                throw new SSOException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Class cMethod = null;
            try
            {
                cMethod = Class.forName(sClass);
            }
            catch (Exception e)
            {
                _logger.error("Class not found: " + sClass, e);
                throw new SSOException(SystemErrors.ERROR_CONFIG_READ);
            }
    
            try
            {
                oAuthenticationMethod = (IWebAuthenticationMethod)cMethod.newInstance();
            }
            catch(Exception e)
            {
                _logger.error("Could not create instance of " + sClass, e);
                throw new SSOException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            oAuthenticationMethod.start(_configManager, eMethod);
        }
        catch (SSOException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during object creation", e);
            throw new SSOException(SystemErrors.ERROR_INTERNAL);
        } 
        return oAuthenticationMethod;
    }
    
    private IAuthenticationMethod getAuthenticationMethod(
        List<IAuthenticationMethod> listMethods, 
        IAuthenticationMethod currentMethod, String sAuthNProfile) throws SSOException
    {
        IAuthenticationMethod oMethod = null;
        int iCurrentMethod = 0;
        int iMax = listMethods.size();
        if(iMax == 0)
        {
            _logger.error("No authentication methods available in pool: " 
                + sAuthNProfile);
            throw new SSOException(SystemErrors.ERROR_INTERNAL);
        }
        
        if (currentMethod != null)
        {
            iCurrentMethod = listMethods.indexOf(currentMethod);
            if (iCurrentMethod == -1)
            {
                _logger.error("Current authentication method unavailable: " 
                    + currentMethod.getID());
                throw new SSOException(SystemErrors.ERROR_INTERNAL);
            }
            iCurrentMethod++;
        }
        if (iCurrentMethod < iMax)
            oMethod = listMethods.get(iCurrentMethod);
        
        return oMethod;
    }
}