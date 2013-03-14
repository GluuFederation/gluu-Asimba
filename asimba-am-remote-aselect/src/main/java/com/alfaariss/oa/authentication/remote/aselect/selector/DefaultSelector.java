/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authentication.remote.aselect.selector;

import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.DetailedUserException;
import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.authentication.remote.aselect.Warnings;
import com.alfaariss.oa.authentication.remote.aselect.idp.storage.ASelectIDP;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.server.Server;
import com.alfaariss.oa.sso.authentication.web.IWebAuthenticationMethod;

/**
 * Default remote A-Select Server selector implementation.
 *
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class DefaultSelector implements ISelector
{
    private final static String DEFAULT_ID_PARAM = "organization_id";
    private final static String REQUEST_PARAM_ORGANIZATIONS = "organizations";
    
    private static final String DEFAULT_JSP_SELECTION = "/ui/sso/authn/remoteaselect/aselect.jsp";
    
    private Log _logger;
    private String _sTemplatePath;
    private String _sIdParameter;
    private boolean _bShowAlways;
    
    /**
     * Constructor.
     */
    public DefaultSelector()
    {
        _logger = LogFactory.getLog(DefaultSelector.class);
    }

    /**
     * @see ISelector#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager,
        Element eConfig) throws OAException
    {
        try
        {
            _sTemplatePath = DEFAULT_JSP_SELECTION;
            _sIdParameter = DEFAULT_ID_PARAM;
            Element eTemplate = oConfigurationManager.getSection(eConfig, "template");
            if (eTemplate == null)
            {
                _logger.warn("No optional 'template' section found in configuration, using defaults");
            }
            else
            {
                _sTemplatePath = oConfigurationManager.getParam(eTemplate, "path");
                if (_sTemplatePath == null)
                {
                    _sTemplatePath = DEFAULT_JSP_SELECTION;
                    _logger.warn("No optional 'path' parameter found in 'template' section in configuration, using default");
                }
                _sIdParameter = oConfigurationManager.getParam(eTemplate, "id_param");
                if (_sIdParameter == null)
                {
                    _sIdParameter = DEFAULT_ID_PARAM;
                    _logger.warn("No optional 'id_param' parameter found in 'template' section in configuration, using default");
                }
            }
            _logger.info("Using JSP: " + _sTemplatePath);
            _logger.info("Using ID parameter: " + _sIdParameter);
            
            _bShowAlways = false;
            String sShowAlways = oConfigurationManager.getParam(eConfig, "always_show_select_form");
            if (sShowAlways != null)
            {
                if (sShowAlways.equalsIgnoreCase("TRUE"))
                {
                    _bShowAlways = true;
                }
                else if (!sShowAlways.equalsIgnoreCase("FALSE"))
                {
                    _logger.error("Invalid value for 'always_show_select_form' parameter found in in configuration: " + sShowAlways);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            _logger.info("Forced show selection always: " + _bShowAlways);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during start", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
    }

    /**
     * @see com.alfaariss.oa.authentication.remote.aselect.selector.ISelector#stop()
     */
    public void stop()
    {
        //do nothing
    }

    /**
     * Resolve the remote organization by user selection. 
     * @see com.alfaariss.oa.authentication.remote.aselect.selector.ISelector#resolve(
     *  javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, 
     *  com.alfaariss.oa.api.session.ISession, java.util.List, java.lang.String, java.util.List)
     */
    public ASelectIDP resolve(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession,
        List<ASelectIDP> listOrganizations, String sMethodName, 
        List<Warnings> oWarnings) throws OAException
    {
        ASelectIDP oSelectedOrganization = null;
        try
        {
            _logger.debug("Resolving remote server id");
            
            String sOrganizationId = oRequest.getParameter(_sIdParameter);
            if (sOrganizationId != null)
            {
                for(ASelectIDP oOrganization : listOrganizations)
                {
                    if (oOrganization.getID().equals(sOrganizationId))
                    {
                        oSelectedOrganization = oOrganization;
                        break; //found the organization, no need to loop any further
                    }
                } 
            }
            else if (listOrganizations.size() == 1 && !_bShowAlways)
                return listOrganizations.get(0);
            
            if (oSelectedOrganization == null)
            {
                oSession.persist();
                forwardUser(oRequest, oResponse, oSession, listOrganizations, 
                    sMethodName, oWarnings);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during resolve", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
        
        return oSelectedOrganization;
        
    }

    private void forwardUser(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession, 
        List<ASelectIDP> listOrganizations, String sMethodName, 
        List<Warnings> oWarnings) throws OAException
    {
        try
        {
            //set request attributes
            oRequest.setAttribute(ISession.ID_NAME, oSession.getId());
            oRequest.setAttribute(ISession.LOCALE_NAME, oSession.getLocale());                       
            oRequest.setAttribute(REQUEST_PARAM_ORGANIZATIONS, listOrganizations);
            if(oWarnings != null)
                oRequest.setAttribute(DetailedUserException.DETAILS_NAME, oWarnings);
            oRequest.setAttribute(
                IWebAuthenticationMethod.AUTHN_METHOD_ATTRIBUTE_NAME, sMethodName);
            oRequest.setAttribute(Server.SERVER_ATTRIBUTE_NAME, 
                Engine.getInstance().getServer());
       
            RequestDispatcher oDispatcher = oRequest.getRequestDispatcher(_sTemplatePath);
            if(oDispatcher == null)
            {
                _logger.warn("There is no request dispatcher supported with name: " 
                    + _sTemplatePath);                    
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            _logger.debug("Forward user to: " + _sTemplatePath);
            
            oDispatcher.forward(oRequest, oResponse);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during forward", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
        }
    }
}
