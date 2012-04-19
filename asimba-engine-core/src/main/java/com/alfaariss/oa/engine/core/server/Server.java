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
package com.alfaariss.oa.engine.core.server;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.attribute.AttributeException;

/**
 * Creates an object with Server specific items.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class Server
{
    private static Log _logger;    
    private String _sID;
    private String _sFriendlyName;
    private Organization _organization;
    private String _sPreAuthorizationProfile;
    private String _sPostAuthorizationProfile;
    
    /**
     * Attribute name for adding the server object as an attribute to a 
     * <code>Map</code>, request, session, or application.
     */
    public final static String SERVER_ATTRIBUTE_NAME = "serverInfo";
        
    /**
     * Creates the object.
     * @param oConfigurationManager the configuration manager where the 
     * configuration can be read from.
     * @param eConfig the configuration section for this object
     * @throws OAException 
     */
    public Server(IConfigurationManager oConfigurationManager, Element eConfig) 
        throws OAException
    {
        try
        {
            _logger = LogFactory.getLog(Server.class);
            
            _sID = oConfigurationManager.getParam(eConfig, "id");
            if (_sID == null || _sID.trim().length() <= 0) 
            {
                _logger.error("No correct 'id' item found in 'server' section in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            _sFriendlyName = oConfigurationManager.getParam(eConfig, "friendlyname");
            if (_sFriendlyName == null || _sFriendlyName.trim().length() <= 0)
            {
                _logger.error("No correct 'friendlyname' item found in 'server' section in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eOrganization = oConfigurationManager.getSection(eConfig, "organization");
            if (eOrganization == null)
            {
                _logger.error("No 'organization' section found in 'server' section in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _organization = new Organization(oConfigurationManager, eOrganization);
            
            Element eAuthorization = oConfigurationManager.getSection(eConfig, "authorization");
            if (eAuthorization != null)
            {
                Element ePre = oConfigurationManager.getSection(eAuthorization, "pre");
                if (ePre != null)
                {
                    _sPreAuthorizationProfile = oConfigurationManager.getParam(ePre, "profile");
                }
                Element ePost = oConfigurationManager.getSection(eAuthorization, "post");
                if (ePost != null)
                {
                    _sPostAuthorizationProfile = oConfigurationManager.getParam(ePost, "profile");
                }
            }
        }
        catch(OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialize", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Returns the server id. 
     * @return the id
     */
    public String getID()
    {
        return _sID;
    }
    
    /**
     * Returns the server friendly name. 
     * @return the friendly name
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }
    
    /**
     * Returns the organization object.
     * @return the organization
     */
    public Organization getOrganization()
    {
        return _organization;
    }
    
    /**
     * Return pre authorization profile id.
     * @return Pre Authorization Profile id or <code>null</code> if not 
     * configured.
     */
    public String getPreAuthorizationProfileID()
    {
        return _sPreAuthorizationProfile;
    }
    
    /**
     * Return post authorization profile id.
     * @return Post Authorization Profile id or <code>null</code> if not 
     * configured.
     */
    public String getPostAuthorizationProfileID()
    {
        return _sPostAuthorizationProfile;
    }
}
