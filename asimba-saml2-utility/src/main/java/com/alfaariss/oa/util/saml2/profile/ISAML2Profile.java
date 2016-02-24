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
package com.alfaariss.oa.util.saml2.profile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.metadata.EntityDescriptor;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow;
import com.alfaariss.oa.util.saml2.ISAML2Requestors;

/**
 * SAML Profile interface.
 *
 * @author MHO
 * @author EVB
 */
public interface ISAML2Profile
{
    /**
     * Process a specific SAML2 profile.
     * 
     * @param oServletRequest The request.
     * @param oServletResponse The response.
     * @throws OAException If processing failed.
     */
    public void process(HttpServletRequest oServletRequest,
        HttpServletResponse oServletResponse) throws OAException;
    
    /**
     * Initializes the profile.
     * 
     * @param configurationManager The configuration manager.
     * @param config The profile configuration section.
     * @param entityDescriptor The metadata entity descriptor.
     * @param sBaseUrl The URL base of the OA profile.
     * @param sWebSSOPath The target location path of the WebSSO.
     * @param requestors The configured requestors.
     * @param issueInstantWindow IssueInstant acceptance window object.
     * @param sProfileID The OA Profile id.
     * @throws OAException If initialization fails.
     */
    public void init(IConfigurationManager configurationManager, 
        Element config, EntityDescriptor entityDescriptor, String sBaseUrl, 
        String sWebSSOPath, ISAML2Requestors requestors, 
        SAML2IssueInstantWindow issueInstantWindow, String sProfileID) 
        throws OAException;
    
    /**
     * Removes the object from memory.
     */
    public void destroy();
    
    /**
     * Returns the ID of the profile.
     * @return String The profile ID.
     */
    public String getID();
}
