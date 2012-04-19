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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.authentication.remote.aselect.Warnings;
import com.alfaariss.oa.authentication.remote.aselect.idp.storage.ASelectIDP;

/**
 * Remote A-Select Server selector interface.
 *
 * Interface for a custom selection of a remote server by the user.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface ISelector
{
    /**
     * Initializes the object with its configuration.
     * 
     * @param oConfigurationManager Configuration manager
     * @param eConfig Configuration section
     * @throws OAException if starting fails
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws OAException;
    
    /**
     * Stops the object.
     */
    public void stop();
    
    /**
     * Resolve a remote A-Select Server id.
     * 
     * @param oRequest The HTTP request
     * @param oResponse The HTTP response
     * @param oSession The user session
     * @param listOrganizations ASelectOrganization objects
     * @param sMethodName The authentication emthod friendly name.
     * @param oWarnings Optional warnings to be displayed.
     * @return The remote ASelectOrganization
     * @throws OAException if resolving fails
     */
    public ASelectIDP resolve(HttpServletRequest oRequest, 
        HttpServletResponse oResponse, ISession oSession, 
        List<ASelectIDP> listOrganizations, String sMethodName, 
        List<Warnings> oWarnings) 
        throws OAException;
    
}
