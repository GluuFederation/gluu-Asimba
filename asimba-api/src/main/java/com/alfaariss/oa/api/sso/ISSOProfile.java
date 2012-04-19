
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
package com.alfaariss.oa.api.sso;

import javax.servlet.ServletContext;

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Interface for requestor profiles.
 *
 * Requestor profiles are components which are started by the OA server 
 * and implement authentication protocols such as Open ID and A-Select. 
 * 
 * @author MHO
 * @author EVB 
 * @author Alfa & Ariss
 *
 */
public interface ISSOProfile
{
       
    /**
     * Start the SSO profile.
     * 
     * @param context The servlet context.
     * @param configurationManager the configuration manager. 
     * @param eParent The parent configuration.
     * @param eSpecific The profile specific configuration.
     * @throws OAException If starting fails
     */
    public void init(ServletContext context, 
        IConfigurationManager configurationManager, Element eParent, 
        Element eSpecific) throws OAException;
    
    /**
     * Stop the SSO profile.
     */
    public void destroy();  
    
    /**
     * Returns the configured ID of the profile. 
     * @return The profile id.
     * @since 1.0
     */
    public String getID();
}
