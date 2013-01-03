/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.sso.web.profile.ssoquery.whitelist;

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Interface for whitelist implementations.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public interface IWhitelist
{
    
    /**
     * Initializes the whitelist.
     * @param configurationManager The configuration manager.
     * @param config The configuration section.
     * @throws OAException If config was invalid.
     */
    public void start(IConfigurationManager configurationManager, Element config) throws OAException;
    
    /**
     * Stops the whitelist.
     */
    public void stop();
    
    /**
     * Verifies if the supplied item is whitelisted.
     *  
     * @param item The item to be checked.
     * @return TRUE if the supplied item is whitelisted.
     * @throws OAException If an internal ocurred during verification.
     */
    public boolean isWhitelisted(String item) throws OAException;
}
