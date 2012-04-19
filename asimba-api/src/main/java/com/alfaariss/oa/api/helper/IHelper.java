
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
package com.alfaariss.oa.api.helper;

import javax.servlet.ServletContext;

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.IOptional;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Interface for helpers.
 *
 * Helpers are components which are started by the OA server and implement 
 * functionality which can be used in profiles, methods, etc. 
 *    
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public interface IHelper extends IOptional
{
    /**
     * Start the helper.
     * 
     * @param context The servlet context.
     * @param configurationManager the configuration manager. 
     * @param eConfig The configuration section for this helper.
     * @throws OAException If starting fails
     */
    public void init(ServletContext context, IConfigurationManager configurationManager
        , Element eConfig) throws OAException;
    
    /**
     * Stop the helper.
     */
    public void destroy();    
}
