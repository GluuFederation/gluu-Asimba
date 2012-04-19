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
package com.alfaariss.oa.helper.stylesheet.handler;

import javax.servlet.http.HttpServletResponse;

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.helper.stylesheet.StyleSheetException;

/**
 * Requestor specific StyleSheet handler.
 * <br>
 * Retrieves and performs an action in response to a request for a style sheet.
 * 
 * @author JVG
 * @author MHO
 * @author Alfa & Ariss
 */
public interface IStyleSheetHandler
{
    /**
     * Starts the handler. 
     * @param oConfigurationManager configuration manager
     * @param eConfig the configuration section
     * @param sHelperID The id of the helper
     * @throws OAException if starting fails
     * @since 1.3
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig, String sHelperID) throws OAException;
    
    /**
     * Stops the handler.
     */
    public void stop();
    
    /**
     * Retrieves a requestor specific stylesheet and performs an action to 
     * send this stylesheet to the requested party.
     * @param session The user authentication session
     * @param oResponse the servlet response
     * @param isWireless true if its a wireless device
     * @throws StyleSheetException if stylesheet retrieval fails
     * @since 1.3
     */
    public void process(ISession session, HttpServletResponse oResponse, boolean isWireless) 
        throws StyleSheetException;
}
