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
package com.alfaariss.oa.util.saml2;

import org.asimba.util.saml2.assertion.SAML2TimestampWindow;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Object containing functionality to verify the IssueInstant of a SAML request.
 * 
 * Update 2012/12/21; Skeleton implementation based on new parent class [mdobrinic]
 *
 * @author mdobrinic
 * @author MHO
 * @author Alfa & Ariss
 */
public class SAML2IssueInstantWindow extends SAML2TimestampWindow
{
    /** serialVersionUID */
    private static final long serialVersionUID = -8468697103482727320L;

    /**
     * Default constructor using default window.
     */
    public SAML2IssueInstantWindow() {
    	super();
    }
    /**
     * Constructor using configurable window.
     * 
     * @param configurationManager The configuration manager
     * @param eConfig The config section for this object
     * @throws OAException If configuration is invalid
     */
    public SAML2IssueInstantWindow (IConfigurationManager configurationManager, 
        Element eConfig) throws OAException
    {
    	super(configurationManager, eConfig);
    }
    
}

