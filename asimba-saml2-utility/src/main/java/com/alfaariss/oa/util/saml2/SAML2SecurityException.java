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

import org.opensaml.saml2.core.StatusCode;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;

/**
 * SAML2 security exception.
 * 
 * This exception can be used when a responder refuses to process the request
 * e.g. invalid signature or requestor ID. 
 * 
 * For internal errors {@link OAException} should be used. 
 * 
 * This exception should result in a HTTP 403 Forbidden status.

 * @author EVB
 * @author Alfa & Ariss
 */
public class SAML2SecurityException extends Exception
{
   
    /** serialVersionUID */
    private static final long serialVersionUID = 5216495310600419070L;
    private RequestorEvent event; 

    /**
     * Create a simple <code>SAML2SecurityException</code>.
     *    
     * @param event The event.
     * @see StatusCode 
     */
    public SAML2SecurityException(RequestorEvent event)
    {
        super();
        this.event = event;
    }

    /**
     * @return the event
     */
    public RequestorEvent getEvent()
    {
        return event;
    }     

    /**
     * Retrieve the event.
     * @see java.lang.Throwable#getMessage()
     */
    public String getMessage()
    {       
        return event.name();
    }
}