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

import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;

/**
 * SAML2 status exception.
 * 
 * This exception can be used when a request or response can not be executed 
 * due to an error. For internal errors {@link OAException} should be used. 
 * 
 * This exception van be used to construct a {@link Status} object.
 * 
 * Top level status must be one of:  
 * <ul>
 *  <li>{@link StatusCode#REQUESTER_URI}</li>
 *  <li>{@link StatusCode#RESPONDER_URI}</li>
 *  <li>{@link StatusCode#VERSION_MISMATCH_URI}</li>
 * </ul> 
 * @author EVB
 * @author Alfa & Ariss
 */
public class StatusException extends Exception
{
   
    /** serialVersionUID */
    private static final long serialVersionUID = 5216495310600419070L;
    private RequestorEvent event; 
    private String topLevelstatusCode;
    private String secondLevelStatusCode;
    private String requestorID;
    
    /**
     * Create a simple <code>StatusException</code>.
     *    
     * @param event The event.
     * @param topLevelstatusCode The top level status code.
     * @see StatusCode 
     */
    public StatusException(RequestorEvent event, String topLevelstatusCode)
    {
        super();
        this.event = event;
        this.requestorID = null;
        this.topLevelstatusCode = topLevelstatusCode;
    }

    /**
     * Create an extended <code>StatusException</code>.
     *
     * @param event The event.
     * @param topLevelstatusCode The top-level status code.
     * @param secondLevelStatusCode The second-level status code.
     * @see StatusCode 
     */
    public StatusException (
        RequestorEvent event, String topLevelstatusCode, String secondLevelStatusCode)
    {
        super();
        this.event = event;
        this.requestorID = null;
        this.topLevelstatusCode = topLevelstatusCode;
        this.secondLevelStatusCode = secondLevelStatusCode;
    }

    /**
     * Create a simple <code>StatusException</code> with requestor.
     *    
     * @param event The event.
     * @param requestorID The requestor.
     * @param topLevelstatusCode The top level status code.
     * @see StatusCode 
     */
    public StatusException(String requestorID,
        RequestorEvent event, String topLevelstatusCode)
    {
        super();
        this.event = event;
        this.requestorID = requestorID;
        this.topLevelstatusCode = topLevelstatusCode;
    }

    /**
     * Create an extended <code>StatusException</code> with requestor.
     *
     * @param event The event.
     * @param requestorID The requestor.
     * @param topLevelstatusCode The top-level status code.
     * @param secondLevelStatusCode The second-level status code.
     * @see StatusCode 
     */
    public StatusException (String requestorID, RequestorEvent event,  
        String topLevelstatusCode, String secondLevelStatusCode)
    {
        super();
        this.event = event;
        this.requestorID = requestorID;
        this.topLevelstatusCode = topLevelstatusCode;
        this.secondLevelStatusCode = secondLevelStatusCode;
    }
    
    /**
     * @return the event
     */
    public RequestorEvent getEvent()
    {
        return event;
    }

    /**
     * @return the topLevelstatusCode
     */
    public String getTopLevelstatusCode()
    {
        return topLevelstatusCode;
    }

    /**
     * @return the secondLevelStatusCode
     */
    public String getSecondLevelStatusCode()
    {
        return secondLevelStatusCode;
    }
        

    /**
     * @return the requestorID
     */
    public String getRequestorID()
    {
        return requestorID;
    }

    /**
     * retrieve the extended message.
     * Returns <code>{@link #getTopLevelstatusCode()} - 
     *  {@link #getSecondLevelStatusCode()}</code>.
     * @see java.lang.Throwable#getMessage()
     */
    public String getMessage()
    {
        StringBuffer sb = new StringBuffer(topLevelstatusCode);
        if(secondLevelStatusCode != null)
            sb.append(" - ").append(secondLevelStatusCode);       
        return sb.toString();
    }
}