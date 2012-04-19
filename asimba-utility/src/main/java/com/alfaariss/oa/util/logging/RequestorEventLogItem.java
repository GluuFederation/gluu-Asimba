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
package com.alfaariss.oa.util.logging;

import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.session.SessionState;

/**
 * An OA logitem for logging requestor event messages.
 * @author MHO
 * @author EVB
 * @author JRE
 * @author Alfa & Ariss
 *
 */
public class RequestorEventLogItem extends AbstractEventLogItem
{
    private final static Integer LOG_EVENT_TYPE = new Integer(2);
    private RequestorEvent _event = null;
  
    /**
     * Create a new <code>RequestorEventLogItem</code>.    
     * @param sessionId The session ID.
     * @param tgtId The TGT id.
     * @param type The identifier of the phase in the authentication proces.
     * @param requestorEvent The event.
     * @param userId The user id.
     * @param organizationId The user organization id.
     * @param ipAddress The client IP address of the user.
     * @param requestor The requestor of the authentication session.
     * @param authority The Authority the caller represents.
     * @param message Additional information.
     * @since 1.2
     */    
    public RequestorEventLogItem (String sessionId, String tgtId, 
        SessionState type, RequestorEvent requestorEvent, String userId, 
        String organizationId, String ipAddress, String requestor, 
        IAuthority authority, String message)
    {
        super(sessionId, tgtId, type, userId, organizationId, ipAddress, 
            requestor, authority, message);
        _event = requestorEvent;      
    }

    /**
     * Create a new <code>RequestorEventLogItem</code>.    
     * @param sessionId The session ID.
     * @param tgtId The TGT id.
     * @param type The identifier of the phase in the authentication proces.
     * @param requestorEvent The event.
     * @param userId The user id.
     * @param ipAddress The client IP address of the user.
     * @param requestor The requestor of the authentication session.
     * @param authority The Authority the caller represents.
     * @param message Additional information.
     */    
    public RequestorEventLogItem (String sessionId, String tgtId, 
        SessionState type, RequestorEvent requestorEvent, String userId, 
        String ipAddress, String requestor, IAuthority authority, 
        String message)
    {
        super(sessionId, tgtId, type, userId, ipAddress, requestor, authority, 
            message);
        _event = requestorEvent;      
    }
    
    /**
     * Create a new <code>RequestorEventLogItem</code>.    
     * @param oSession The session.    
     * @param ipAddress The client IP adres of the user.
     * @param requestorEvent The event to be logged.
     * @param authority The Authority the caller represents.
     * @param message Additional information.
     */
    public RequestorEventLogItem (ISession oSession, 
        String ipAddress, RequestorEvent requestorEvent, IAuthority authority, String message)
    {
        super(oSession, ipAddress, authority, message);       
        _event = requestorEvent;       
    }
    
    /**
     * Format this <code>UserEventLogItem</code> for logging.
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        StringBuffer sb = new StringBuffer(50);        
        sb.append(_eventType).append(SEPERATOR);
        sb.append(_sSessionId).append(SEPERATOR);
        sb.append(_sTgtId).append(SEPERATOR);
        sb.append(_sUserId).append(SEPERATOR);
        sb.append(_sOrganizationId).append(SEPERATOR);
        sb.append(_sIpAddress).append(SEPERATOR);
        sb.append(LOG_EVENT_TYPE).append(SEPERATOR);
        sb.append(_event).append(SEPERATOR);
        sb.append(_sRequestor).append(SEPERATOR);
        sb.append(_sAuthority).append(SEPERATOR);
        sb.append(_sMessage);
        return sb.toString();
    }

    /**
     * Retrieve the event.
     * @return The event.
     */
    public RequestorEvent getEvent()
    {
        return _event;
    }   
    
    /**
     * @see com.alfaariss.oa.util.logging.AbstractEventLogItem#getLogItemType()
     */
    public Integer getLogItemType()
    {
        return LOG_EVENT_TYPE;
    }
}