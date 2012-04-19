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

import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.api.user.IUser;

/**
 * An OA base log item for logging event messages.
 * @author MHO
 * @author EVB
 * @author JRE
 * @author Alfa & Ariss
 *
 */
public abstract class AbstractEventLogItem
{
    /** The separator which can be used to separate the log message items */
    protected static final String SEPERATOR = ", ";
    
    /** Session id */
    protected String _sSessionId = null;
    /** TGT id */
    protected String _sTgtId = null;
    /** event type (session state) */
    protected SessionState _eventType = null;
    /** User id */
    protected String _sUserId = null;
    /** User organization id */
    protected String _sOrganizationId = null;
    /** IP Address */
    protected String _sIpAddress = null;
    /** Requestor */
    protected String _sRequestor = null;
    /** additional message */
    protected String _sMessage = null;
    /** Authority */
    protected String _sAuthority = null;

    /**
     * Create a new <code>AuditLogItem</code>.    
     * @param sessionId The session ID.
     * @param tgtId The TGT id.
     * @param type The identifier of the phase in the authentication process.
     * @param userId The user id.
     * @param organizationId The user organization id.
     * @param ipAddress The client IP address of the user.
     * @param requestor The requestor of the authentication session.
     * @param authority The Authority the caller represents.
     * @param message Additional information.
     * @since 1.2
     */
    public AbstractEventLogItem (String sessionId, String tgtId, 
        SessionState type, String userId, String organizationId, 
        String ipAddress, String requestor, IAuthority authority, 
        String message)
    {
        _sSessionId = sessionId;
        _sTgtId = tgtId;
        _eventType = type;
        _sUserId = userId;
        _sOrganizationId = organizationId;
        _sIpAddress = ipAddress;
        _sRequestor = requestor;
        _sAuthority = authority.getAuthority();
        _sMessage = message;
    }
    
    /**
     * Create a new <code>AuditLogItem</code>.    
     * @param sessionId The session ID.
     * @param tgtId The TGT id.
     * @param type The identifier of the phase in the authentication process.
     * @param userId The user id.
     * @param ipAddress The client IP address of the user.
     * @param requestor The requestor of the authentication session.
     * @param authority The Authority the caller represents.
     * @param message Additional information.
     */
    public AbstractEventLogItem (String sessionId, String tgtId, 
        SessionState type, String userId, String ipAddress, String requestor, 
        IAuthority authority, String message)
    {
        _sSessionId = sessionId;
        _sTgtId = tgtId;
        _eventType = type;
        _sUserId = userId;
        _sOrganizationId = null;
        _sIpAddress = ipAddress;
        _sRequestor = requestor;
        _sAuthority = authority.getAuthority();
        _sMessage = message;
    }    
    
    /**
     * Create a new <code>AuditLogItem</code>.    
     * @param oSession The session.    
     * @param ipAddress The client IP address of the user.
     * @param authority The Authority the caller represents.
     * @param message Additional information.
     */
    public AbstractEventLogItem (ISession oSession, 
        String ipAddress, IAuthority authority, String message)
    {
        if(oSession == null)
            throw new  IllegalArgumentException("Supplied session is empty");
        _sSessionId = oSession.getId();
        _sTgtId = oSession.getTGTId();
        _eventType = oSession.getState();
        IUser user =  oSession.getUser();
        _sUserId =  (user == null) ? null : user.getID();
        _sOrganizationId = (user == null) ? null : user.getOrganization();
        _sIpAddress = ipAddress;
        _sRequestor = oSession.getRequestorId();
        _sAuthority = authority.getAuthority();
        _sMessage = message;
    }
    
    /**
     * Format this <code>AuditLogItem</code> for logging.
     * @see java.lang.Object#toString()
     */
    public abstract String toString();

    /**
     * Retrieve the event type/state.
     * @return The event type.
     */
    public SessionState getEventType()
    {
        return _eventType;
    }

    /**
     * Retrieve the authority.
     * @return The authority.
     */
    public String getAuthority()
    {
        return _sAuthority;
    }

    /**
     * Retrieve the ip address.
     * @return The ip address.
     */
    public String getIpAddress()
    {
        return _sIpAddress;
    }

    /**
     *  Retrieve the message.
     * @return The additional message
     */
    public String getMessage()
    {
        return _sMessage;
    }

    /**
     * Retrieve the requestor of the authentication.
     * @return The requestor.
     */
    public String getRequestor()
    {
        return _sRequestor;
    }

    /**
     * Retrieve the session id.
     * @return The session ID.
     */
    public String getSessionId()
    {
        return _sSessionId;
    }

    /**
     * Retrieve the TGT ID.
     * @return The TGT ID.
     */
    public String getTgtId()
    {
        return _sTgtId;
    }

    /**
     * Retrieve user ID.
     * @return the user ID.
     */
    public String getUserId()
    {
        return _sUserId;
    }

    /**
     * Retrieve user organization ID.
     * @return the user organization ID.
     */
    public String getOrganizationId()
    {
        return _sOrganizationId;
    }
    
    /**
     * Retrieve the type of the log item.
     * 
     * @return Type of the log item or NULL when not available.
     * @since 1.5
     */
    public Integer getLogItemType()
    {
        return null;
    }
}