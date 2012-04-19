
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
package com.alfaariss.oa.profile.aselect.business;

import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.profile.aselect.ASelectErrors;

/**
 * Exception for handling authentication errors.
 * 
 * This exception is used in case the {@link SessionState} has one of the 
 * following values:
 * 
 * <ul>
 *  <li>USER_CANCELLED</li>
 *  <li>AUTHN_FAILED</li>
 *  <li>PRE_AUTHZ_FAILED</li>
 *  <li>AUTHN_SELECTION_FAILED</li>
 *  <li>USER_BLOCKED</li>
 *  <li>USER_UNKNOWN</li>
 * </ul>
 * 
 * The detail message should be {@link ASelectErrors} field.
 * 
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class AuthNException extends Exception
{
    /** serialVersionUID */
    private static final long serialVersionUID = 6716947992637029578L;

    /**
     * Constructor.
     * @param detail The detail message.
     * @see ASelectErrors
     */
    public AuthNException (String detail)
    {
        super(detail);
    }
    
    /**
     * @return the _event
     */
    public RequestorEvent getEvent()
    {
        //DD Although authentication has failed, the token dereference succeeded
        return RequestorEvent.TOKEN_DEREFERENCE_SUCCESSFUL;
    }
}