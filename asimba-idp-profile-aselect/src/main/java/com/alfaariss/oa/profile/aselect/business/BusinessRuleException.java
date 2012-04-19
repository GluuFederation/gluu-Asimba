
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
import com.alfaariss.oa.profile.aselect.ASelectErrors;

/**
 * Exception for handling business rule validation errors.
 * 
 * The detail message should be {@link ASelectErrors} field.
 * 
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class BusinessRuleException extends Exception
{
    /** serialVersionUID */
    private static final long serialVersionUID = 8858861896922249912L;
    private RequestorEvent _event;

    /**
     * Constructor.
     * @param event The event.
     * @param detail The detail message.
     * @param cause The cause.
     * @see ASelectErrors
     */
    public BusinessRuleException (
        RequestorEvent event, String detail, Throwable cause)
    {        
        super(detail, cause);
        _event = event;
    }

    /**
     * Constructor.
     * @param event The event.
     * @param detail The detail message.
     * @see ASelectErrors
     */
    public BusinessRuleException (RequestorEvent event, String detail)
    {
        super(detail);
        _event = event;
    }
    
    /**
     * @return the _event
     */
    public RequestorEvent getEvent()
    {
        return _event;
    }
}