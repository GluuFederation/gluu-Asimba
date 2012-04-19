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
package com.alfaariss.oa;

import com.alfaariss.oa.UserEvent;

/**
 * User exception.
 * @author MHO
 * @author Alfa & Ariss BV
 *
 */
public class UserException extends Exception
{
    /**
     * Name (userEvent) for adding the user event from this object as attribute 
     * to a JSP page.
     */
    public final static String USEREVENT_NAME = "userEvent";
    
    /** serialVersionUID */
    private static final long serialVersionUID = -86320306110296792L;
    private UserEvent _event;   
        
    /**
     * Create a new <code>UserException</code>.
     * @param userEvent The occurred user event.
     */
    public UserException(UserEvent userEvent)
    {
        _event = userEvent;
    }

    /**
     * Returns the UserEvent.
     * @return The occurred user event.
     */
    public UserEvent getEvent()
    {
        return _event;
    }
    
    /**
     * @see java.lang.Throwable#getMessage()
     */
    public String getMessage()
    {
        return _event.name();
    }
}