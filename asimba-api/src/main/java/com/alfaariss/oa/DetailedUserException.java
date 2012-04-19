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

import java.util.List;
import java.util.Vector;

/**
 * Exception for User errors which result in showing the user interaction page.
 * @author MHO
 * @author Alfa & Ariss BV
 *
 */
public class DetailedUserException extends Exception
{
    /**
     * Name (details) for adding the details from this object as attribute to 
     * a JSP page.
     */
    public final static String DETAILS_NAME = "details";
    
    /** serialVersionUID */
    private static final long serialVersionUID = -5082073196214324350L;
    
    private List<Enum> _listDetails;    
    private UserEvent _event;   
    
    /**
     * Create a new <code>DetailedUserException</code>.
     * @param userEvent user event that occurred
     * @param details List with enumerated values.
     */
    public DetailedUserException(UserEvent userEvent, List<Enum> details)
    {
        _listDetails = details;
        _event = userEvent;
    }
    
    /**
     * Create a new <code>DetailedUserException</code> with one detail.
     * @param userEvent user event that occurred
     * @param detail enumerated value.
     */
    public DetailedUserException(UserEvent userEvent, Enum detail)
    {  
        _event = userEvent;
        _listDetails = new Vector<Enum>();
        _listDetails.add(detail);
    }
    
    /**
     * Returns the details.
     * @return The the details to be displayed to the user or null if not available.
     */
    public List<Enum> getDetails()
    {
        return _listDetails;
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
    
    /**
     * Returns the name of the first detail.
     * @return name of the first detail
     */
    public String getFirstDetail()
    {
        return _listDetails.get(0).name();
    }
}