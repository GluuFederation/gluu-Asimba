
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
package com.alfaariss.oa.profile.aselect.binding;

/**
 * The request interface.
 *
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface IRequest
{
    /**
     * Retrieve a parameter value with the specified name.
     * @param sName the parameter name
     * @return Object the parameter value
     * @throws BindingException if retrieval fails
     */
    public Object getParameter(String sName) throws BindingException;
    
    /**
     * The URL to which the request is sent.
     * @return The URL as a <code>String</code>.
     */
    public String getRequestedURL();

}