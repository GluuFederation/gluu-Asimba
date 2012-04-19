
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
 * The response interface.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public interface IResponse
{

    /**
     * Set a parameter with the supplied name and value.
     * @param sName the name of the value
     * @param oValue the value of the parameter can be a String or Vector
     * @throws BindingException if the parameter can't be set
     */
    public void setParameter(String sName, Object oValue) throws BindingException;

    /**
     * Sends the response message.
     * @throws BindingException if sending fails 
     */
    public void send() throws BindingException;

}