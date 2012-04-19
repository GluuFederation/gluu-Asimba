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
package com.alfaariss.oa.util.communication;

import com.alfaariss.oa.OAException;

/**
 * Communication exception.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class CommunicationException extends OAException
{
    /**
     * The serial version UID.
     */
    private static final long serialVersionUID = 4621414597523510841L;

    /**
     * Create a new <code>CommunicationException</code>.
     * @param iCode The error code.
     */
    public CommunicationException (int iCode)
    {
        super(iCode);
    }
    
    /**
     * Create a new <code>CommunicationException</code> with the given cause.
     * @param iCode The error code.
     * @param throwable The error cause.
     */
    public CommunicationException (int iCode, Throwable throwable)
    {
        super(iCode, throwable);
    }
}