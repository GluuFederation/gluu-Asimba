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
package com.alfaariss.oa.profile.aselect;


/**
 * A-Select Exception.
 *
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class ASelectException extends Exception 
{
    private static final long serialVersionUID = -6701986668876011528L;

    /**
     * Creates the exception based on the error code.
     * @param sCode Error code
     */
    public ASelectException (String sCode)
    {
        super(sCode);
    }
    
    /**
     * Creates the exception based on the error code and throwable cause.
     * @param sCode Error code
     * @param tCause The throwable that caused the exception
     */
    public ASelectException (String sCode, Throwable tCause)
    {
        super(sCode, tCause);
    }

}
