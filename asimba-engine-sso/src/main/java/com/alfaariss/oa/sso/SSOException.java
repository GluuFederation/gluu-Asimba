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
package com.alfaariss.oa.sso;

import com.alfaariss.oa.OAException;

/**
 * Exception for SSO related internal errors.
 * @author JVG
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class SSOException extends OAException
{
    /** serialVersionUID */
    private static final long serialVersionUID = -6037183727649480933L;

    /**
     * Create exception.
     * @param code The error code.
     */
    public SSOException (int code)
    {
        super(code);
    }

    /**
     * Create exception with cause.
     * @param code The error code.
     * @param cause the cause
     */
    public SSOException (int code, Throwable cause)
    {
        super(code, cause);
    }
}
