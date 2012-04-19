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
package com.alfaariss.oa.api.tgt;

import java.io.Serializable;

import com.alfaariss.oa.UserEvent;

/**
 * Error object for processing TGT Events.
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class TGTEventError implements Serializable
{
    /** serialVersionUID */
    private static final long serialVersionUID = -331283011732000112L;
    
    private UserEvent _eventCode;
    private String _sDetail;
    
    /**
     * Constructor.
     * @param code The error code.
     */
    public TGTEventError(UserEvent code)
    {
        _eventCode = code;
    }
    
    /**
     * Constructor.
     * @param code The error code.
     * @param detail The detail.
     */
    public TGTEventError(UserEvent code, String detail)
    {
        _eventCode = code;
        _sDetail = detail;
    }
    
    /**
     * Returns the error code as enumeration.
     * @return The error code.
     */
    public UserEvent getCode()
    {
        return _eventCode;
    }
    
    /**
     * Returns more details.
     * @return A detailed message
     */
    public String getDetail()
    {
        return _sDetail;
    }
}
