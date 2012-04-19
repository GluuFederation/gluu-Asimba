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
package com.alfaariss.oa.util.logging;


/**
 * An OA logitem for elaborated logging system messages.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class SystemLogItem 
{    
    private String _sSessionId;
    private int _iCode;
    private String _sMessage;

    /**
     * Create a new <code>SystemLogItem</code>.    
     * @param sSessionId The session ID.
     * @param iCode The error code.
     * @param sMessage Additional information.
     */
    public SystemLogItem (String sSessionId, int iCode, String sMessage)
    {
        _sSessionId = sSessionId;     
        _iCode = iCode;
        _sMessage = sMessage;
    }    
        
    /**
     * Format this <code>AuditLogItem</code> for logging.
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        StringBuffer sb = new StringBuffer(50);        
        sb.append(_sMessage);
        sb.append(" code=(").append(_iCode).append("),");
        sb.append(" session=(").append(_sSessionId).append(")");      
        return sb.toString();
    }

}