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
package com.alfaariss.oa.engine.core.idp.storage;

import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.api.requestor.IRequestor;

/**
 * Abstract IDP implementation.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
abstract public class AbstractIDP implements IIDP
{
    /** System logger */
    protected static Log _logger;
    /** ID of the IDP */
    protected String _sID;
    /** Friendly name of the IDP */
    protected String _sFriendlyName;
    
    /** last modified date of of the IDP; or null if unknown */
    protected Date _dLastModified;
    
    /**
     * Constructor. 
     */
    public AbstractIDP()
    {
        _logger = LogFactory.getLog(this.getClass());
    }
    
    /**
     * Constructor. 
     * @param id The IDP ID.
     * @param friendlyname The IDP friendly name. 
     */
    public AbstractIDP(String id, String friendlyname, Date dLastModified)
    {
        _logger = LogFactory.getLog(this.getClass());
        _sID = id;
        _sFriendlyName = friendlyname;
        _dLastModified = dLastModified;
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDP#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDP#getID()
     */
    public String getID()
    {
        return _sID;
    }

    /**
     * @see IModifyable#getLastModified() 
     */
    public Date getLastModified() {
    	return _dLastModified;
    }

    /**
     * @see IModifyable#setLastModified()
     * @param dLastModified
     */
    public void setLastModified(Date dLastModified) {
    	_dLastModified = dLastModified;
    }

    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        StringBuffer sbInfo = new StringBuffer("IDP '");
        sbInfo.append(_sID);
        sbInfo.append("' (");
        sbInfo.append(_sFriendlyName);
        sbInfo.append(")");
        return sbInfo.toString();
    }
    
    /**
     * @see java.lang.Object#hashCode()
     * @since 1.4
     */
    public int hashCode()
    {
        return _sID.hashCode();
    }
    
    /**
     * Returns TRUE if server ID and organization ID of both organizations are 
     * equally.
     * <br>
     * Both ID's are compared case sensitive.
     * @see java.lang.Object#equals(java.lang.Object)
     * @since 1.4
     */
    public boolean equals(Object other)
    {
        if(!(other instanceof IIDP))
            return false; 
        
        IIDP otherIDP = (IIDP)other; 
        
        String sOtherIDP = otherIDP.getID();    
        if (sOtherIDP == null)
        {
            if (this.getID() != null)
                return false;
        }
        else if (!sOtherIDP.equals(this.getID()))
            return false;
        
        return true;
    }  
}
