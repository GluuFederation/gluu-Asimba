/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2010 Alfa & Ariss B.V.
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
package com.alfaariss.oa.profile.aselect.logout;

import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.user.IUser;

/**
 * A-Select logout target.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class LogoutTarget
{
    private IRequestor _requestor;
    private String _sTarget;
    private String _sTGTID;
    private String _sUserID;
    private String _sUserOrganization;
    
    /**
     * Constructor.
     * @param requestor The requestor
     * @param targetURL The target URL
     * @param tgt The TGT
     */
    public LogoutTarget(IRequestor requestor, String targetURL, ITGT tgt)
    {
        _sTarget = targetURL;
        _requestor = requestor;
        _sTGTID = tgt.getId();
        
        IUser user = tgt.getUser();
        _sUserID = user.getID();
        _sUserOrganization = user.getOrganization();
    }
    
    /**
     * Returns the target URL. 
     * @return The target URL as String.
     */
    public String getTargetURL()
    {
        return _sTarget;
    }
    
    /**
     * Returns the requestor. 
     * @return The requestor.
     */
    public IRequestor getRequestor()
    {
        return _requestor;
    }
    
    /**
     * Returns the TGT ID. 
     * @return The ID of the TGT.
     */
    public String getTGTID()
    {
        return _sTGTID;
    }
    
    /**
     * Returns the User ID. 
     * @return The User ID.
     */
    public String getUserID()
    {
        return _sUserID;
    }
    
    /**
     * Returns the organization ID.
     * @return The user organization ID.
     */
    public String getUserOrganization()
    {
        return _sUserOrganization;
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        return _sTarget;
    }
}
