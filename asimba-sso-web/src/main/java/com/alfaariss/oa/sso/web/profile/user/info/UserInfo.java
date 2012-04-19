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
package com.alfaariss.oa.sso.web.profile.user.info;

import java.util.Date;
import java.util.List;

import com.alfaariss.oa.api.authentication.IAuthenticationMethod;
import com.alfaariss.oa.api.authentication.IAuthenticationProfile;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.user.IUser;

/**
 * Contains all User information to be displayed.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class UserInfo
{
    /**
     * The name of the user info attribute
     */
    public final static String USER_INFO_NAME = "userInfo";
        
    private IUser _user;
    private List<IAuthenticationMethod> _listAuthNMethods;
    private List<IAuthenticationProfile> _listAuthNProfiles;
    private List<IRequestor> _listRequestors;
    private List<IAttribute> _listUserAttributes;
    private Date _dExpireTime;
    
    /**
     * Create new information for the given TGT.
     * @param tgt The TGT.
     * @param listAuthNProfiles Authentication Profile objects.
     * @param listRequestors Requestor objects.
     * @param userAttributes User attributes.
     */
    public UserInfo (ITGT tgt, List<IAuthenticationProfile> listAuthNProfiles, 
        List<IRequestor> listRequestors, List<IAttribute> userAttributes)
    {
        _user = tgt.getUser();
        _dExpireTime = tgt.getTgtExpTime();        
        _listAuthNMethods = tgt.getAuthenticationProfile().getAuthenticationMethods();
        _listAuthNProfiles = listAuthNProfiles;
        _listRequestors = listRequestors;
        _listUserAttributes = userAttributes;
    }

    /**
     * @return the user object
     */
    public IUser getUser()
    {
        return _user;
    }

    /**
     * @return the authnMethods
     */
    public List<IAuthenticationMethod> getAuthnMethods()
    {
        return _listAuthNMethods;
    }

    /**
     * @param authNProfiles the authNProfiles to set
     */
    public void setAuthnProfiles(List<IAuthenticationProfile> authNProfiles)
    {
        this._listAuthNProfiles = authNProfiles;
    }

    /**
     * @return the authNProfiles
     */
    public List<IAuthenticationProfile> getAuthnProfiles()
    {
        return _listAuthNProfiles;
    }
    
    /**
     * @param requestors the requestors to set
     */
    public void setRequestors(List<IRequestor> requestors)
    {
        this._listRequestors = requestors;
    }

    /**
     * @return the requestors
     */
    public List<IRequestor> getRequestors()
    {
        return _listRequestors;
    }

    /**
     * @return the expireTime
     */
    public Date getExpireTime()
    {
        return _dExpireTime;
    }
    
    /**
     * @return the user attributes
     */
    public List<IAttribute> getUserAttributes()
    {
        return _listUserAttributes;
    }
}
