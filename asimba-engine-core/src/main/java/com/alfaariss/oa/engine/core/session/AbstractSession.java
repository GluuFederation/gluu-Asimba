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
package com.alfaariss.oa.engine.core.session;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Vector;

import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.authentication.IAuthenticationProfile;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.attribute.SessionAttributes;


/**
 * A simple session implementation which can be stored in memory.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public abstract class AbstractSession implements ISession, Serializable
{   
    /**
	 * 
	 */
	private static final long serialVersionUID = 2035158024380320256L;
	/** session id */
    protected String _id;
    /** expire time */
    protected long _lExpireTime;
    /** session attributes */
    protected ISessionAttributes _attributes;
    private String _requestorId;
    private List<IAuthenticationProfile> _listAuthNProfiles;
    private int _iSelectedAuthNProfile;
    private IUser _uOwner;
    private String _tgtId;
    private SessionState _state;
    private String _sProfileURL;
    private boolean _forcedAuthentication;
    private String _sForcedUserID;
    private Locale _locale;
    private boolean _isPassive;
    
    /**
     * Create a new <code>AbstractSession</code>.
     * @param requestorId The id of the requestor for which this authentication
     *  session is created. 
     */
    public AbstractSession(String requestorId)
    { 
        _requestorId = requestorId;
        _attributes = new SessionAttributes();
        _state = SessionState.SESSION_CREATED;
        _forcedAuthentication = false;
        _iSelectedAuthNProfile = -1;
        _listAuthNProfiles = new Vector<IAuthenticationProfile>();
        _isPassive = false;
    } 
   
    /**
     * @see com.alfaariss.oa.api.session.ISession#getId()
     */
    public String getId()
    {
        assert _id != null : "Session id not set";
        return _id;
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#getRequestorId()
     */
    public String getRequestorId()
    {
        return _requestorId;
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#getUser()
     */
    public IUser getUser()
    {
        return _uOwner;
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#setUser(com.alfaariss.oa.api.user.IUser)
     */
    public void setUser(IUser user)
    {
        _uOwner = user;
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#getState()
     */
    public SessionState getState()
    {
        return _state;
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#setState(
     *  com.alfaariss.oa.api.session.SessionState)
     */
    public void setState(SessionState state)
    {
        if (state == null)
            throw new IllegalArgumentException("Supplied session state is null");
        _state = state;        
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#expire()
     */
    public void expire()
    {
        _lExpireTime = 0;
        
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#isExpired()
     */
    public boolean isExpired()
    {
        return _lExpireTime <= System.currentTimeMillis();
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#getExpTime()
     */
    public long getExpTime()
    {
        return _lExpireTime;
    }
    
    /**
     * @see com.alfaariss.oa.api.session.ISession#setExpTime(long)
     */
    public void setExpTime(long expirationTime)
    {
        _lExpireTime = expirationTime;        
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#getTGTId()
     */
    public String getTGTId()
    {
        return _tgtId;
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#setTGTId(String)
     */
    public void setTGTId(String id)
    {
        _tgtId = id;        
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#getAttributes()
     */
    public ISessionAttributes getAttributes()
    {
        return _attributes;
    }
    
    /**
     * @see com.alfaariss.oa.api.session.ISession#getProfileURL()
     */
    public String getProfileURL()
    {
        return _sProfileURL;
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#setProfileURL(
     *  java.lang.String)
     */
    public void setProfileURL(String url)
    {
        if (url == null)
            throw new IllegalArgumentException("Supplied URL is null");
        _sProfileURL = url;        
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#isForcedAuthentication()
     */
    public boolean isForcedAuthentication()
    {
        return _forcedAuthentication;
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#setForcedAuthentication(
     *  boolean)
     */
    public void setForcedAuthentication(boolean enabled)
    {
        _forcedAuthentication = enabled;        
    }
    
    /**
     * Return the hashcode from the id.
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        return _id.hashCode();
    }

    /**
     * Compare ID.
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object other)
    {
        if(!(other instanceof AbstractSession))
            return false;        
        return _id.equals(((AbstractSession)other)._id);
    }
    
    /**
     * @see com.alfaariss.oa.api.session.ISession#getForcedUserID()
     */
    public String getForcedUserID()
    {
        return _sForcedUserID;
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#getLocale()
     */
    public Locale getLocale()
    {
        return _locale;
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#setForcedUserID(java.lang.String)
     */
    public void setForcedUserID(String id)
    {
        _sForcedUserID = id;
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#setLocale(java.util.Locale)
     */
    public void setLocale(Locale locale)
    {
        _locale = locale;
    }

    /**
     * @see com.alfaariss.oa.api.session.ISession#getAuthNProfiles()
     */
    public List<IAuthenticationProfile> getAuthNProfiles()
    {
        List<IAuthenticationProfile> listReturn = new Vector<IAuthenticationProfile>();
        listReturn.addAll(_listAuthNProfiles);
        return listReturn;
    }

    
    /**
     * @see com.alfaariss.oa.api.session.ISession#getSelectedAuthNProfile()
     */
    public IAuthenticationProfile getSelectedAuthNProfile()
    {
        if (_iSelectedAuthNProfile < 0 || _iSelectedAuthNProfile > _listAuthNProfiles.size())
            return null;
        
        return _listAuthNProfiles.get(_iSelectedAuthNProfile);
    }

    /**
     * @see ISession#setAuthNProfiles(java.util.List)
     */
    public void setAuthNProfiles(List<IAuthenticationProfile> profiles)
    {
        _iSelectedAuthNProfile = -1;
        _listAuthNProfiles = profiles;
    }

    /**
     * @see ISession#setSelectedAuthNProfile(
     *  IAuthenticationProfile)
     */
    public void setSelectedAuthNProfile(IAuthenticationProfile profile)
    {
        int iIndex = _listAuthNProfiles.indexOf(profile);
        if (iIndex < 0)
            throw new IllegalArgumentException("Invalid authN profile supplied: " 
                + profile.getID());
        
        _iSelectedAuthNProfile = iIndex;
    }
    
    /**
     * @see com.alfaariss.oa.api.session.ISession#isPassive()
     */
    public boolean isPassive()
    {
        return _isPassive;
    }
    
    /**
     * @see com.alfaariss.oa.api.session.ISession#setPassive(boolean)
     */
    public void setPassive(boolean passive)
    {
        _isPassive = passive;
    }
    
    /**
     * @see com.alfaariss.oa.api.tgt.ISession#getSessionExpTime()
     */
    public Date getSessionExpTime()
    {
		return new Date(_lExpireTime);
	}

}
