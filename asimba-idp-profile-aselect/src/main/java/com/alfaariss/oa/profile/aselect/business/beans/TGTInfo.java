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
package com.alfaariss.oa.profile.aselect.business.beans;

import java.io.Serializable;
import java.util.Date;

import com.alfaariss.oa.profile.aselect.ASelectErrors;

/**
 * JavaBean containing all TGT/authentication properties.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class TGTInfo implements Serializable
{
    /** serialVersionUID */
    private static final long serialVersionUID = -4063751476195472452L;

    private String _oaID;    
    private String _organization;   
    private int _appLevel;   
    private int _authspLevel; 
    private String _authsp;   
    private String _uid;  
    private long _expiration;    
    private String _attributes;    
    private String _resultCode;

    /**
     * Default constructor.
     */
    public TGTInfo()
    {
        super();
        _resultCode = null;
        _oaID = null;
        _organization = null;
        _appLevel = -1;
        _authspLevel = -1;
        _authsp = null;
        _uid = null;
        _expiration = -1;
    }
    
    /**
     * Constructor.
     * @param resultCode The Authentication result should be 
     * {@link ASelectErrors} constant.
     */
    public TGTInfo (String resultCode)
    {
        super();
        _resultCode = resultCode;
        _oaID = null;
        _organization = null;
        _appLevel = -1;
        _authspLevel = -1;
        _authsp = null;
        _uid = null;
        _expiration = -1;
    }
    
    /**
     * Constructor with predefined properties.
     * The result is {@link ASelectErrors#ERROR_ASELECT_SUCCESS}. 
     * @param oaID The id of the OpenASelect Server
     * @param organization The organization the user belongs to
     * @param appLevel Required level for the authentication
     * @param authspLevel The numeric level of the authentication mechanism
     * @param authsp The ID of the authentication profile
     * @param uid The user ID
     * @param expiration The time when the TGT will expire

     */
    public TGTInfo (String oaID, String organization, int appLevel, 
        int authspLevel, String authsp, String uid, long expiration)
    {
        super();
        _resultCode = ASelectErrors.ERROR_ASELECT_SUCCESS;
        _oaID = oaID;
        _organization = organization;
        _appLevel = appLevel;
        _authspLevel = authspLevel;
        _authsp = authsp;
        _uid = uid;
        _expiration = expiration;
    }

    /**
     * Long representing UTC time in milliseconds since 1970.
     * @return the expiration
     */
    public long getExpiration()
    {
        return _expiration;
    }

    /**
     * Long representing UTC time in milliseconds since 1970.
     * @param expiration the expiration to set
     */
    public void setExpiration(long expiration)
    {
        this._expiration = expiration;
    }

    /**
     * The id of the OpenASelect Server
     * @return the oaID
     */  
    public String getOaID()
    {
        return _oaID;
    }

    /**
     * The id of the OpenASelect Server
     * @param oaID the oaID to set
     */
    public void setOaID(String oaID)
    {
        this._oaID = oaID;
    }

    /**
     * Specifies the organization that user belongs to.
     * @return the organization
     */   
    public String getOrganization()
    {
        return _organization;
    }

    /**
     * Specifies the organization that user belongs to.
     * @param organization the organization to set
     */
    public void setOrganization(String organization)
    {
        this._organization = organization;
    }

    /**
     * The user's id.
     * @return the uid
     */
    public String getUid()
    {
        return _uid;
    }

    /**
     * The user's id.
     * @param uid the uid to set
     */
    public void setUid(String uid)
    {
        this._uid = uid;
    }

    /**
     * Required level for the authentication
     * @return the appLevel
     */
    public int getAppLevel()
    {
        return _appLevel;
    }

    /**
     * Required level for the authentication
     * @param appLevel the appLevel to set
     */
    public void setAppLevel(int appLevel)
    {
        this._appLevel = appLevel;
    }

    /**
     * The ID of the authentication profile
     * @return the authentication profile id
     */
    public String getAuthsp()
    {
        return _authsp;
    }

    /**
     * The ID of the authentication profile
     * @param authsp the authsp (authentication profile id) to set
     */
    public void setAuthsp(String authsp)
    {
        this._authsp = authsp;
    }

    /**
     * The numeric level of the authentication mechanism
     * @return the authspLevel
     */
    public int getAuthspLevel()
    {
        return _authspLevel;
    }

    /**
     * The numeric level of the authentication mechanism
     * @param authSPLevel the authspLevel to set
     */
    public void setAuthspLevel(int authSPLevel)
    {
        this._authspLevel = authSPLevel;
    } 
    
    /**
     * The numeric level of the authentication mechanism.
     * 
     * Added for backwards compatibility with A-Select 1.4.
     * @return the authspLevel
     */
    public int getAspLevel()
    {
        return _authspLevel;
    }
    
    /**
     * The ID of the authentication profile.
     * 
     * Added for backwards compatibility with A-Select 1.4.
     * @return The asp (authentication profile id)
     */
    public String getAsp()
    {
        return _authsp;
    }
     
    /**
     * Gathered Attributes.
     * 
     * The attributes are encoded using base64 encoding. 
     * @return The attributes
     */
    public String getAttributes()
    {
        return _attributes;
    }

    /**
     * Gathered Attributes.
     * 
     * The attributes are encoded using base64 encoding. 
     * @param attributes the attributes to set
     */
    public void setAttributes(String attributes)
    {
        this._attributes = attributes;
    }

    /**
     * Authentication result, {@link ASelectErrors#ERROR_ASELECT_SUCCESS}(0000) 
     * for success.
     * @return The resultCode
     * @see ASelectErrors
     */
    public String getResultCode()
    {
        return _resultCode;
    }
    
    /**
     * Set the authentication result.
     * {@link ASelectErrors#ERROR_ASELECT_SUCCESS}(0000) for success.
     * @param resultCode The Authentication result should be 
     *  {@link ASelectErrors} constant.
     * @see ASelectErrors
     */
    public void setResultCode(String resultCode)
    {
        _resultCode = resultCode;
    }

    /**
     * A string representation of the TGT Info.
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        StringBuffer info = new StringBuffer("\n");
        info.append("----------------------------------------------------------------------------\nTGT info\n");
        info.append("----------------------------------------------------------------------------\n");
        if(_resultCode != null)
            info.append("result code: ").append(_resultCode).append("\n");
        if(_oaID != null)
            info.append("aselect-server: ").append(_oaID).append("\n");
        info.append("user: ");
        if(_uid != null)
            info.append(_uid);
        else
            info.append("[unknown]");
        if(_organization != null)
            info.append("@").append(_organization);
        info.append("\n");
        if(_oaID != null)
            info.append("app level: ").append(_appLevel).append("\n");
        if(_oaID != null)
            info.append("Authsp Level: ").append(_authspLevel).append("\n");
        if(_oaID != null)
            info.append("authsp: ").append(_oaID).append("\n");
        info.append("expiration: ").append(new Date(_expiration)).append("\n");
        info.append("----------------------------------------------------------------------------\n\n");
        return info.toString();
    }
}