/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authentication.remote.saml2.beans;

import java.util.List;
import java.util.Vector;

import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.user.AbstractUser;

/**
 * SAML User object.
 * 
 * @author MHO
 * @author jre
 * @since 1.0
 */
public class SAMLRemoteUser extends AbstractUser
{
    private static final long serialVersionUID = -760508002735952152L;
    private String _sMethodID;
    private String _sFormat;
    private List<String> _vSessionIndexes;
    private String _sNameQualifier;
    private String _sSPNameQualifier;
    private String _sIDP;

    /**
     * Constructor.
     * 
     * @param sOrganization Organization ID, in the SAML case the NameQualifier of the NameID.
     * @param sUserId The UID, in the SAML case the NameID.
     * @param sMethodID The authentication method.
     * @param sFormat The ID format, in the SAML case the Format of the NameID.
     * @param sNameQualifier User namequalifier
     * @param sSPNameQualifier User SP namequalifier
     * @param sIDP The ID of the IdP known by this OAS, where the user was authenticated by. (can be a proxy)
     */
    public SAMLRemoteUser(String sOrganization, String sUserId, 
        String sMethodID, String sFormat, String sNameQualifier, 
        String sSPNameQualifier, String sIDP)
    {
        super(sOrganization, sUserId, true);
        _sMethodID = sMethodID;
        _sFormat = sFormat;
        _vSessionIndexes = new Vector<String>();
        _sNameQualifier = sNameQualifier;
        _sSPNameQualifier = sSPNameQualifier;
        _sIDP = sIDP;
    }  

    /**
     * Returns the organization where the user was authenticated.
     * <br>
     * This organization is directly known as IdP at this OAS.
     * @return The remote organization where the user was authenticated at.
     */
    public String getIDP()
    {
        return _sIDP;
    }
    
    /**
     * Creates the user object.
     *
     * @param sOrganization the user organization
     * @param sUserId The unique remote user ID.
     * @param sMethodID Method id
     */
    public SAMLRemoteUser(String sOrganization, String sUserId, String sMethodID)
    {
        super(sOrganization, sUserId, true);
        _sMethodID = sMethodID;
    }
    
    /**
     * Returns <code>method != null && method equals this.method</code>.
     * @see IUser#isAuthenticationRegistered(java.lang.String)
     */
    public boolean isAuthenticationRegistered(String method)
    {
        return (method != null && method.equals(_sMethodID));
    }
    
    /**
     * The format of the NameID, e.g. "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".
     *
     * @return The format.
     */
    public String getFormat()
    {
        return _sFormat;
    }
    
    /**
     * Adds an SessionIndex. 
     * @param SessionIndex The SessionIndex to be added.
     */
    public void addSessionIndex(String SessionIndex)
    {
        _vSessionIndexes.add(SessionIndex);
    }
    
    /**
     * Returns the SessionIndex. 
     * @return SessionIndex
     */
    public List<String> getSessionIndexes()
    {
        return _vSessionIndexes;
    }
    
    /**
     * Returns the NameQualifier if available.
     *  
     * @return NameQualifier
     * @since 1.1
     */
    public String getNameQualifier()
    {
        return _sNameQualifier;
    }
    
    /**
     * Returns the SPNameQualifier if available.
     *  
     * @return SPNameQualifier
     * @since 1.1
     */
    public String getSPNameQualifier()
    {
        return _sSPNameQualifier;
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.user.AbstractUser#equals(java.lang.Object)
     */
    public boolean equals(Object other)
    {
        if(!(other instanceof IUser))
            return false;
        
        IUser otherUser = (IUser)other;
        String otherID = otherUser.getID();
        String otherOrg = otherUser.getOrganization();

        if (otherID == null)
        {
            if (getID() != null) return false;
        }
        else
        {
            if (!otherID.equalsIgnoreCase(getID())) return false;
        }
        
        if (otherOrg == null)
        {
            if (getOrganization() != null) return false;
        }
        else
        {
            if (!otherOrg.equals(getOrganization())) return false;
        }
        
        return true;                
    }
}
