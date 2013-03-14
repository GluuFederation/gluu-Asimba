/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authentication.remote.aselect.idp.storage;

import com.alfaariss.oa.engine.core.idp.storage.AbstractIDP;

/**
 * ASelect IDP object.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class ASelectIDP extends AbstractIDP
{
    private static final long serialVersionUID = -781337667870042826L;
    
    private String _sServerID;
    private boolean _bDoSigning;
    private String _sURL;
    private String _sCountry;
    private String _sLanguage;
    private boolean _bASynchronousLogout;
    private boolean _bSynchronousLogout;
    private int _iLevel;
    private boolean _bArpTargetEnabled;
    
    /**
     * Creates an ASelectOrganization object.
     * @param sOrganizationID The organization id.
     * @param sFriendlyname The organization friendlyname.
     * @param sServerID The organization server ID.
     * @param sURL The organization server URL.
     * @param iLevel The organization level.
     * @param bDoSigning TRUE if signing is enabled.
     * @param sCountry Optional Country parameter.
     * @param sLanguage Optional Language parameter.
     * @param bASynchronousLogout TRUE if asynchronous logout is supported.
     * @param bSynchronousLogout TRUE if synchronous logout is supported.
     * @param bArpTargetEnabled True if arp_target is enabled. 
     */
    public ASelectIDP(String sOrganizationID, String sFriendlyname, 
        String sServerID, String sURL, int iLevel, boolean bDoSigning, 
        String sCountry, String sLanguage, boolean bASynchronousLogout,
        boolean bSynchronousLogout, boolean bArpTargetEnabled)
    {
        super(sOrganizationID, sFriendlyname);
        _sServerID = sServerID;
        _sURL = sURL;
        _iLevel = iLevel;
        _bDoSigning = bDoSigning;
        _sCountry = sCountry;
        _sLanguage = sLanguage;
        _bASynchronousLogout = bASynchronousLogout;
        _bSynchronousLogout = bSynchronousLogout;
        _bArpTargetEnabled = bArpTargetEnabled;
    }
    /**
     * @return TRUE if requests must be signed.
     */
    public boolean doSigning()
    {
        return _bDoSigning;
    }
    /**
     * @return The remote server id.
     */
    public String getServerID()
    {
        return _sServerID;
    }

    /**
     * @return Returns the URL of the remote A-Select Server.
     */
    public String getURL()
    {
        return _sURL;
    }

    /**
     * @return The minimum authentication level.
     */
    public int getLevel()
    {
        return _iLevel;
    }

    /**
     * @return Country id
     */
    public String getCountry()
    {
        return _sCountry;
    }

    /**
     * @return Language id
     */
    public String getLanguage()
    {
        return _sLanguage;
    }
    
    /**
     * @return TRUE if asynchronous logout is supported by this organization.
     * @since 1.4
     */
    public boolean hasASynchronousLogout()
    {
        return _bASynchronousLogout;
    }
    
    /**
     * @return TRUE if synchronous logout is supported by this organization.
     * @since 1.4
     */
    public boolean hasSynchronousLogout()
    {
        return _bSynchronousLogout;
    }

    /**
     * Returns TRUE arp_target parameter is supported for the organization.
     * 
     * @return TRUE if arp_target parameter must be send.
     */
    public boolean isArpTargetEnabled()
    {
        return _bArpTargetEnabled;
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        StringBuffer sbInfo = new StringBuffer("A-Select Server (");
        sbInfo.append(_sServerID);
        sbInfo.append(") @ Organization: ");
        sbInfo.append(_sID);
        return sbInfo.toString();
    }
    
    /**
     * @see java.lang.Object#hashCode()
     * @since 1.4
     */
    public int hashCode()
    {
        StringBuffer sbThisUser = new StringBuffer();
        sbThisUser.append(_sServerID);
        sbThisUser.append("@");
        sbThisUser.append(_sID);
        
        return sbThisUser.toString().hashCode();
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
        if(!(other instanceof ASelectIDP))
            return false; 
        
        ASelectIDP otherOrganization = (ASelectIDP)other; 
        
        String sOtherOrganization = otherOrganization.getID();    
        if (sOtherOrganization == null)
        {
            if (this.getID() != null)
                return false;
        }
        else if (!sOtherOrganization.equals(this.getID()))
            return false;
        
        String sOtherServerID = otherOrganization.getServerID();
        if (sOtherServerID == null)
        {
            if (this.getServerID() != null)
                return false;
        }
        else if (!sOtherServerID.equals(this.getServerID()))
            return false;
        
        return true;
    } 
}
