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
package com.alfaariss.oa.util.saml2.proxy;

import java.io.Serializable;

/**
 * IDPEntry object for storing the IDPEntry information as a session attribute.
 * @author MHO
 * @author Alfa & Ariss
 */
public class SAML2IDPEntry implements Serializable
{
    private static final long serialVersionUID = 1941735023412475301L;
    
    private String _sProviderID;
    private String _sName;
    private String _sLoc;
    
    /**
     * Default Constructor.
     */
    public SAML2IDPEntry ()
    {
        _sProviderID = null;
        _sName = null;
        _sLoc = null;
    }
    
    /**
     * Constructor.
     * 
     * @param sProviderID The required provider id.
     * @param sName The optional name (or NULL).
     * @param sLoc The optional loc (or NULL).
     */
    public SAML2IDPEntry (String sProviderID, String sName, String sLoc)
    {
        _sProviderID = sProviderID;
        _sName = sName;
        _sLoc = sLoc;
    }

    /**
     * Returns the ProviderID value. 
     * @return String with the ProviderID.
     */
    public String getProviderID()
    {
        return _sProviderID;
    }
    
    /**
     * Returns the Name value.
     * @return String with the Name value or <code>NULL</code> if not available.
     */
    public String getName()
    {
        return _sName;
    }
    
    /**
     * Returns the Loc value.
     * @return String with the Loc value or <code>NULL</code> if not available.
     */
    public String getLoc()
    {
        return _sLoc;
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        return _sProviderID;
    }
}
