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
package com.alfaariss.oa.engine.core.requestor;

import java.util.Collections;
import java.util.Map;
import java.util.Properties;

import com.alfaariss.oa.api.requestor.IRequestor;

/**
 * An IDP requestor.
 * @author MHO
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class Requestor implements IRequestor 
{
    private static final long serialVersionUID = -8539374895896063069L;
    private String _sID;
    private String _sFriendlyName;    
    private boolean _bEnabled;  
    private Properties _properties;

    /**
     * Create an empty  <code>Requestor</code>.
     */
    public Requestor ()
    {
        this._sID = null;
        this._sFriendlyName = null;
        this._bEnabled = false;
        _properties = new Properties();
    }       

    /**
     * Create a <code>Requestor</code>.
     * @param id The id.
     * @param friendlyName The friendly display name.
     * @param enabled Enabled.
     * @param properties The extended requestor properties.
     */
    public Requestor (String id, String friendlyName, 
        boolean enabled, Properties properties)
    {
        this._sID = id;
        this._sFriendlyName = friendlyName;
        this._bEnabled = enabled;
        _properties = properties;
    }
    
    /**
     * @see com.alfaariss.oa.api.IManagebleItem#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }
    
    /**
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }
    
    /**
     * @see com.alfaariss.oa.api.IManagebleItem#getID()
     */
    public String getID()
    {
        return _sID;
    }
    
    /**
     * Returns the unmodifiable properties Map.
     * @see IRequestor#getProperties()
     */
    public Map getProperties()
    {
        return Collections.unmodifiableMap(_properties);
    }

    /**
     * @see IRequestor#getProperty(java.lang.String)
     */
    public Object getProperty(String name)
    {
        return _properties.get(name);
    }

    /**
     * @see IRequestor#isProperty(java.lang.String)
     */
    public boolean isProperty(String name)
    {
        return _properties.containsKey(name);
    }
    
    /**
     * The {@link java.lang.Object#hashCode()} of the ID.
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        return _sID.hashCode();
    }
    
    /**
     * Returns <code>ID.equals(other.ID)</code>.
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object other)
    {
        if(!(other instanceof Requestor))
            return false;        
        return _sID.equals(((Requestor)other)._sID);
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        StringBuffer sbInfo = new StringBuffer(_sFriendlyName);
        sbInfo.append(" (").append(_sID).append(")");             
        return sbInfo.toString();
    }
}