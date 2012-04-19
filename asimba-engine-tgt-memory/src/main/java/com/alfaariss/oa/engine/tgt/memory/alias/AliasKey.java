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
package com.alfaariss.oa.engine.tgt.memory.alias;

/**
 * Alias Key object.
 * 
 * Used to index Aliases.
 * 
 * @author MHO
 * @author Alfa & Ariss
 */
public class AliasKey
{   
    private String _sRequestorID;
    private String _sSecKey;
    
    /**
     * Constructor.
     * @param sRequestorID The requestor ID on which this alias applies.
     * @param sSecKey The secundary key.
     */
    public AliasKey(String sRequestorID, String sSecKey)
    {
        _sRequestorID = sRequestorID;
        _sSecKey = sSecKey;
    }

    /**
     * Returns the requestor ID.
     * 
     * @return The requestor ID.
     */
    public String getRequestorID()
    {
        return _sRequestorID;
    }


    /**
     * Returns the secundary key.
     * 
     * @return The secundary key.
     */
    public String getSecKey()
    {
        return _sSecKey;
    }
    
    /**
     * Return the hashcode.
     * 
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        StringBuffer sb = new StringBuffer(_sRequestorID);
        sb.append(_sSecKey);
        return sb.toString().hashCode();
    }
    
    /**
     * Compare.
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object other)
    {
        if(!(other instanceof AliasKey))
            return false;
        
        AliasKey otherAliasKey = (AliasKey)other;
        
        if (_sRequestorID.equals(otherAliasKey.getRequestorID())
            && _sSecKey.equals(otherAliasKey.getSecKey()))
            return true;
        
        return false;
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        StringBuffer sbInfo = new StringBuffer("Requestor '");
        sbInfo.append(_sRequestorID);
        sbInfo.append("' - Secundary key '");
        sbInfo.append(_sSecKey);
        sbInfo.append("'");
        return sbInfo.toString();
    }
}
