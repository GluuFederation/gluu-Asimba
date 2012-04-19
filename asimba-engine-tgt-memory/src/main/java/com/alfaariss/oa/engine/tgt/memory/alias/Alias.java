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
 * Implementation of the IAlias interface.
 *
 * This class is created as an object for storing the alias information.
 * 
 * An alias is unique per tgt id and requestor, so more aliasses of the same 
 * type can be available for one tgt.
 * 
 * @author MHO
 * @author Alfa & Ariss
 */
public class Alias
{   
    private String _sRequestorID;
    private String _sTGTID;
    private String _sAlias;
    
    /**
     * Constructor.
     * 
     * @param sTGTID The TGT ID on which this alias applies.
     * @param sRequestorID The requestor ID on which this alias applies.
     * @param sAlias The alias value.
     */
    public Alias(String sTGTID, String sRequestorID, String sAlias)
    {
        _sTGTID = sTGTID;
        _sRequestorID = sRequestorID;
        _sAlias = sAlias;
    }

    /**
     * Returns the TGT ID on which the alias applies.
     * 
     * @return The TGT ID.
     */
    public String getTGTID()
    {
        return _sTGTID;
    }

    /**
     * Returns the requestor ID on which the alias applies.
     * 
     * @return The requestor ID.
     */
    public String getRequestorID()
    {
        return _sRequestorID;
    }
    
    /**
     * Returns the alias value.
     * 
     * @return The alias.
     */
    public String getAlias()
    {
        return _sAlias;
    }
    
    /**
     * Return the hashcode.
     * 
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        StringBuffer sb = new StringBuffer(_sTGTID);
        sb.append(_sRequestorID);
        sb.append(_sAlias);
        return sb.toString().hashCode();
    }
    
    /**
     * Compare.
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object other)
    {
        if (other == null)
            return false;
        
        if(!(other instanceof Alias))
            return false;
        
        Alias otherAlias = (Alias)other;
        
        if (_sTGTID.equals(otherAlias.getTGTID())
            && _sRequestorID.equals(otherAlias.getRequestorID())
            && _sAlias.equals(otherAlias.getAlias()))
            return true;
        
        return false;
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        StringBuffer sbInfo = new StringBuffer("Alias '");
        sbInfo.append(_sAlias);
        sbInfo.append("' for Requestor '");
        sbInfo.append(_sRequestorID);
        sbInfo.append("' and TGT: ");
        sbInfo.append(_sTGTID);
        return sbInfo.toString();
    }
}
