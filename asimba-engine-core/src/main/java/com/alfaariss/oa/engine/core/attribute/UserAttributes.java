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
package com.alfaariss.oa.engine.core.attribute;

import java.util.Enumeration;
import java.util.Hashtable;

import com.alfaariss.oa.api.attribute.IAttributes;

/**
 * The OA Attributes object.
 *
 * @author MHO
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class UserAttributes implements IAttributes 
{
    /** serialVersionUID */
    private static final long serialVersionUID = 3322934500217377616L;
    private final Hashtable<String, Object> _htAttributes;
    private final Hashtable<String, String> _htAttributeFormats;

    /**
     * Create new empty attributes.
     */
    public UserAttributes()
    {
        _htAttributes = new Hashtable<String, Object>();
        _htAttributeFormats = new Hashtable<String,String>();
    }

	/**
     * Returns the attribute with the supplied name.
	 * @see com.alfaariss.oa.api.attribute.IAttributes#get(java.lang.String)
	 */
    @Override
	public Object get(String sName)
    {
        return _htAttributes.get(sName);
    }

    /**
     * Returns all attribute names as an <code>Enumeration</code>.
     * @see com.alfaariss.oa.api.attribute.IAttributes#getNames()
     */
    @Override
	public Enumeration<?> getNames()
    {
        return _htAttributes.keys();
    }

    /**
     * Removes the attribute with the supplied name.
     * @see com.alfaariss.oa.api.attribute.IAttributes#remove(java.lang.String)
    */
    @Override
	public void remove(String sName)
    {
	    _htAttributes.remove(sName);
	    _htAttributeFormats.remove(sName);
	}

    /**
     * Checks if the attribute with the supplied name exists.
     * @see com.alfaariss.oa.api.attribute.IAttributes#contains(java.lang.String)
     */
    @Override
    public boolean contains(String sName)
    {
        return _htAttributes.containsKey(sName);
    }

    /**
     * Stores or overwrites the supplied attribute.
     * @see com.alfaariss.oa.api.attribute.IAttributes#put(java.lang.String, java.lang.Object)
     */
    @Override
    public void put(String sName, Object oValue)
    {
        _htAttributes.put(sName, oValue);
    }
    
    /**
     * Return the hash code of the attributes.
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        return _htAttributes.hashCode();
    }
    
    /**
     * Compare with another object.
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(Object other)
    {
        if(!(other instanceof UserAttributes))
            return false;
        return _htAttributes.equals(other);
    }   
    
    /**
     * Return all attributes in a <code>String</code>.
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString()
    { 
        return _htAttributes.toString();
    }

    /**
     * @see com.alfaariss.oa.api.attribute.IAttributes#size()
     */
    @Override
    public int size()
    {
        return _htAttributes.size();
    }

    /**
     * @see com.alfaariss.oa.api.attribute.IAttributes#getFormat(java.lang.String)
     */
    @Override
    public String getFormat(String name)
    {
        return _htAttributeFormats.get(name);
    }

    /**
     * @see com.alfaariss.oa.api.attribute.IAttributes#put(java.lang.String, java.lang.String, java.lang.Object)
     */
    @Override
    public void put(String name, String format, Object value)
    {
        _htAttributes.put(name, value);
        if (format != null)
            _htAttributeFormats.put(name,format);
        else
            _htAttributeFormats.remove(name);
    }

    /**
     * @see com.alfaariss.oa.api.attribute.IAttributes#removeFormat(java.lang.String)
     */
    @Override
    public void removeFormat(String name)
    {
        _htAttributeFormats.remove(name);
    }

    /**
     * @see com.alfaariss.oa.api.attribute.IAttributes#setFormat(java.lang.String, java.lang.String)
     */
    @Override
    public void setFormat(String name, String format)
    {
        if (_htAttributes.containsKey(name))
            _htAttributeFormats.put(name,format);
    }
}