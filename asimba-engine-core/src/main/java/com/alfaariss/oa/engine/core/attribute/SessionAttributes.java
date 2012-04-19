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
package com.alfaariss.oa.engine.core.attribute;

import java.util.Enumeration;
import java.util.Hashtable;

import com.alfaariss.oa.api.attribute.ISessionAttributes;

/**
 * The Session Attributes object.
 *
 * @author MHO
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class SessionAttributes implements ISessionAttributes 
{
    /** serialVersionUID */
    private static final long serialVersionUID = 3322934500217377616L;
    private Hashtable<String, Object> _htAttributes;

	/**
	 * Create new empty attributes.
	 */
	public SessionAttributes()
    {
        _htAttributes = new Hashtable<String, Object>();
	}

	/**
     * Returns the attribute with the supplied name.
	 * @see com.alfaariss.oa.api.attribute.ISessionAttributes#get(java.lang.Class, java.lang.String)
	 */
	public Object get(Class oClass, String sName)
    {
        StringBuffer sbName = new StringBuffer(oClass.getName());
        sbName.append(".");
        sbName.append(sName);
        return _htAttributes.get(sbName.toString());
	}

	/**
     * @see com.alfaariss.oa.api.attribute.ISessionAttributes#get(java.lang.Class, java.lang.String, java.lang.String)
     */
    public Object get(Class<?> oClass, String sID, String sName)
    {
        StringBuffer sbName = new StringBuffer(oClass.getName());
        sbName.append(".");
        sbName.append(sID);
        sbName.append(".");
        sbName.append(sName);
        return _htAttributes.get(sbName.toString());
    }

    /**
	 * Returns all attribute names as an <code>Enumeration</code>.
	 * @see com.alfaariss.oa.api.attribute.ISessionAttributes#getNames()
	 */
	public Enumeration<?> getNames()
    {
        return _htAttributes.keys();
    }

    /**
     * Removes the attribute with the supplied name.
	 * @see com.alfaariss.oa.api.attribute.ISessionAttributes#remove(java.lang.Class, java.lang.String)
	 */
	public void remove(Class oClass, String sName)
    {
        StringBuffer sbName = new StringBuffer(oClass.getName());
        sbName.append(".");
        sbName.append(sName);
	    _htAttributes.remove(sbName.toString());
	}

    /**
     * @see com.alfaariss.oa.api.attribute.ISessionAttributes#remove(java.lang.Class, java.lang.String, java.lang.String)
     */
    public void remove(Class<?> oClass, String sID, String sName)
    {
        StringBuffer sbName = new StringBuffer(oClass.getName());
        sbName.append(".");
        sbName.append(sID);
        sbName.append(".");
        sbName.append(sName);
        _htAttributes.remove(sbName.toString());
    }

    /**
     * Checks if the attribute with the supplied name exists.
     * @see com.alfaariss.oa.api.attribute.ISessionAttributes#contains(java.lang.Class, java.lang.String)
     */
    public boolean contains(Class oClass, String sName)
    {
        StringBuffer sbName = new StringBuffer(oClass.getName());
        sbName.append(".");
        sbName.append(sName);
        return _htAttributes.containsKey(sbName.toString());
    }

    /**
     * @see com.alfaariss.oa.api.attribute.ISessionAttributes#contains(java.lang.Class, java.lang.String, java.lang.String)
     */
    public boolean contains(Class<?> oClass, String sID, String sName)
    {
        StringBuffer sbName = new StringBuffer(oClass.getName());
        sbName.append(".");
        sbName.append(sID);
        sbName.append(".");
        sbName.append(sName);
        return _htAttributes.containsKey(sbName.toString());
    }

    /**
     * Stores or overwrites the supplied attribute.
     * @see com.alfaariss.oa.api.attribute.ISessionAttributes#put(java.lang.Class, java.lang.String, java.lang.Object)
     */
    public void put(Class oClass, String sName, Object oValue)
    {
        StringBuffer sbName = new StringBuffer(oClass.getName());
        sbName.append(".");
        sbName.append(sName);
        _htAttributes.put(sbName.toString(), oValue);
    }
    
    /**
     * Stores or overwrites the supplied attribute.
     * This method is added for components that can be configured multiple times 
     * like authn methods, so that attributes can't be used by multiple the same 
     * authn methods. In this case the supplied id must be the configured authn 
     * method id. 
     * @see com.alfaariss.oa.api.attribute.ISessionAttributes#put(java.lang.Class, java.lang.String, java.lang.String, java.lang.Object)
     */
    public void put(Class<?> oClass, String sID, String sName, Object oValue)
    {
        StringBuffer sbName = new StringBuffer(oClass.getName());
        sbName.append(".");
        sbName.append(sID);
        sbName.append(".");
        sbName.append(sName);
        _htAttributes.put(sbName.toString(), oValue);
    }
    
    /**
     * Return the hash code of the attributes.
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        return _htAttributes.hashCode();
    }
    
    /**
     * Compare with another object.
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object other)
    {
        if(!(other instanceof SessionAttributes))
            return false;
        return _htAttributes.equals(other);
    }   
    
    /**
     * Return all attributes in a <code>String</code>.
     * @see java.lang.Object#toString()
     */
    public String toString()
    { 
        return _htAttributes.toString();
    }

    /**
     * @see com.alfaariss.oa.api.attribute.ISessionAttributes#size()
     */
    public int size()
    {
        return _htAttributes.size();
    }
}