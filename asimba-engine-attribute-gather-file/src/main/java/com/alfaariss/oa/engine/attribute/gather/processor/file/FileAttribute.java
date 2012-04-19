/*
 * Asimba Server
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
package com.alfaariss.oa.engine.attribute.gather.processor.file;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Vector;

/**
 * Attribute object used by file gatherer.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.5
 */
public class FileAttribute implements Serializable
{
    /** serialVersionUID */
    private static final long serialVersionUID = 8748747983489451817L;
    private String _sName;
    private String _sFormat;
    private List<Object> _listValues;

    /**
     * Constructor.
     * @param name The attribute name.
     */
    public FileAttribute(String name)
    {
        _sName = name;
        _sFormat = null;
        _listValues = new Vector<Object>();
    }
    
    /**
     * Constructor.
     * @param name The attribute name.
     * @param format The attribute format.
     */
    public FileAttribute(String name, String format)
    {
        _sName = name;
        _sFormat = format;
        _listValues = new Vector<Object>();
    }
    
    /**
     * Constructor with single value.
     * @param name The attribute name.
     * @param format The attribute format.
     * @param value The attribute value.
     */
    public FileAttribute(String name, String format, Object value)
    {
        _sName = name;
        _sFormat = format;
        _listValues = new Vector<Object>();
        _listValues.add(value);
    }
    
    /**
     * Constructor with multiple values.
     * @param name The attribute name.
     * @param format The attribute format.
     * @param values The attribute values.
     */
    public FileAttribute(String name, String format, Collection<?> values)
    {
        _sName = name;
        _sFormat = format;
        _listValues.addAll(values);
    }
    
    /**
     * Adds the supplied values to this attribute.
     * <br>
     * All items in the collection will be added as individual values.
     * @param values The values to be added.
     */
    public void addValues(Collection<?> values)
    {
        _listValues.addAll(values);
    }
    
    /**
     * Adds the supplied value to this attribute.
     * <br>
     * The supplied value will be added as one individual value also when it has 
     * the <code>Collection</code> type.
     * @param value The value to be added.
     */
    public void addValue(Object value)
    {
        _listValues.add(value);
    }
    
    /**
     * Returns the attribute name. 
     * @return The attribute name.
     */
    public String getName()
    {
        return _sName;
    }
    
    /**
     * Returns the attribute format. 
     * @return The attribute format or NULL if not available.
     */
    public String getFormat()
    {
        return _sFormat;
    }
    
    /**
     * Returns the value of this attribute.
     * <br>
     * If multiple values are available, only the first one will be returned. 
     * @return The attribute value. 
     */
    public Object getValue()
    {
        return _listValues.get(0);
    }
    
    /**
     * Returns all values of this attribute. 
     * @return List containing all values.
     */
    public List<Object> getValues()
    {
        return _listValues;
    }
    
    /**
     * Sets the attribute format. 
     * @param format The attribute format to be set.
     */
    public void setFormat(String format)
    {
        _sFormat = format;
    }
    
    /**
     * Return the hash code of the attribute name.
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        return _sName.hashCode();
    }
    
    /**
     * Compare with another object.
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object other)
    {
        if(!(other instanceof FileAttribute))
            return false;
        
        FileAttribute fAttr = (FileAttribute)other;
        
        if (_sName == null && fAttr.getName() != null)
            return false;
        else if (!_sName.equals(fAttr.getName()))
            return false;
        
        if (_sFormat == null && fAttr.getFormat() != null)
            return false;
        else if (!_sFormat.equals(fAttr.getFormat()))
            return false;
        
        if (_listValues == null && fAttr.getValues() != null)
            return false;
        else if (!_listValues.equals(fAttr.getValues()))
            return false;
        
        return true;
    }   
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    { 
        StringBuffer sbInfo = new StringBuffer(_sName);
        sbInfo.append(" (");
        sbInfo.append(_sFormat);
        sbInfo.append(")");
        return sbInfo.toString();
    }
    
}
