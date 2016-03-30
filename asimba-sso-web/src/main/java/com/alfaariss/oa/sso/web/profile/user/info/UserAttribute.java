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
package com.alfaariss.oa.sso.web.profile.user.info;


/**
 * Contains a user attribute.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class UserAttribute implements IAttribute
{
    private final String _sName;
    private final Object _oValue;

    /**
     * Constructor.
     * 
     * @param name The attribute name.
     * @param value The attribute value.
     */
    public UserAttribute(String name, Object value)
    {
        _sName = name;
        _oValue = value;
    }
    /**
     * @see com.alfaariss.oa.sso.web.profile.user.info.IAttribute#getName()
     */
    @Override
    public String getName()
    {
        return _sName;
    }

    /**
     * @see com.alfaariss.oa.sso.web.profile.user.info.IAttribute#getValue()
     */
    @Override
    public Object getValue()
    {
        return _oValue;
    }

}
