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
package com.alfaariss.oa.util.saml2.binding;

import org.opensaml.xml.parse.BasicParserPool;

/**
 * Base class for encoding and decoding factories.
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public abstract class AbstractBindingFactory
{
    /** The configuration. */
    protected BindingProperties _prop;
    
    /**
     * The XML parser pool.
     */
    protected BasicParserPool _pool;
    
    /**
     * Default protected constructor.
     * @param prop The bindings configuration properties.
     */
    protected AbstractBindingFactory(BindingProperties prop)
    {   
        _prop = prop;             
        _pool = new BasicParserPool();
        _pool.setNamespaceAware(true);   
    }  
}