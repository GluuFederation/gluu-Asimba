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
package com.alfaariss.oa.util.saml2;

import org.opensaml.saml2.metadata.EntityDescriptor;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.util.saml2.binding.BindingProperties;

/**
 * SAML2 Exchange class.
 * @author MHO
 * @author Alfa & Ariss
 */
public class SAML2Exchange
{
    private static EntityDescriptor _entityDescriptor;
    private static BindingProperties _spSSOBindingProperties;
    
    /**
     * Returns the EntityDescriptor if it is set.
     *
     * @return The EntityDescriptor object.
     * @throws OAException If the entity descriptor is not set.
     */
    public static EntityDescriptor getEntityDescriptor() throws OAException
    {
        if (_entityDescriptor == null) 
            throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
        
        return _entityDescriptor;
    }
    
    /**
     * Set the entity descriptor object for general purpose by the authentication
     * method.
     *
     * @param ed The entity descriptor object.
     */
    public static void setEntityDescriptor(EntityDescriptor ed)
    {
        _entityDescriptor = ed;
    }
    
    /**
     * Returns the BindingProperties if they are set.
     *
     * @return The BindingProperties.
     * @throws OAException If the binding properties are not set.
     */
    public static BindingProperties getSPSSOBindingProperties() throws OAException
    {
        if (_spSSOBindingProperties == null) 
            throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
        
        return _spSSOBindingProperties;
    }
    
    /**
     * Set binding properties to be used by AuthN method.
     * 
     * @param bProps The <code>BindingProperties</code>
     */
    public static void setSPSSOBindingProperties(BindingProperties bProps)
    {
        _spSSOBindingProperties = bProps;
    }
}
