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

import java.util.HashMap;
import java.util.Map;

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
	/** Managed list of SAML2IDPProfile@ID to EntityDescriptor */
	protected static Map<String, EntityDescriptor> _mEntityDescriptors = new HashMap<String, EntityDescriptor>();
	/** Managed list of SAML2IDPProfile@ID to BindingProperties (of the Response Endpoint) */
	protected static Map<String, BindingProperties> _mSPSSOBindingProperties = new HashMap<String, BindingProperties>();
    
    /**
     * Returns the EntityDescriptor for the SAML2 IDP Profile ID if it is set.
     *
     * @param sIDPProfileId The SAML2IDPProfileId to find the EntityDescriptor for
     * @return The EntityDescriptor object.
     * @throws OAException If the entity descriptor is not set.
     */
    public static EntityDescriptor getEntityDescriptor(String sIDPProfileId) throws OAException
    {
        if (_mEntityDescriptors.containsKey(sIDPProfileId) && 
        		_mEntityDescriptors.get(sIDPProfileId) != null) {
        	return _mEntityDescriptors.get(sIDPProfileId);
        }
        
        throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
    }
    
    /**
     * Set the entity descriptor object of a SAML2 IDP Profile ID for general purpose 
     * by the authentication method.
     *
     * @param sIDPProfileId The SAML2IDPProfileId to register the EntityDescriptor instance with
     * @param oED The entity descriptor object.
     */
    public static void setEntityDescriptor(String sIDPProfileId, EntityDescriptor oED)
    {
        _mEntityDescriptors.put(sIDPProfileId, oED);
    }
    
    /**
     * Returns the BindingProperties if they are set.
     *
     * @param sIDPProfileId The SAML2IDPProfileId to find the BindingProperties for
     * @return The BindingProperties.
     * @throws OAException If the binding properties are not set.
     */
    public static BindingProperties getSPSSOBindingProperties(String sIDPProfileId) throws OAException
    {
    	if (_mSPSSOBindingProperties.containsKey(sIDPProfileId) && 
    			_mSPSSOBindingProperties.get(sIDPProfileId) != null) {
    		return _mSPSSOBindingProperties.get(sIDPProfileId);
    	}
    	 
        throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
    }
    
    /**
     * Set binding properties of the ResponseEndpoint of a SAML2IDPProfileId to be used by AuthN method.
     * 
     * 
     * @param bProps The <code>BindingProperties</code>
     */
    public static void setSPSSOBindingProperties(String sIDPProfileId, BindingProperties bProps)
    {
    	_mSPSSOBindingProperties.put(sIDPProfileId, bProps);
    }
}
