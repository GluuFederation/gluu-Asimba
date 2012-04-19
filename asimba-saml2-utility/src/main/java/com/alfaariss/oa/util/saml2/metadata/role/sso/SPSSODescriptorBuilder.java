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

package com.alfaariss.oa.util.saml2.metadata.role.sso;

import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.util.saml2.metadata.role.IRoleDescriptorBuilder;

/**
 * Builder for IDPSSODescriptorBuilder elements.
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public class SPSSODescriptorBuilder extends
    AbstractSSODescriptorBuilder<SPSSODescriptor>
{
    /**
     * Initialize builder.
     * @param configuration
     * @param profile
     * @param oSPSSODescriptor The SPSSODescriptor to extend 
     *  (if <code>null</code> a new SPSSODescriptor will be constructed. 
     */
    public SPSSODescriptorBuilder (IConfigurationManager configuration, 
        Element profile, SPSSODescriptor oSPSSODescriptor)
    {
        super(configuration, profile);        
        
        if(oSPSSODescriptor == null)
        {
            org.opensaml.saml2.metadata.impl.SPSSODescriptorBuilder builder = 
                (org.opensaml.saml2.metadata.impl.SPSSODescriptorBuilder)
                _builderFactory.getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
    
            // Create the IDPSSODescriptor
            _result = builder.buildObject();
        }
        else
        {
            _result = oSPSSODescriptor; 
        }      
    }

    /**
     * Build optional <code>NameIDMappingService</code>.
     *
     * Zero or more elements of type EndpointType that describe endpoints that 
     * support the Name Identifier Mapping profile.
     */
    public void buildNameIDMappingService()
    {
        //TODO EVB: Build the optional <code>NameIDMappingService</code>.
    }

    /**
     * Build optional <code>AssertionIDRequestService</code>.
     *
     * Zero or more elements of type EndpointType that describe endpoints 
     * that support the profile of the Assertion Request protocol.
     */
    public void buildAssertionIDRequestService()
    {
      //TODO EVB: Build the optional <code>NameIDMappingService</code>.
    }

    /**
     * Build optional <code>AttributeProfile</code>.
     *
     * Zero or more elements of type anyURI that enumerate the attribute 
     * profiles supported by this identity provider. 
     */
    public void buildAttributeProfile()
    {
      //TODO EVB: Build the optional <code>AttributeProfile</code>.
    }

    /**
     * Build optional <code>Attribute</code>.
     *
     *  Zero or more elements that identify the SAML attributes supported 
     *  by the identity provider.
     */
    public void buildAttribute()
    {
        //TODO EVB: Build the optional <code>Attribute</code>s.
    }

    /**
     * @see IRoleDescriptorBuilder#getResult()
     */
    public SPSSODescriptor getResult()
    {
        return _result;
    }   
                                   
}
