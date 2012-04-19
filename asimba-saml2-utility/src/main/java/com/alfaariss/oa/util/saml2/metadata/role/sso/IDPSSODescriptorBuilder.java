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

import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.util.saml2.binding.BindingProperties;
import com.alfaariss.oa.util.saml2.metadata.role.IRoleDescriptorBuilder;

/**
 * Builder for IDPSSODescriptorBuilder elements.
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public class IDPSSODescriptorBuilder extends
    AbstractSSODescriptorBuilder<IDPSSODescriptor>
{
    /**
     * Initialize builder.
     * @param configuration
     * @param profile
     * @param oIDPSSODescriptor The IDPSSODescriptor to extend 
     *  (if <code>null</code> a new IDPSSODescriptor will be constructed. 
     */
    public IDPSSODescriptorBuilder (IConfigurationManager configuration, 
        Element profile, IDPSSODescriptor oIDPSSODescriptor)
    {
        super(configuration, profile);        
        
        if(oIDPSSODescriptor == null)
        {
            org.opensaml.saml2.metadata.impl.IDPSSODescriptorBuilder builder = 
                (org.opensaml.saml2.metadata.impl.IDPSSODescriptorBuilder)
                _builderFactory.getBuilder(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
    
            // Create the IDPSSODescriptor
            _result = builder.buildObject();
        }
        else
        {
            _result = oIDPSSODescriptor; 
        }      
    }

    /**
     * Build optional <code>WantAuthnRequestsSigned</code>.
     *
     * Optional attribute that indicates a requirement for the 
     * <code>&lt;samlp:AuthnRequest&gt;</code> messages received by this 
     * identity provider to be signed.
     * @param b The value to be used as <code>WantAuthnRequestsSigned</code>.
     */
    public void buildWantAuthnRequestsSigned(boolean b)
    {
        //DD OA wants AuthnRequests signed is defined globally, validation can be omitted per pool by configuration
        _result.setWantAuthnRequestsSigned(b);        
    }

    /**
     * Build mandatory <code>SingleSignOnService</code>.
     * 
     * One or more elements of type EndpointType that describe endpoints 
     * that support the profiles of the Authentication Request protocol.
     * @param pBindings Contains the supported bindings.
     * @param endpoint The endpoint for this service.
     */
    public void buildSingleSignOnService(String endpoint, BindingProperties pBindings)
    {     
        SAMLObjectBuilder endpointBuilder = 
            (SAMLObjectBuilder)_builderFactory.getBuilder(
                SingleSignOnService.DEFAULT_ELEMENT_NAME); 
        
        for(String binding : pBindings.getBindings())
        {
            SingleSignOnService sso = (SingleSignOnService)endpointBuilder.buildObject();
            sso.setBinding(binding);
            sso.setLocation(endpoint);
            _result.getSingleSignOnServices().add(sso);
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
    public IDPSSODescriptor getResult()
    {
        return _result;
    }   
                                   
}
