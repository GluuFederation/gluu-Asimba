/*
 * Asimba - Serious Open Source SSO
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

package com.alfaariss.oa.authentication.remote.saml2.profile.re.metadata;

import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.util.saml2.binding.BindingProperties;
import com.alfaariss.oa.util.saml2.metadata.role.IRoleDescriptorBuilder;
import com.alfaariss.oa.util.saml2.metadata.role.sso.AbstractSSODescriptorBuilder;

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
     * Build <code>AssertionConsumerService</code>(s).
     *
     * One or more elements that describe indexed endpoints that support the profiles of the
     * Authentication Request protocol defined in [SAMLProf]. All service providers support 
     * at least one such endpoint, by definition.
     * 
     * @param endpoint Default endpoint for assertion consumer service.
     * @param pBindings Supported bindings.
     */
    public void buildAssertionConsumerServices(String endpoint, BindingProperties pBindings)
    {     
        SAMLObjectBuilder endpointBuilder = 
            (SAMLObjectBuilder)_builderFactory.getBuilder(
                AssertionConsumerService.DEFAULT_ELEMENT_NAME); 
        
        String defaultBinding = pBindings.getDefault();
        int index = 0;
        for(String binding : pBindings.getBindings())
        {
            AssertionConsumerService acs = (AssertionConsumerService)endpointBuilder.buildObject();
            acs.setBinding(binding);
            acs.setLocation(endpoint);
            if (binding.equals(defaultBinding)) acs.setIsDefault(true);
            else acs.setIsDefault(false);
            acs.setIndex(index);
            index++;
            _result.getAssertionConsumerServices().add(acs);
        } 
    }

    /**
     * Build <code>AttributeConsumingService</code>(s).
     * 
     * Zero or more elements that describe an application or service provided by the service 
     * provider that requires or desires the use of SAML attributes.
     */
    public void buildAttributeConsumingService()
    {
    }
    
    /**
     * Set AuthnRequestsSigned.
     * 
     * Optional attribute that indicates whether the &lt;samlp:AuthnRequest&gt; messages sent by 
     * this service provider will be signed. If omitted, the value is assumed to be false.
     * 
     * @param signed true, if AuthN requests must be signed. 
     */
    public void buildAuthnRequestsSigned(boolean signed)
    {
        _result.setAuthnRequestsSigned(signed);
    }
    
    /**
     * Set WantAssertionsSigned.
     * 
     * Optional attribute that indicates a requirement for the &lt;saml:Assertion&gt; elements 
     * received by this service provider to be signed. If omitted, the value is assumed to 
     * be false. This requirement is in addition to any requirement for signing derived from 
     * the use of a particular profile/binding combination.
     * 
     * @param signed true, if SP requires assertions to be signed. 
     */
    public void buildWantAssertionsSigned(boolean signed)
    {
        _result.setWantAssertionsSigned(signed);
    }

    /**
     * @see IRoleDescriptorBuilder#getResult()
     */
    public SPSSODescriptor getResult()
    {
        return _result;
    }   
                                   
}
