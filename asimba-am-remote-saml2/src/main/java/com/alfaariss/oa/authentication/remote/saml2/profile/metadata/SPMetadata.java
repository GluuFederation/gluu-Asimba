/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authentication.remote.saml2.profile.metadata;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.Signature;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow;
import com.alfaariss.oa.util.saml2.SAML2Requestors;
import com.alfaariss.oa.util.saml2.profile.metadata.AbstractMetadataProfile;

/**
 * SP Metadata supplier.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.1
 */
public class SPMetadata extends AbstractMetadataProfile
{
    private static Log _logger;
    
    /**
     * Constructor. 
     */
    public SPMetadata()
    {
        _logger = LogFactory.getLog(SPMetadata.class);
    }
    
    /**
     * @see com.alfaariss.oa.util.saml2.profile.metadata.AbstractMetadataProfile#init(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element, org.opensaml.saml2.metadata.EntityDescriptor, java.lang.String, java.lang.String, com.alfaariss.oa.util.saml2.SAML2Requestors, com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow, java.lang.String)
     */
    public void init(IConfigurationManager configurationManager,
        Element config, EntityDescriptor entityDescriptor, String baseUrl,
        String webSSOPath, SAML2Requestors requestors,
        SAML2IssueInstantWindow issueInstantWindow, String profileID)
        throws OAException
    {
        super.init(configurationManager, config, entityDescriptor, baseUrl, 
            webSSOPath, requestors, issueInstantWindow, profileID);
        
        SPSSODescriptor origSPSSODescriptor = _entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        if (origSPSSODescriptor != null)
        {
            SPSSODescriptor spSSODescriptor = cloneSPSSODescriptor(origSPSSODescriptor);
            _myEntityDescriptor.getRoleDescriptors().add(spSSODescriptor);
        }
        
        Signature signature = _entityDescriptor.getSignature();
        if (signature != null)
        {
            signSAMLObject(_myEntityDescriptor);
        }
        else
        {
            if(_myEntityDescriptor.getDOM() == null)
            {
                Marshaller marshaller = Configuration.getMarshallerFactory(
                    ).getMarshaller(_myEntityDescriptor);
                if (marshaller == null) 
                {
                    _logger.error("No marshaller registered for " + 
                        _myEntityDescriptor.getElementQName() + 
                        ", unable to marshall metadata");
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                try
                {
                    marshaller.marshall(_myEntityDescriptor);
                }
                catch (MarshallingException e)
                {
                    _logger.warn("Could not marshall", e);
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
            }
        }
    }
    
    /**
     * @see com.alfaariss.oa.util.saml2.profile.ISAML2Profile#destroy()
     */
    public void destroy()
    {
        super.destroy();
    }

    /**
     * @see com.alfaariss.oa.util.saml2.profile.ISAML2Profile#process(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    public void process(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) throws OAException
    {
        _logger.debug("Supplying SP Role Metadata");
        super.process(servletRequest, servletResponse);
    }
    
    private SPSSODescriptor cloneSPSSODescriptor(SPSSODescriptor orig) 
        throws OAException
    {
        SPSSODescriptor spRoleDescriptor = null;
        try
        {
            Element eSource = orig.getDOM();
            if(eSource == null)
            {
                Marshaller marshaller = Configuration.getMarshallerFactory(
                    ).getMarshaller(orig);
                if (marshaller == null) 
                {
                    _logger.error("No marshaller registered for " + 
                        orig.getElementQName() + 
                        ", unable to marshall metadata");
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                eSource = marshaller.marshall(orig);
            }
            
            SPSSODescriptorBuilder spSSOBuilder = 
                (SPSSODescriptorBuilder)_builderFactory.getBuilder(
                    SPSSODescriptor.DEFAULT_ELEMENT_NAME);
                
            spRoleDescriptor = spSSOBuilder.buildObject();
          
            spRoleDescriptor.setDOM((Element)eSource.cloneNode(true));
        }
        catch (MarshallingException e)
        {
            _logger.debug("Could not marshall object: " + 
                orig.getElementQName(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Could not clone SPSSODescriptor", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return spRoleDescriptor;
    }

}
