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
package com.alfaariss.oa.util.saml2.profile.metadata;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.ContactPerson;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.Organization;
import org.opensaml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.util.saml2.SAML2Constants;
import com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow;
import com.alfaariss.oa.util.saml2.SAML2Requestors;
import com.alfaariss.oa.util.saml2.profile.AbstractSAML2Profile;

/**
 * IdP Metadata supplier.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.2
 */
abstract public class AbstractMetadataProfile extends AbstractSAML2Profile
{
    /** Metadata descriptor of this profile */
    protected EntityDescriptor _myEntityDescriptor;
    /** XML object builder factory */
    protected XMLObjectBuilderFactory _builderFactory;
    
    private static Log _logger;
    
    /**
     * Constructor. 
     */
    public AbstractMetadataProfile()
    {
        _logger = LogFactory.getLog(this.getClass());
        _builderFactory = Configuration.getBuilderFactory();
    }
    
    /**
     * @see com.alfaariss.oa.util.saml2.profile.ISAML2Profile#destroy()
     */
    public void destroy()
    {
        super.destroy();
    }

    /**
     * @see com.alfaariss.oa.util.saml2.profile.ISAML2Profile#init(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element, org.opensaml.saml2.metadata.EntityDescriptor, java.lang.String, java.lang.String, com.alfaariss.oa.util.saml2.SAML2Requestors, com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow, java.lang.String)
     */
    public void init(IConfigurationManager configurationManager,
        Element config, EntityDescriptor entityDescriptor, String baseUrl,
        String webSSOPath, SAML2Requestors requestors,
        SAML2IssueInstantWindow issueInstantWindow, String profileID)
        throws OAException
    {
        super.init(configurationManager, config, entityDescriptor, baseUrl, 
            webSSOPath, requestors, issueInstantWindow, profileID);
        
        _myEntityDescriptor = copyMetadata(entityDescriptor);
    }

    /**
     * @see com.alfaariss.oa.util.saml2.profile.ISAML2Profile#process(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    public void process(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) throws OAException
    {
        try
        {
            handleMetaData(servletResponse, _myEntityDescriptor);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.warn(
                "Internal Error while supplying metadata", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Pretty print the metadata to the printwriter.
     * @param servletResponse The servlet response where the metadata should be written to.
     * @param entityDescriptor The metadata.
     * @throws OAException If an internal error ocurred.
     */
    protected void handleMetaData(
        HttpServletResponse servletResponse, EntityDescriptor entityDescriptor) 
        throws OAException
    {
        PrintWriter pwOut = null;
        try 
        {
            TransformerFactory tfactory = TransformerFactory.newInstance();
            Transformer serializer = tfactory.newTransformer();
            servletResponse.setContentType(SAML2Constants.METADATA_CONTENT_TYPE);
            servletResponse.setHeader("Content-Disposition", 
                "attachment; filename=metadata.xml");
            
            //TODO EVB, MHO: cache processing conform RFC2616 [saml-metadata r1404]
            pwOut = servletResponse.getWriter();
            serializer.transform(new DOMSource(entityDescriptor.getDOM()), new StreamResult(pwOut));
        }  
        catch (IOException e)
        {
            _logger.warn(
                "I/O error while processing metadata request", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch (Exception e) 
        {
            _logger.warn(
                "Internal Error while processing metadata request", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        } 
        finally
        {
            if(pwOut != null)
                pwOut.close();
        }       
    }

    /**
     * Copying metadata parameters from the supplied entity descriptor.
     * @param entityDescriptor The metadata which must be used as source to copy.
     * @return The new metadata with copied items.
     * @throws OAException If an internal error ocurred.
     */
    protected EntityDescriptor copyMetadata(EntityDescriptor entityDescriptor) 
        throws OAException
    {
        try
        {   
            EntityDescriptorBuilder builder = (EntityDescriptorBuilder)
                _builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
            
            EntityDescriptor descriptor = builder.buildObject();
            
            descriptor.setEntityID(entityDescriptor.getEntityID());
            descriptor.setID(entityDescriptor.getID());
            descriptor.setValidUntil(entityDescriptor.getValidUntil());
            descriptor.setCacheDuration(entityDescriptor.getCacheDuration());
            
            Organization organization = entityDescriptor.getOrganization();
            if (organization != null)
            {
                Organization newOrganization = (Organization)cloneXMLObject(organization);
                descriptor.setOrganization(newOrganization);
            }
            
            for (ContactPerson cp: entityDescriptor.getContactPersons())
            {
                ContactPerson contactPerson = (ContactPerson)cloneXMLObject(cp);
                descriptor.getContactPersons().add(contactPerson);
            }
            
            return descriptor;
        }       
        catch(Exception e)
        {
            _logger.error("Could not construct metadata", e);
            throw new OAException(SystemErrors.ERROR_INIT);
        }
    }

    /**
     * Performs a deep clone of the supplied object. 
     * @param object The XML object to be cloned.
     * @return A deep clone of the supplied object.
     * @throws OAException If marshalling fails
     */
    protected XMLObject cloneXMLObject(XMLObject object) throws OAException
    {
        Element eClone = null;
        try
        {   
            Element eSource = object.getDOM();
            if(eSource == null)
            {
                Marshaller marshaller = Configuration.getMarshallerFactory(
                    ).getMarshaller(object);
                if (marshaller == null) 
                {
                    _logger.error("No marshaller registered for " + 
                        object.getElementQName() + 
                        ", unable to marshall metadata");
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                eSource = marshaller.marshall(object);
            }
            
            eClone = (Element)eSource.cloneNode(true);
            
            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(eClone);
            if (unmarshaller == null)
            {
                _logger.error("No unmarshaller registered for " + 
                    eClone.getNodeName() + ", unable to unmarshall metadata");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            return unmarshaller.unmarshall(eClone);
        }
        catch (MarshallingException e)
        {
            _logger.debug("Could not marshall object: " + 
                object.getElementQName(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch (UnmarshallingException e)
        {
            _logger.debug("Could not unmarshall object: " + 
                eClone.getNodeName(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.warn(
                "Internal Error while cloning object: " + 
                object.getElementQName(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
}
