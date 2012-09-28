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
package com.alfaariss.oa.util.saml2.metadata.entitydescriptor;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Locale;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.saml2.metadata.Company;
import org.opensaml.saml2.metadata.ContactPerson;
import org.opensaml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml2.metadata.EmailAddress;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.GivenName;
import org.opensaml.saml2.metadata.LocalizedString;
import org.opensaml.saml2.metadata.Organization;
import org.opensaml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml2.metadata.OrganizationName;
import org.opensaml.saml2.metadata.OrganizationURL;
import org.opensaml.saml2.metadata.SurName;
import org.opensaml.saml2.metadata.TelephoneNumber;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.server.Server;
import com.alfaariss.oa.util.saml2.crypto.SAML2CryptoUtils;
import com.alfaariss.oa.util.saml2.metadata.AbstractMetadataBuilder;

/**
 * Builder for entity descriptor.
 *
 * This builder does not add any role descriptors.
 * 
 * @author EVB
 * @author Alfa & Ariss
 */
public class EntityDescriptorBuilder extends AbstractMetadataBuilder 
{
    private Log _logger;
    private IConfigurationManager _configuration;
    private Element _eMetadata;
    private Server _serverInfo;  
    private EntityDescriptor _result;
       
    /**
     * Default constructor.
     * @param configuration The configuration manager.
     * @param eMetadata The metadata section.
     * @param serverInfo The Server object containing basic server information.
     */
    public EntityDescriptorBuilder(IConfigurationManager configuration, 
        Element eMetadata, Server serverInfo)
    {
        super();
        _logger = LogFactory.getLog(EntityDescriptorBuilder.class);
        _configuration = configuration;
        _eMetadata = eMetadata;
        _serverInfo = serverInfo;
        
        org.opensaml.saml2.metadata.impl.EntityDescriptorBuilder builder = 
            (org.opensaml.saml2.metadata.impl.EntityDescriptorBuilder)
            _builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);

        // Create the assertion
        _result = builder.buildObject();
    }
    
    /**
     * Build the optional <code>ID</code>.
     * 
     * An optional document-unique identifier for the element.
     */
    public void buildID()
    {        
       _result.setID(_serverInfo.getID()); 
    }

    /**
     * Build the mandatory <code>entityID</code>.
     *
     * Specifies the unique identifier of the SAML entity whose metadata is 
     * described by the element's contents. This element is mandatory.
     * @throws OAException  If creation fails.
     */
    public void buildEntityID() throws OAException
    {
        String sEntityID = null;
        try
        {
            sEntityID = _configuration.getParam(
                _eMetadata, "entityID");
            if(sEntityID == null || sEntityID.length() <= 0)
            {
                _logger.error("Empty required entity ID");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            _result.setEntityID(sEntityID);
        }
        catch(IllegalArgumentException e) //ID invalid
        {                
            _logger.error("Not a valid entity ID: " 
                + sEntityID == null ? "" : sEntityID, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
    }
    
    /**
     * Build the optional <code>&lt;Organization&gt;</code> element.
     * 
     * Optional element identifying the organization responsible for the SAML 
     * entity described by the element.
     * @throws OAException If building fails.
     */
    public void buildOrganization() throws OAException
    {
        try
        {
            Element eOrg = _configuration.getSection(_eMetadata, "organization");
            if(eOrg != null)
            {      
                //OA Configuration does not support localization; the  default locale is used
                String language = Locale.getDefault().getLanguage();
                
                com.alfaariss.oa.engine.core.server.Organization orgInfo = 
                    _serverInfo.getOrganization();
                SAMLObjectBuilder builder = (SAMLObjectBuilder)_builderFactory.getBuilder(
                    Organization.DEFAULT_ELEMENT_NAME); 
                Organization organization = (Organization)builder.buildObject();
                
                String sOrgName = orgInfo.getID();
                if(sOrgName.length() <= 0)
                {

                    _logger.error("Empty required OrganizationName");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                SAMLObjectBuilder organizationNameBuilder = 
                    (SAMLObjectBuilder)_builderFactory.getBuilder(
                            OrganizationName.DEFAULT_ELEMENT_NAME); 
                OrganizationName organizationName = 
                    (OrganizationName)organizationNameBuilder.buildObject();
                organizationName.setName(new LocalizedString(sOrgName, language));
                organization.getOrganizationNames().add(organizationName);
                
                String sOrgDisplayName = orgInfo.getFriendlyName();
                if(sOrgDisplayName.length() <= 0)
                {
                    _logger.error("Empty required OrganizationDisplayName");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                SAMLObjectBuilder organizationDisplayNameBuilder = 
                    (SAMLObjectBuilder)_builderFactory.getBuilder(
                            OrganizationDisplayName.DEFAULT_ELEMENT_NAME);  
                OrganizationDisplayName oDisplayName = 
                    (OrganizationDisplayName)organizationDisplayNameBuilder.buildObject();
                oDisplayName.setName(new LocalizedString(
                    orgInfo.getFriendlyName(), language));
                organization.getDisplayNames().add(oDisplayName);
                
                //TODO EVB: Add organization URL parameter to standard organization section
                String sURL = _configuration.getParam(eOrg, "url");
                if(sURL == null)
                {
                    _logger.error("No organization URL configured");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                try
                {
                    new URL(sURL);
                }
                catch(MalformedURLException e)
                {
                    _logger.error("Invalid organization URL configured: " + sURL, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                SAMLObjectBuilder organizationURLBuilder = 
                    (SAMLObjectBuilder)_builderFactory.getBuilder(
                            OrganizationURL.DEFAULT_ELEMENT_NAME);  
                OrganizationURL oOrganizationURL = 
                    (OrganizationURL)organizationURLBuilder.buildObject();
                oOrganizationURL.setURL(new LocalizedString(sURL, language));
                organization.getURLs().add(oOrganizationURL);   
                _result.setOrganization(organization);   
            }
        }
        catch(ConfigurationException e)
        {
            _logger.error("Error while reading configuration", e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
    }
    
    /**
     * Build the optional <code>validUntil</code>.
     * 
     * Optional attribute indicates the expiration time of the metadata 
     * contained in the element and any contained elements.
     */
    public void buildValidUntil()
    {
        //TODO JRE, RDV: Define usecase metadata valid until.
        //TODO Build the optional <code>validUntil</code>.        
    }

    /**
     * Build the optional <code>cacheDuration</code>.
     * 
     * Optional attribute indicates the maximum length of time a consumer should 
     * cache the metadata contained in the element and any contained elements.
     * @throws OAException If configuration is invalid
     */
    public void buildCacheDuration() throws OAException
    {
        String cacheDuration = null;
        try
        {
            cacheDuration = _configuration.getParam(_eMetadata, "cacheDuration");
            if (cacheDuration != null)
            {
                Long longCacheDuration = Long.valueOf(cacheDuration);
                if (longCacheDuration != null)
                    _result.setCacheDuration(longCacheDuration);
            }
        }
        catch(NumberFormatException e)
        {
            _logger.error("Invalid 'cacheDuration' configured: " + cacheDuration, e);
            throw new OAException(SystemErrors.ERROR_INIT);
        }
        catch(ConfigurationException e)
        {
            _logger.error("Error while reading cacheDuration configuration", e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }            
    }

    /**
     * Build the optional <code>&lt;ContactPerson&gt;</code> elements.
     * 
     * Optional sequence of elements identifying various kinds of contact 
     * personnel. This method can be called multiple times to add zero or more 
     * contact persons.
     * @throws OAException If configuration is invalid
     */
    public void buildContactPersons() throws OAException
    {
        try
        {
            Element eContactPersons = _configuration.getSection(_eMetadata, "ContactPersons");
            if (eContactPersons != null)
            {
                Element eContactPerson = _configuration.getSection(eContactPersons, "ContactPerson");
                while (eContactPerson != null)
                {
                    SAMLObjectBuilder builder = (SAMLObjectBuilder)_builderFactory.getBuilder(
                        ContactPerson.DEFAULT_ELEMENT_NAME); 
                    ContactPerson contactPerson = (ContactPerson)builder.buildObject();
                    
                    String sContactType = _configuration.getParam(eContactPerson, "contactType");
                    if (sContactType == null)
                    {
                        _logger.error("No required contactType configured for contactPerson");
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    ContactPersonTypeEnumeration contactPersonType = ContactPersonTypeEnumeration.OTHER;
                    if (sContactType.equalsIgnoreCase(ContactPersonTypeEnumeration.OTHER.toString()))
                        contactPersonType = ContactPersonTypeEnumeration.OTHER;
                    else if (sContactType.equalsIgnoreCase(ContactPersonTypeEnumeration.ADMINISTRATIVE.toString()))
                        contactPersonType = ContactPersonTypeEnumeration.ADMINISTRATIVE;
                    else if (sContactType.equalsIgnoreCase(ContactPersonTypeEnumeration.BILLING.toString()))
                        contactPersonType = ContactPersonTypeEnumeration.BILLING;
                    else if (sContactType.equalsIgnoreCase(ContactPersonTypeEnumeration.SUPPORT.toString()))
                        contactPersonType = ContactPersonTypeEnumeration.SUPPORT;
                    else if (sContactType.equalsIgnoreCase(ContactPersonTypeEnumeration.TECHNICAL.toString()))
                        contactPersonType = ContactPersonTypeEnumeration.TECHNICAL;
                    else
                    {
                        _logger.error("Unsupported contactType configured for contactPerson: " + sContactType);
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    contactPerson.setType(contactPersonType);
                    
                    String sCompany = _configuration.getParam(eContactPerson, "Company");
                    if (sCompany != null)
                    {
                        SAMLObjectBuilder companyBuilder = 
                            (SAMLObjectBuilder)_builderFactory.getBuilder(
                                Company.DEFAULT_ELEMENT_NAME); 
                        Company company = (Company)companyBuilder.buildObject();
                        company.setName(sCompany);
                        contactPerson.setCompany(company);
                    }
                    
                    String sGivenName = _configuration.getParam(eContactPerson, "GivenName");
                    if (sGivenName != null)
                    {
                        SAMLObjectBuilder givenNameBuilder = 
                            (SAMLObjectBuilder)_builderFactory.getBuilder(
                                GivenName.DEFAULT_ELEMENT_NAME); 
                        GivenName givenName = (GivenName)givenNameBuilder.buildObject();
                        givenName.setName(sGivenName);
                        contactPerson.setGivenName(givenName);
                    }
                    
                    String sSurName = _configuration.getParam(eContactPerson, "SurName");
                    if (sSurName != null)
                    {
                        SAMLObjectBuilder surNameBuilder = 
                            (SAMLObjectBuilder)_builderFactory.getBuilder(
                                SurName.DEFAULT_ELEMENT_NAME); 
                        SurName surName = (SurName)surNameBuilder.buildObject();
                        surName.setName(sSurName);
                        contactPerson.setSurName(surName);
                    }
                    
                    Element eEmailAddresses = _configuration.getSection(eContactPerson, "EmailAddresses");
                    if (eEmailAddresses != null)
                    {
                        Element eEmailAddress = _configuration.getSection(eEmailAddresses, "EmailAddress");
                        while (eEmailAddress != null)
                        {
                            //DD using XML object directory for reading config instead of using the configmanager, because the configmanager doesn't support getNextParam() functionality
                            String sEmailAddress = eEmailAddress.getTextContent();
                            if (sEmailAddress != null)
                            {
                                SAMLObjectBuilder emailAddressBuilder = 
                                    (SAMLObjectBuilder)_builderFactory.getBuilder(
                                        EmailAddress.DEFAULT_ELEMENT_NAME); 
                                EmailAddress emailAddress = (EmailAddress)emailAddressBuilder.buildObject();
                                emailAddress.setAddress(sEmailAddress.trim());
                                
                                contactPerson.getEmailAddresses().add(emailAddress);
                            }
                            
                            eEmailAddress = _configuration.getNextSection(eEmailAddress);
                        }
                    }
                    
                    Element eTelephoneNumbers = _configuration.getSection(eContactPerson, "TelephoneNumbers");
                    if (eTelephoneNumbers != null)
                    {
                        Element eTelephoneNumber = _configuration.getSection(eTelephoneNumbers, "TelephoneNumber");
                        while (eTelephoneNumber != null)
                        {
                            //DD using XML object directory for reading config instead of using the configmanager, because the configmanager doesn't support getNextParam() functionality
                            String sTelephoneNumber = eTelephoneNumber.getTextContent();
                            if (sTelephoneNumber != null)
                            {
                                SAMLObjectBuilder telephoneNumberBuilder = 
                                    (SAMLObjectBuilder)_builderFactory.getBuilder(
                                        TelephoneNumber.DEFAULT_ELEMENT_NAME); 
                                TelephoneNumber telephoneNumber = (TelephoneNumber)telephoneNumberBuilder.buildObject();
                                telephoneNumber.setNumber(sTelephoneNumber.trim());
                                
                                contactPerson.getTelephoneNumbers().add(telephoneNumber);
                            }
                            
                            eTelephoneNumber = _configuration.getNextSection(eTelephoneNumber);
                        }
                    }
                    
                    _result.getContactPersons().add(contactPerson);
                    
                    eContactPerson = _configuration.getNextSection(eContactPerson);
                }
            }
        }
        catch(ConfigurationException e)
        {
            _logger.error("Error while reading ContactPersons configuration", e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
    }

    /**
     * Build the optional <code>&lt;AdditionalMetadataLocation&gt;</code> elements.
     * 
     * Optional sequence of namespace-qualified locations where additional 
     * metadata exists for the SAML entity. This method can be called multiple 
     * times to add zero or more additional locations.
     */
    public void buildAdditionalMetadataLocation()
    {
        //TODO Build the optional AdditionalMetadataLocation (EVB)        
    }
    
    /**
     * Build the optional <code>&lt;ds:Signature&gt;</code> element.
     *
     * An XML signature that authenticates the {@link EntityDescriptor}. 
     * This Signature is only created if metadata signing is enabled by 
     * configuration.
     * 
     * @param crypto The OA crypto manager.
     * @throws OAException If building signature fails.
     */
    public void buildSignature(CryptoManager crypto) throws OAException
    {
        String sEntityID = _result.getEntityID();
        if(sEntityID == null)
        {
            throw new IllegalArgumentException(
                "Entity ID not built yet, use buildEntityID() first");
        }
        try
        {
            // <signing enabled="true" /> ?
            Element eSigning = _configuration.getSection(_eMetadata, "signing");
            if(eSigning != null)
            {
                String sSigning = _configuration.getParam(eSigning, "enabled");                
                if("true".equalsIgnoreCase(sSigning)) //Signing enabled
                {
                    //Build signature
                    SignatureBuilder builder = 
                        (SignatureBuilder)_builderFactory.getBuilder(
                            Signature.DEFAULT_ELEMENT_NAME);   
                    Signature signature = builder.buildObject(
                        Signature.DEFAULT_ELEMENT_NAME); 
                    
                    signature.setSignatureAlgorithm(
                        SAML2CryptoUtils.getXMLSignatureURI(crypto));
                    
                    //Get signing credentials
                    X509Credential signingX509Cred = 
                        SAML2CryptoUtils.retrieveMySigningCredentials(
                            crypto, sEntityID);                         
                    signature.setSigningCredential(signingX509Cred);
                    
                    SecurityHelper.prepareSignatureParams(
                        signature, signingX509Cred, null, null);
                    
                    _result.setSignature(signature);
                    
                    //update digest algorithm
                    SAMLObjectContentReference contentReference = 
                        ((SAMLObjectContentReference)signature.getContentReferences().get(0));
                    contentReference.setDigestAlgorithm(
                        SAML2CryptoUtils.getXMLDigestMethodURI(crypto.getMessageDigest()));
                }
                else if(!"false".equalsIgnoreCase(sSigning))
                {
                    _logger.error(
                        "Invalid or missing enabled parameter found in 'signing' section");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }              
            }
        }
        catch (SecurityException e)
        {
           _logger.error("Could not build metadata signature", e);
           throw new OAException(SystemErrors.ERROR_INTERNAL);           
        } 
    }

    /**
     * Retrieve the builder result
     * 
     * @return The constructed <code>EntityDescriptor</code>.
     */
    public EntityDescriptor getResult()
    {
        return _result;
    }    
}