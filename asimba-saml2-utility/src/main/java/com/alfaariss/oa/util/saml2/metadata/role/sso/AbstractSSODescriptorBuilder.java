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
package com.alfaariss.oa.util.saml2.metadata.role.sso;

import java.util.List;

import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.common.impl.ExtensionsBuilder;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.SSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml2.metadata.impl.NameIDFormatBuilder;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.util.saml2.binding.BindingProperties;
import com.alfaariss.oa.util.saml2.crypto.SAML2CryptoUtils;
import com.alfaariss.oa.util.saml2.metadata.AbstractMetadataBuilder;
import com.alfaariss.oa.util.saml2.metadata.role.IRoleDescriptorBuilder;

/**
 * Abstract builder for SSODescriptor elements.
 *
 * Base class for the concrete {@link IDPSSODescriptorBuilder}.
 * 
 * @author EVB
 * @author Alfa & Ariss
 * @param <RD> The concrete role descriptor type.
 */
public abstract class AbstractSSODescriptorBuilder<RD extends SSODescriptor> 
    extends AbstractMetadataBuilder implements IRoleDescriptorBuilder<RD>
{
    private Log _logger;
    /** Configuration manager */
    protected IConfigurationManager _configuration;
    /** Profile section */
    protected Element _eProfile;
    /** The result. */
    protected RD _result;
    
    /**
     * Initialized builder.
     * 
     * @param configuration The configuration manager.
     * @param eProfile The configuration for this builder.
     */
    public AbstractSSODescriptorBuilder(IConfigurationManager configuration, 
        Element eProfile)
    {
        super();
        _logger = LogFactory.getLog(AbstractSSODescriptorBuilder.class);
        _configuration = configuration;
        _eProfile = eProfile;
    }
    
    /**
     * @see IRoleDescriptorBuilder#buildID()
     */
    public void buildID() throws OAException
    {
        try
        {
            //Use profile ID as SSODescriptor ID
            String sID = _configuration.getParam(_eProfile, "id");
            if(sID == null || sID.trim().length() <= 0)
            {
                _logger.error("Empty 'id' item in 'profile' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            _result.setID(sID);
        }
        catch (ConfigurationException e)
        {
            _logger.error("Could not read from configuration", e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }        
    }
    
    /**
     * @see IRoleDescriptorBuilder#buildProtocolSupportEnumeration()
     */
    public void buildProtocolSupportEnumeration()
    {
        //DD Only SAML v2 is supported
        _result.addSupportedProtocol(SAMLConstants.SAML20P_NS);
    }
    
    /**
     * @see IRoleDescriptorBuilder#buildErrorURL()
     */
    public void buildErrorURL()
    {
      //TODO Build the optional <code>ErrorURL</code>.        
    }

    /**
     * @see IRoleDescriptorBuilder#buildSigningKeyDescriptor(
     *  CryptoManager, String)
     */
    public void buildSigningKeyDescriptor(CryptoManager crypto,
        String sEntityID) throws OAException
    {
        try
        {
            //Build signing key descriptor
            KeyDescriptorBuilder keyDescriptorBuilder = 
                (KeyDescriptorBuilder)_builderFactory.getBuilder(
                    KeyDescriptor.DEFAULT_ELEMENT_NAME);       
            KeyDescriptor keyDescriptor = keyDescriptorBuilder.buildObject();
    
            keyDescriptor.setUse(UsageType.SIGNING);
            
            //TODO EVB: build EncryptionMethod
//            EncryptionMethodBuilder encryptionMethodBuilder = 
//                (EncryptionMethodBuilder)_builderFactory.getBuilder(
//                    EncryptionMethod.DEFAULT_ELEMENT_NAME);       
//            EncryptionMethod method = encryptionMethodBuilder.buildObject();
//            
//            String sAlgorithm = SAML2CryptoUtils.getXMLSignatureURI(crypto);
//            method.setAlgorithm(sAlgorithm);
//            
//            keyDescriptor.getEncryptionMethods().add(method);  
            
            //Build credential
            X509Credential signingCredential = 
                SAML2CryptoUtils.retrieveMySigningCredentials(
                    crypto, sEntityID);
            
            // Using default: Configuration.getGlobalSecurityConfiguration and XMLSignature
            SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
            NamedKeyInfoGeneratorManager kiMgr = secConfig.getKeyInfoGeneratorManager();
            KeyInfoGeneratorFactory kiFactory = kiMgr.getDefaultManager().getFactory(signingCredential);
               
            KeyInfoGenerator kiGenerator = kiFactory.newInstance();
            if (kiGenerator != null) 
            {
                KeyInfo keyInfo = kiGenerator.generate(signingCredential);
                keyDescriptor.setKeyInfo(keyInfo);  
            }
            
            _result.getKeyDescriptors().add(keyDescriptor);    
        }
        catch (SecurityException e)
        {
           _logger.error("Could not generate SigningKeyDescriptor", e);
           throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Build optional <code>ArtifactResolutionService</code> 
     *
     *  Zero or more elements of type IndexedEndpointType that describe indexed 
     *  endpoints that support the Artifact Resolution profile. 
     * @param endpoint The endpoint for this service.
     */
    public void buildArtifactResolutionService(String endpoint)
    {
        SAMLObjectBuilder endpointBuilder = 
            (SAMLObjectBuilder)_builderFactory.getBuilder(
                ArtifactResolutionService.DEFAULT_ELEMENT_NAME);
        List<ArtifactResolutionService> services = _result.getArtifactResolutionServices();
        ArtifactResolutionService ars = (ArtifactResolutionService)endpointBuilder.buildObject();
        ars.setIndex(new Integer(services.size()));
        ars.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
        ars.setLocation(endpoint);
        services.add(ars);
    }
   
    /**
     * Build optional <code>SingleLogoutService</code>.
     *
     * Zero or more elements of type EndpointType that describe endpoints 
     * that support the Single Logout profiles.
     * @param endpoint The endpoint for this service.
     * @param pBindings Contains the supported bindings.
     */
    public void buildSingleLogoutService(String endpoint, BindingProperties pBindings)
    {
        SAMLObjectBuilder endpointBuilder = 
            (SAMLObjectBuilder)_builderFactory.getBuilder(
                SingleLogoutService.DEFAULT_ELEMENT_NAME); 
        
        for(String binding : pBindings.getBindings())
        {
            SingleLogoutService sls = (SingleLogoutService)endpointBuilder.buildObject();
            sls.setBinding(binding);
            sls.setLocation(endpoint);
            _result.getSingleLogoutServices().add(sls);
        }        
    }                              
                                 
    /**
     * Build optional <code>ManageNameIDService</code>.
     *
     * Zero or more elements of type EndpointType that describe endpoints 
     * that support the Name Identifier Management profiles.
     */
    public void buildManageNameIDService()
    {
      //TODO Implement the ManageNameIDService (EVB)
    }                                                           
                                
    /**
     * Build optional <code>NameIDFormat</code>.
     *
     * Zero or more elements of type anyURI that enumerate the name identifier 
     * formats supported by this system entity acting in this role. 
     * @throws OAException if nameid format could not be build.
     */
    public void buildNameIDFormats() throws OAException
    {
        try
        {          
            Element eNameIDs = _configuration.getSection(_eProfile, "nameid");
            if(eNameIDs != null) //Name id's configured
            {
                //Get formats
                List<NameIDFormat> formats = _result.getNameIDFormats();
                
                //Create builder
                NameIDFormatBuilder nameIDFormatBuilder = 
                    (NameIDFormatBuilder)_builderFactory.getBuilder(
                        NameIDFormat.DEFAULT_ELEMENT_NAME);
                //Get first format
                Element eFormat = _configuration.getSection(eNameIDs, "format");
                while (eFormat != null) //For all formats
                {
                    String id = _configuration.getParam(eFormat, "id");                   
                    if (id == null)
                    {
                        _logger.error(
                            "No 'id' item found in 'format' section in configuration");
                        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    //Check for duplicates
                    boolean bFound = false;
                    for(NameIDFormat format : formats)
                    {
                        if(id.equals(format.getFormat()))
                        {
                            bFound = true;
                            break;
                        }
                    }
                    
                    if(!bFound) //Not found yet
                    {
                        NameIDFormat format = nameIDFormatBuilder.buildObject();                  
                        format.setFormat(id);                                     
                        formats.add(format);
                    }
                    
                    //get next format
                    eFormat = _configuration.getNextSection(eFormat);
                }
            }
        }
        catch (ConfigurationException e)
        {
            _logger.error("Could not read from configuration", e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }        
    }
    
    /**
     * Build optional Extensions from configuration.
     * @see com.alfaariss.oa.util.saml2.metadata.role.IRoleDescriptorBuilder#buildExtensions()
     */
    public void buildExtensions() throws OAException
    {
        Element eMetadata = _configuration.getSection(_eProfile, "metadata");
        if (eMetadata != null)
        {
            Element eExtensions = _configuration.getSection(eMetadata, "Extensions");
            if(eExtensions != null)
            {
                _logger.debug("Adding configured metadata Extensions");
                ExtensionsBuilder builder = new ExtensionsBuilder();
                Extensions extensions = builder.buildObject();
    
                NodeList nl = eExtensions.getChildNodes();
                for (int i = 0; i < nl.getLength(); i++)
                {
                    Node el = nl.item(i).cloneNode(true);
                    if (el.getNodeType() == Node.ELEMENT_NODE)
                    {
                        Element cel = (Element)el;
        
                        XSAnyBuilder annyBuilder = new XSAnyBuilder();
                        XSAny any = annyBuilder.buildObject(new QName(""));
                        any.setDOM(cel);
                        extensions.getUnknownXMLObjects().add(any);
                    }
                }
                
                _result.setExtensions(extensions);
            }
        }
    }
}
