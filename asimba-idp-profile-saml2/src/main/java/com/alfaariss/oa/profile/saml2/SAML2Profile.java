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
package com.alfaariss.oa.profile.saml2;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Hashtable;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.utility.xml.XMLUtils;
import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IService;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.profile.IRequestorProfile;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.profile.saml2.listener.SAML2TGTListener;
import com.alfaariss.oa.util.saml2.SAML2Constants;
import com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow;
import com.alfaariss.oa.util.saml2.ISAML2Requestors;
import com.alfaariss.oa.util.saml2.SAML2RequestorsLDAP;
import com.alfaariss.oa.util.saml2.metadata.MetaDataDirector;
import com.alfaariss.oa.util.saml2.metadata.entitydescriptor.EntityDescriptorBuilder;
import com.alfaariss.oa.util.saml2.metadata.role.IRoleDescriptorBuilder;
import com.alfaariss.oa.util.saml2.metadata.role.sso.IDPSSODescriptorBuilder;
import com.alfaariss.oa.util.saml2.opensaml.CustomOpenSAMLBootstrap;
import com.alfaariss.oa.util.saml2.profile.ISAML2Profile;

/**
 * The SAML2 profile for OpenASelect.
 *
 * Processes all incoming calls according to the SAML v2.0 specification. 
 * 
 * @author MHO
 * @author EVB
 * @author Alfa & Ariss
 * @see <a href="http://docs.oasis-open.org/security/saml/v2.0/" 
 *  target="_new">OASIS Security Assertion Markup Language (SAML) V2.0</a>
 */
public class SAML2Profile implements IRequestorProfile, IService
{
    private static final String DEFAULT_SSO_PATH = "/sso";
    
    private Log _logger;

    private Map<String, ISAML2Profile> _processors;
    private ISAML2Requestors _requestors;
    private String _sID;
    
    /** The metadata EntityDescriptor */
    private EntityDescriptor _entityDescriptor;
    private SAML2TGTListener _oSAML2TGTListener;
    
    /**
     * Constructor.
     * @throws OAException if OpenSAML cannot be initialized
     */
    public SAML2Profile() throws OAException
    {
        _logger = LogFactory.getLog(SAML2Profile.class);
        _processors = new Hashtable<String, ISAML2Profile>();
        _sID = null;
        _entityDescriptor = null;
        
        try
        {
            CustomOpenSAMLBootstrap.bootstrap();
        }
        catch (ConfigurationException e)
        {
            _logger.error("Could not initialize OpenSAML", e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
    }
    
    /**
     * Returns the profile ID.
     * @return String the profile id
     */
    public String getID()
    {
        return _sID;
    }
    
    
    /**
     * Returns the configured ISAML2Requestors instance for this profile
     * @return
     */
    public ISAML2Requestors getSAML2Requestors() {
    	return _requestors;
    }
   
    /**
     * @see IRequestorProfile#init(javax.servlet.ServletContext, 
     *  IConfigurationManager, org.w3c.dom.Element)
     */
    public void init(ServletContext context,
        IConfigurationManager configurationManager, Element config)
        throws OAException
    {
        try
        {
            _sID = configurationManager.getParam(config, "id");
            if (_sID == null)
            {
                _logger.error("No 'id' item found in 'profile' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            String sBaseUrl = configurationManager.getParam(config, "baseURL");
            if (sBaseUrl == null)
            {
                _logger.error("No 'baseURL' item found in 'profile' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            try
            {
                new URL(sBaseUrl);
            }
            catch (MalformedURLException e)
            {
                _logger.error("Invalid 'baseURL' item found in 'profile' section in configuration (should be an URL): " 
                    + sBaseUrl, e);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            _logger.info("Using configured Base URL: " + sBaseUrl);
            
            //read websso config
            String sWebSSOPath = DEFAULT_SSO_PATH;
            
            Element eWebSSO = configurationManager.getSection(config, "websso");
            if (eWebSSO == null)
            {
                _logger.warn("No optional 'websso' section found in 'profile' section with id='" + _sID + "' in configuration, using defaults");
            }
            else
            {
                sWebSSOPath = configurationManager.getParam(eWebSSO, "path");
                if (sWebSSOPath == null)
                {
                    _logger.warn("No optional 'path' parameter found in 'websso' section in configuration, using default");
                }
            }
            _logger.info("Using configured WebSSO path: " + sWebSSOPath);
            
            SAML2IssueInstantWindow issueInstantWindow = null;
            Element eIssueInstant = configurationManager.getSection(config, "IssueInstant");
            if (eIssueInstant == null)
                issueInstantWindow = new SAML2IssueInstantWindow();
            else
                issueInstantWindow = new SAML2IssueInstantWindow(
                    configurationManager, eIssueInstant);

            
            //read requestors config
            Element eRequestors = configurationManager.getSection(config, "requestors");
            if (eRequestors == null) {
                _logger.info("No optional 'requestors' section found in 'profile' section in configuration with profile id: "+ _sID);
            }
            // SAML2Requestors constructor can handle null for empty requestors section:
            // Use SAML2RequestorsLDAP for load both XML and LDAP requestors.
            _requestors = new SAML2RequestorsLDAP(configurationManager, eRequestors, _sID);
            
            //read profiles config
            Element eProfiles = configurationManager.getSection(config, "profiles");
            if (eProfiles == null)
            {
                _logger.error("No 'profiles' section found in 'profile' section in configuration with profile id: " 
                    + _sID);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eProfile = configurationManager.getSection(eProfiles, "profile");
            if (eProfile == null)
            {
                _logger.error("No SAML 'profile' section found in 'profiles' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _entityDescriptor = constructMetaData(configurationManager, config);
            while (eProfile != null)
            {
                ISAML2Profile samlProfile = 
                    createProfile(configurationManager, eProfile);
                
                samlProfile.init(configurationManager, eProfile, 
                    _entityDescriptor, sBaseUrl, sWebSSOPath, _requestors, 
                    issueInstantWindow, _sID);
                
                _processors.put(samlProfile.getID(), samlProfile);
                
                eProfile = configurationManager.getNextSection(eProfile);
            }
            
            Element eLogout = configurationManager.getSection(config, "logout");
            _oSAML2TGTListener = new SAML2TGTListener(configurationManager, 
                eLogout, _sID, _requestors, _entityDescriptor);
            if (_oSAML2TGTListener.isEnabled())
            {
                Engine.getInstance().getTGTFactory().addListener(_oSAML2TGTListener);
                _logger.info("Outgoing synchronous logout: enabled");
            }
            else
            {
                _logger.info("Outgoing synchronous logout: disabled");
                _oSAML2TGTListener = null;
            }
            
            
            signMetaData(); 
        }
        catch (OAException e)
        {
            destroy();
            throw e;
        }
        catch (Exception e)
        {
            destroy();
            _logger.fatal("Internal error during initialize", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Process a SAML2 message or query.
     * @see IService#service(javax.servlet.http.HttpServletRequest, 
     *  javax.servlet.http.HttpServletResponse)
     */
    public void service(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) throws OAException
    {
        try
        {            
            ISAML2Profile samlProfile = resolveSAMLProfile(servletRequest);
            if (samlProfile != null)
            {
                //Process SAML using a profile
                samlProfile.process(servletRequest, servletResponse);
            }                   
            else
            {
                String sRequestURI = servletRequest.getRequestURI();
                
                //remove a trailing '/' from the URL if it is available
                if (sRequestURI.endsWith("/"))
                    sRequestURI = sRequestURI.substring(0, sRequestURI.length() -1);
                
                String sContextPath = servletRequest.getContextPath();
                String sServletPath = servletRequest.getServletPath();
                
                int iBaseURILength = sContextPath.length() + sServletPath.length() 
                    + "/".length() + _sID.length(); 
                
                if (sRequestURI.length() == iBaseURILength)
                { //DD The metadata can be requested by accessing the root of the SAML2 profile
                    _logger.debug("Supplying Metadata");
                    handleMetaData(servletResponse);
                }
                else
                {
                    String sRequestURL = servletRequest.getRequestURL().toString();
                    _logger.debug("No SAML Profile found for request and no metadata requested: " 
                        + sRequestURL);
                    try
                    {
                        if (!servletResponse.isCommitted())
                            servletResponse.sendError(HttpServletResponse.SC_NOT_FOUND
                                , sRequestURI);
                    }
                    catch (IOException e1)
                    {
                      _logger.warn("Could not send response", e1);
                    }
                }
            }
        }
        catch (OAException e) //Internal error
        {
            throw e;
        }
        catch (Exception e) //Unknown internal error
        {
            _logger.fatal("Internal error during service", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * @see IRequestorProfile#destroy()
     */
    public void destroy()
    {
        if (_oSAML2TGTListener != null)
        {
            try
            {
                Engine.getInstance().getTGTFactory().removeListener(_oSAML2TGTListener);
            }
            catch (OAException e)
            {
                _logger.error("Could not remove the logout handler as TGT listener", e);
            }
        }
        
        if (_processors != null)
        {
            for (ISAML2Profile samlProfile : _processors.values())
                samlProfile.destroy();
            
            _processors.clear();
        }
        
        if (_requestors != null)
            _requestors.destroy();
        
    }
    
    private ISAML2Profile createProfile(IConfigurationManager 
        configurationManager, Element config) throws OAException
    {
        ISAML2Profile samlProfile = null;
        try
        {
            String sClass = configurationManager.getParam(config, "class");
            if (sClass == null)
            {
                _logger.error("No 'class' item found in 'profile' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Class oClass = null;
            try
            {
                oClass = Class.forName(sClass);
            }
            catch (Exception e)
            {
                _logger.error("No 'class' found with name: " + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            try
            {
                samlProfile = (ISAML2Profile)oClass.newInstance();
            }
            catch (Exception e)
            {
                _logger.error("Could not create an 'ISAML2Profile' instance of the configured 'class' found with name: " 
                    + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during creation of SAML profile object", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return samlProfile;
    }
    
    //Resolve the saml profile based on request
    private ISAML2Profile resolveSAMLProfile(HttpServletRequest servletRequest) 
    {
        ISAML2Profile samlProfile = null;
        
        String sRequestURI = servletRequest.getRequestURI();
        
        //remove a trailing '/' from the URL if it is available
        if (sRequestURI.endsWith("/"))
            sRequestURI = sRequestURI.substring(0, sRequestURI.length() -1);
        
        String sContextPath = servletRequest.getContextPath();
        String sServletPath = servletRequest.getServletPath();
        
        int iBaseURILength = sContextPath.length() + sServletPath.length() 
            + "/".length() + _sID.length() + "/".length(); 
        
        if (sRequestURI.length() <= iBaseURILength)
        {//URL is smaller than or equal to the saml2 profile root URL, so no specific SAML profile is requested.
            return null;
        }
        
        String sSubURI = sRequestURI.substring(iBaseURILength);
        if(sSubURI.length() > 1)
        {        
            for (String samlProfileID: _processors.keySet())
            {
                if (sSubURI.startsWith(samlProfileID))
                {
                    samlProfile = _processors.get(samlProfileID);
                    break;
                }
            }
        }        
        return samlProfile;
    }
    
    //Construct the metadata using a director
    private EntityDescriptor constructMetaData(
        IConfigurationManager configuration, Element eSAML2Profile) throws OAException
    {
        EntityDescriptor descriptor = null;
        try
        {
            Element eMetaData = configuration.getSection(eSAML2Profile, "metadata");
            if(eMetaData == null)
            {
                _logger.error("No 'metadata' section found");
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            //Create builders
            EntityDescriptorBuilder builder = new EntityDescriptorBuilder(
                configuration, eMetaData, Engine.getInstance().getServer());
            
            IRoleDescriptorBuilder<IDPSSODescriptor> roleBuilder = 
                new IDPSSODescriptorBuilder(configuration, eSAML2Profile, null);
           
            CryptoManager crypto = Engine.getInstance().getCryptoManager();           
         
            //Create director
            MetaDataDirector director  = new MetaDataDirector(builder, 
                roleBuilder, crypto);
         
            //Build
            director.constructMetadata();
            descriptor = builder.getResult();
                        
            return descriptor;
        }
        catch (OAException e) 
        {
             throw e;
        }       
        catch(Exception e)
        {
            _logger.error("Could not construct metadata", e);
            throw new OAException(SystemErrors.ERROR_INIT);
        }
    }
    
    //Sign the metadata
    private void signMetaData() throws OAException
    {        
        try
        {           
            //Marshall 
            Marshaller marshaller = Configuration.getMarshallerFactory(
                ).getMarshaller(_entityDescriptor);
            if (marshaller == null) 
            {
                _logger.error("No marshaller registered for " + 
                    _entityDescriptor.getElementQName() + 
                    ", unable to marshall metadata");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            if(_entityDescriptor.getDOM() == null)
                marshaller.marshall(_entityDescriptor);
            
            //Optional signing
            Signature signature = _entityDescriptor.getSignature();
            if(signature != null)
            {
                Signer.signObject(signature);
            }
            else
            {
                _logger.info("Metadata signing is disabled");
            }
        }
        catch (OAException e) 
        {
             throw e;
        }
        catch (MarshallingException e)
        {
            _logger.warn(
                "Marshalling error while signing metadata request", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch(Exception e)
        {
            _logger.error("Could not sign metadata", e);
            throw new OAException(SystemErrors.ERROR_INIT);
        }
    }
    
    //Pretty print the metadata to the printwriter
    private void handleMetaData(
        HttpServletResponse servletResponse) throws OAException
    {
        PrintWriter oPWOut = null;
        try 
        { 
        	// Marshall the metadata:
			MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
			Marshaller marshaller = marshallerFactory.getMarshaller(_entityDescriptor);
			Element e = marshaller.marshall(_entityDescriptor);
			
            servletResponse.setContentType(SAML2Constants.METADATA_CONTENT_TYPE);
            servletResponse.setHeader("Content-Disposition", 
                "attachment; filename=metadata.xml");

            //TODO EVB, MHO: cache processing conform RFC2616 [saml-metadata r1404]
            oPWOut = servletResponse.getWriter();
			String s = XMLUtils.getStringFromDocument(e.getOwnerDocument()); 

			oPWOut.write(s);
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
                "Internal error while processing metadata request", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        } 
        finally
        {
            if(oPWOut != null)
                oPWOut.close();
        }       
    }
}
