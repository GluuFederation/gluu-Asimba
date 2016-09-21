/*
 * Asimba - Serious Open Source SSO
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2011 Alfa & Ariss B.V.
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
package com.alfaariss.oa.authentication.remote.saml2.profile;

import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.authentication.remote.provisioning.saml2.AssertionUserStorage;
import org.asimba.util.saml2.assertion.SAML2TimestampWindow;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.GetComplete;
import org.opensaml.saml2.core.IDPEntry;
import org.opensaml.saml2.core.IDPList;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.ProxyRestriction;
import org.opensaml.saml2.core.RequesterID;
import org.opensaml.saml2.core.Scoping;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.GetCompleteBuilder;
import org.opensaml.saml2.core.impl.IDPEntryBuilder;
import org.opensaml.saml2.core.impl.IDPListBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequesterIDBuilder;
import org.opensaml.saml2.core.impl.ScopingBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.idmapper.IIDMapper;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.authentication.remote.saml2.SAML2AuthNConstants;
import com.alfaariss.oa.authentication.remote.saml2.beans.SAMLRemoteUser;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.attribute.UserAttributes;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.idp.storage.IIDPStorage;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
import com.alfaariss.oa.engine.user.provisioning.ProvisioningUser;
import com.alfaariss.oa.engine.user.provisioning.translator.standard.StandardProfile;
import com.alfaariss.oa.util.saml2.SAML2ConditionsWindow;
import com.alfaariss.oa.util.saml2.crypto.SAML2CryptoUtils;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;
import com.alfaariss.oa.util.saml2.proxy.ProxyAttributes;
import com.alfaariss.oa.util.saml2.proxy.SAML2IDPEntry;

/**
 * Basics for SAML2 Profile implementations.
 *
 * @author jre
 * @author Alfa & Ariss
 */
public abstract class AbstractAuthNMethodSAML2Profile implements IAuthNMethodSAML2Profile
{
    /** System logger */
    private Log _logger = LogFactory.getLog(AbstractAuthNMethodSAML2Profile.class);
    
    /**
     * Authentication method ID
     */
    protected String _sMethodID;
    
    /** Linked SAML2 IDP Profile that receives the profile's Response messages */
    protected String _sLinkedIDPProfile;

    /**
     * The Configuration manager instance
     */
    protected IConfigurationManager _oConfigManager = null;
    
    /**
     * The cryptoManager
     */
    protected CryptoManager _crypto = null;
    
    /**
     * Metadata store.
     */
    protected EntityDescriptor _entityDescriptor = null;
    
    /**
     * SAML XML object builder factory.
     */
    protected XMLObjectBuilderFactory _builderFactory = Configuration.getBuilderFactory();
    
    /** Signing is enabled in OA */
    protected boolean _signingEnabled;
    
    /**
     * UID mapper
     */
    protected IIDMapper _idMapper = null;
    
    /**
     * The organization storage
     */
    protected IIDPStorage _organizationStorage;
    
    /** SAML2 Conditions acceptance Window */
    protected SAML2ConditionsWindow _conditionsWindow;
    
    /**
     * Acceptance window for AuthnStatement/AuthnInstant values
     */
    protected SAML2TimestampWindow _oAuthnInstantWindow;
    
    /** Organization ID of this OpenASelect Server */
    protected String _sMyOrganizationID;
    
    /** IRequestorPoolFactory */
    protected IRequestorPoolFactory _requestorPoolFactory;
    
    /** Is OA Server 1.5 compaible */ 
    protected boolean _bCompatible;
    
    /** StandardProfile how a Remote User is provisioned */
    protected StandardProfile _oRemoteSAMLUserProvisioningProfile;
    
    /**
     * @see com.alfaariss.oa.authentication.remote.saml2.profile.IAuthNMethodSAML2Profile#init(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element, org.opensaml.saml2.metadata.EntityDescriptor, com.alfaariss.oa.api.idmapper.IIDMapper, com.alfaariss.oa.engine.core.idp.storage.IIDPStorage, java.lang.String, com.alfaariss.oa.util.saml2.SAML2ConditionsWindow)
     * @see 
     */
    public void init(IConfigurationManager configurationManager, Element config,
        EntityDescriptor entityDescriptor, IIDMapper mapper, 
        IIDPStorage orgStorage, String sMethodID, String sLinkedIDPProfile,
        SAML2ConditionsWindow conditionsWindow, SAML2TimestampWindow oAuthnInstantWindow,
        StandardProfile oRemoteSAMLUserProvisioningProfile) throws OAException
    {
        _oConfigManager = configurationManager;
        
        Engine oaEngine = Engine.getInstance();
        _crypto = oaEngine.getCryptoManager();
        _entityDescriptor = entityDescriptor;
        _idMapper = mapper;
        _organizationStorage = orgStorage;
        _sMethodID = sMethodID;
        _sLinkedIDPProfile = sLinkedIDPProfile;
        _conditionsWindow = conditionsWindow;
        _oAuthnInstantWindow = oAuthnInstantWindow;
        _sMyOrganizationID = oaEngine.getServer().getOrganization().getID();
        _requestorPoolFactory = oaEngine.getRequestorPoolFactory();
        _oRemoteSAMLUserProvisioningProfile = oRemoteSAMLUserProvisioningProfile;
        
        try
        {
            _signingEnabled = false;
            SAML2CryptoUtils.retrieveMySigningCredentials(_crypto, _entityDescriptor.getEntityID());
            SAML2CryptoUtils.getXMLSignatureURI(_crypto);
            SAML2CryptoUtils.getXMLDigestMethodURI(_crypto.getMessageDigest());
            _signingEnabled = true;
            _logger.info("Signing enabled");
        }
        catch(OAException e)
        {          
           //Logged in SAML2CryptoUtils
            _logger.info("Signing disabled");
        }  
    }

    /**
     * @see com.alfaariss.oa.authentication.remote.saml2.profile.IAuthNMethodSAML2Profile#destroy()
     */
    public void destroy()
    {
        //does nothing
    }
    
    /**
     * Check authentication statements' subject confirmations.
     *
     * @param subjectConfirmations The authentication statements' subject confirmations.
     * @return true if confirmations are correct.
     */
    protected boolean checkConfirmations(List<SubjectConfirmation> subjectConfirmations)
    {
        if (subjectConfirmations != null)
        {
            for(SubjectConfirmation conf : subjectConfirmations)
            {
                SubjectConfirmationData subjectConfirmationData = 
                    conf.getSubjectConfirmationData();
                if (subjectConfirmationData != null)
                {
                    boolean dateOK = subjectConfirmationData.getNotBefore() == null || subjectConfirmationData.getNotBefore().isBeforeNow();
                    dateOK = dateOK && (subjectConfirmationData.getNotOnOrAfter() == null || subjectConfirmationData.getNotOnOrAfter().isAfterNow());
                    dateOK = dateOK && (subjectConfirmationData.getNotOnOrAfter() == null || !subjectConfirmationData.getNotOnOrAfter().isEqualNow());
                    if (!dateOK) return false;
                }
            }
        }
        return true;
    }
    
    /**
     * Build a user object from an Assertion
     *
     * TODO -FO: determine what to do with NameQualifier/SPNameQualifier?
     *
     * @param oAssertion The Assertion object (must contain a subject child!)
     * @param sMethodId The Method ID calling this method.
     * @param sIDPId The EntityId of the organization that is used as organizationId 
     * 	when no NameQualifier is specified.
     * @return The SAMLUser.
     */
    protected SAMLRemoteUser createUserFromAssertion(Assertion oAssertion, String sMethodId, String sIDPId)
    		throws OAException
    {
    	Subject subj = oAssertion.getSubject();
        NameID nid = subj.getNameID();
        
        if (nid == null) {
        	_logger.warn("No NameID in Subject when trying to establish User from Assertion");
        	return null;
        }
        
        if (nid != null)
        {
            String sUserID = getUID(nid);
            if (sUserID != null)
            {
                String sNameIDFormat = nid.getFormat();
                if (sNameIDFormat == null)
                {   //DD use unspecified if no format is available saml-core-2.0-os r455
                    sNameIDFormat = NameIDType.UNSPECIFIED;
                }
                
                String sNameQualifier = nid.getNameQualifier();
                String sSPNameQualifier = nid.getSPNameQualifier();
                
                String sUserOrganization = sNameQualifier;
                if (sUserOrganization == null)
                {
                	String sLocalEntityId = _entityDescriptor.getEntityID();
                	
                	// If provided SPNameQualifier is not the same as our SP EntityId:
                    if (sSPNameQualifier != null && !sLocalEntityId.equals(sSPNameQualifier)) 
                    {
                        //..then the UserOrg can be assumed to be scoped within provided SPNameQualif
                        sUserOrganization = sSPNameQualifier;
                    }
                    else
                    {
                        //..otherwise UserOrg is not explicitly provided; make it to be the RemoteIDP-ID
                        sUserOrganization = sIDPId;
                    }
                }
                
                List<SubjectConfirmation> subjectConfirmations = subj.getSubjectConfirmations();
                //DD: Multiple confirmations are not yet supported.
                
                if (!checkConfirmations(subjectConfirmations))
                {  
                    _logger.debug("Subject Confirmation data time stamp(s) incorrect");
                    return null;
                }
                
                // Do provisioning?
                if (_oRemoteSAMLUserProvisioningProfile == null) {
                	// Nope, just instantiate without provisioning properties and do not
                	// add more available AuthMethods
	                return new SAMLRemoteUser(sUserOrganization, sUserID, sMethodId, 
	                    sNameIDFormat, sNameQualifier, sSPNameQualifier, sIDPId);
                } else {
                	// Yes, do provisioning, use the assertion as External Storage
                	AssertionUserStorage oAUS = new AssertionUserStorage(oAssertion);
                	ProvisioningUser oProvisioningUser = 
                			_oRemoteSAMLUserProvisioningProfile.getUser(oAUS, sUserOrganization, sUserID);
                	
                	return new SAMLRemoteUser(oProvisioningUser, sMethodId,
                			sNameIDFormat, sNameQualifier, sSPNameQualifier, sIDPId);
                }
            }
        }
        
        return null;
    }
    
    /**
     * Checks validity of authentication statement
     *
     * @param stmt The AuthnStatement SAML object
     * @return true if correct
     */
    protected boolean checkAuthNStatement(AuthnStatement stmt)
    {
        //TODO check authN context?
        //does not have to do anything yet? AuthN context type check?
        if (! _oAuthnInstantWindow.canAccept(stmt.getAuthnInstant()))
        {
            _logger.debug("AuthN statement check failed: issue instant not in acceptable window.");
            return false;
        }

        return true;
    }
    
    /**
     * Check status.
     *
     * @param status The Status object.
     * @param org The organization.
     * @return true if status is "Success"
     */
    protected UserEvent getStatus(Status status, SAML2IDP org)
    {
        StatusCode statusCode = (status == null ? null : status.getStatusCode());
        String sStatus = (statusCode == null ? null : statusCode.getValue());
        
        if (StatusCode.SUCCESS_URI.equals(sStatus))
        {
            return UserEvent.AUTHN_METHOD_SUCCESSFUL;
        }
        
        StringBuffer sbDebug = new StringBuffer("Status code isn't '");
        sbDebug.append(StatusCode.SUCCESS_URI);
        sbDebug.append("' but is: ");
        sbDebug.append(sStatus);
        _logger.debug(sbDebug.toString());
        
        return UserEvent.AUTHN_METHOD_FAILED;
    }
    
    /**
     * Checks conditions and sets proxy restrictions if available.
     *
     * @param con The Conditions SAML object
     * @return true if conditions are met.
     */
    protected boolean doConditions(Conditions con)
    {
        if (!_conditionsWindow.canAccept(con.getNotBefore(), con.getNotOnOrAfter()))
            return false;
        
        //check audience restrictions
        boolean arOK = false;
        List<AudienceRestriction> ars = con.getAudienceRestrictions();
        if (ars == null || ars.size() == 0) 
            arOK = true;
        else
        {
            for(AudienceRestriction ar : ars)
            {
                List<Audience> as = ar.getAudiences();
                if (as != null)
                {
                    for (Audience a : as)
                    {
                        String sAURI = a.getAudienceURI();
                        if (!sAURI.endsWith("/")) sAURI = sAURI + "/";
                        if (sAURI.startsWith(_entityDescriptor.getEntityID()))
                        {
                            arOK = true;
                            break;
                        }
                    }
                }
                if (arOK) break;
            }
        }
        
        //OneTimeUse is ignored.
        
        
        //ProxyRestriction never invalidates a message (saml-core-2.0-os, r.994)
        //only sets new values in proxy session attributes
        //DD ProxyRestriction is not supported in the profile, so ignore it here as well (for now)

        
        if (!arOK)
        {
            _logger.debug("Message error: Audience restriction prohibited use of assertion");
        }
        
        return arOK;
    }
    
    /**
     * Sets proxy attributes according to ProxyAttributes element.
     * 
     * @param pr The ProxyRestriction element.
     */
    protected void setProxyRestrictions(ProxyRestriction pr)
    {
    }

    /**
     * Get attributes from attribute statement.
     * 
     * @param stmts List of attribute statement SAML objects.
     * @return The IAttributes object.
     */
    protected IAttributes getAttributeMap(List<AttributeStatement> stmts)
    {
        if (stmts == null || stmts.isEmpty()) return null;
        
        IAttributes returnAtts = new UserAttributes();
        
        for (AttributeStatement stmt : stmts)
        {
            List<Attribute> atts = stmt.getAttributes();
            for (Attribute att : atts)
            {                
                //DD We only support XSString (if OpenSAML does) and XSAny
                if (att.getAttributeValues() == null || att.getAttributeValues().isEmpty()) {
                     _logger.error("Empty attribute (skipped): " + att);
                     continue;
                }
                XMLObject obj = att.getAttributeValues().get(0);
                String content = null;
                if (obj instanceof XSString)
                {
                    //ok
                    XSString str = (XSString)obj;
                    content = str.getValue();
                }
                //OpenSAML reads type=xs:string attributes as any-typed?
                else if (obj instanceof XSAny)
                {
                    //ok
                    XSAny str = (XSAny)obj;
                    content = str.getTextContent();
                }
                else
                {
                    _logger.debug("Unrecognized type of attribute (skipped): " + obj.getClass().getName());
                }
                
                if (returnAtts.contains(att.getName()))
                {
                    _logger.debug("Duplicate name for attribute (skipped): " + att.getName());
                }
                else if (content == null) {
                	// Workaround to not crash on null-content (i.e. when AttributeValue is not text-content)
                	_logger.debug("No content for the value of "+att.getName()+" ("+content+"), ignoring.");
                } else {
                    _logger.debug("Adding attribute to map: " + att.getName());
                    
                    if (_bCompatible)
                    {
                        //DD Unspecified name format will be ignored
                		String sAttributeNameFormat = att.getNameFormat();
                		if (sAttributeNameFormat != null && sAttributeNameFormat.equals(Attribute.UNSPECIFIED))
                			sAttributeNameFormat = null;
            		
            		    returnAtts.put(att.getName(), sAttributeNameFormat, content);
                    }
            		else
            		{
            		    returnAtts.put(att.getName(), content);
            		}
                }
            }
        }
        
        return returnAtts;
    }
    
    /**
     * Maps attributes using the configured mapping (if exists).
     *
     * @param source The source attributes, probably from the SAML response.
     * @param target The mapped attributes, to be used by OA.
     * @param mapping The mapping hashtable.
     * @return The mapped attributes.
     */
    protected IAttributes mapAttributes(IAttributes source, IAttributes target,
        Hashtable<String, String> mapping)
    {
        Enumeration enumNames = source.getNames();
        while (enumNames.hasMoreElements())
        {
            String sName = (String)enumNames.nextElement();
            Object oValue = source.get(sName);
            String sMappedName = mapping.get(sName);
            if (sMappedName != null) 
                sName = sMappedName;
            
            if (_bCompatible)
            {
                //DD Unspecified name format will be ignored
                String sAttributeNameFormat = source.getFormat(sName);
                if (sAttributeNameFormat != null && sAttributeNameFormat.equals(Attribute.UNSPECIFIED))
                	sAttributeNameFormat = null;
                
                target.put(sName, sAttributeNameFormat, oValue);
            }
            else
            {// not using unsupported attribute format
                target.put(sName, oValue);
            }
        }
        return target;
    }
    
    /**
     * Sign the suplied saml object.
     * @param samlObject saml object to be signed
     * @throws OAException If the crypto configuration in OA is unsupported
     */
    protected void signSAMLObject(SignableSAMLObject samlObject) 
        throws OAException
    {
        try
        {  
            XMLObjectBuilderFactory builderFactory = 
                Configuration.getBuilderFactory();
            //Build signature
            SignatureBuilder builder = 
                (SignatureBuilder)builderFactory.getBuilder(
                    Signature.DEFAULT_ELEMENT_NAME);   
            Signature signature = builder.buildObject(
                Signature.DEFAULT_ELEMENT_NAME); 
            
            signature.setSignatureAlgorithm(
                SAML2CryptoUtils.getXMLSignatureURI(_crypto));
            
            //Get signing credentials
            X509Credential signingX509Cred = 
                SAML2CryptoUtils.retrieveMySigningCredentials(
                    _crypto, _entityDescriptor.getEntityID());                         
            signature.setSigningCredential(signingX509Cred);
            
            SecurityHelper.prepareSignatureParams(
                signature, signingX509Cred, null, null);
            
            samlObject.setSignature(signature);
            
            //update digest algorithm
            SAMLObjectContentReference contentReference = 
                ((SAMLObjectContentReference)signature.getContentReferences().get(0));
            contentReference.setDigestAlgorithm(
                SAML2CryptoUtils.getXMLDigestMethodURI(_crypto.getMessageDigest()));
            
            //Marshall 
            Marshaller marshaller = Configuration.getMarshallerFactory(
                ).getMarshaller(samlObject);
            if (marshaller == null) 
            {
                _logger.error("No marshaller registered for " + 
                    samlObject.getElementQName() + 
                    ", unable to marshall assertion");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            if(samlObject.getDOM() == null)
                marshaller.marshall(samlObject);
            
            Signer.signObject(signature);
        }
        catch (OAException e) 
        {
             throw e;
        }
        catch (MarshallingException e)
        {
            _logger.warn(
                "Marshalling error while signing object", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch(Exception e)
        {
            _logger.error("Could not sign object", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Creates a default empty SAML context object.
     *  
     * TODO -MG: merge with AbstractSAML2Profile.createEncodingContext
     *  
     * @param request Servlet request.
     * @param response Servlet response.
     * @return Default SAML context object.
     */
    protected SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> 
        createEncodingContext(HttpServletRequest request, 
            HttpServletResponse response)
    {
        HTTPInTransport inTransport = new HttpServletRequestAdapter(request);
                
        HTTPOutTransport outTransport = new HttpServletResponseAdapter(response, 
            request.isSecure());
        
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> 
            context = new BasicSAMLMessageContext<SignableSAMLObject, 
                SignableSAMLObject, SAMLObject>();  
        
        context.setInboundMessageTransport(inTransport);
        context.setOutboundMessageTransport(outTransport);
        
        return context;
    }
    
    /**
     * Build an endpoint.
     * 
     * TODO -MG: merge with AbstractSAML2Profile.buildMetadataEndpoint
     * 
     * @param elementName The type of service for the endpoint.
     * @param sBinding The binding to be used.
     * @param sLocation The endpoint location.
     * @param sResponseLocation The optional response location. 
     * @return The constructed endpoint.
     */
    protected Endpoint buildMetadataEndpoint(QName elementName, 
        String sBinding, String sLocation, 
        String sResponseLocation)
    {
        XMLObjectBuilderFactory builderFactory = 
            Configuration.getBuilderFactory();
        
        XMLObjectBuilder endpointBuilder = builderFactory.getBuilder(elementName);
            
        Endpoint samlEndpoint = (Endpoint)endpointBuilder.buildObject(elementName);
        samlEndpoint.setLocation(sLocation);
        samlEndpoint.setBinding(sBinding);
        
        if (sResponseLocation != null)
            samlEndpoint.setResponseLocation(sResponseLocation);  
        
        return samlEndpoint;
    }
    
    /**
     * Builds <code>Issuer</code> object.
     *
     * @return The <code>Issuer</code> object.
     */
    protected Issuer buildIssuer()
    {
        IssuerBuilder issuerBuilder = 
            (IssuerBuilder)Configuration.getBuilderFactory()
            .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(_entityDescriptor.getEntityID());
        
        return issuer;
    }
    
    /**
     * Builds <code>NameIDPolicy</code> object.
     * 
     * NameID format is determined using the following sources (in this order):
     * 
     * 1. Proxy attribute
     * 2. Requestor metadata
     * 3. Configured value
     * 
     * @param session The Authentication session (for proxy attribute).
     * @param descriptor The current idp sso descriptor from the organization metadata.
     * @param useAllowCreate The explicit value of AllowCreate that must be used unless a proxied value is available.
     * @param forcedNameIDFormat The explicit value of the NameIDFormat that must be used.
     *
     * @return The <code>NameIDPolicy</code> object.
     */
    protected NameIDPolicy buildNameIDPolicy(ISession session, 
        IDPSSODescriptor descriptor, Boolean useAllowCreate, 
        String forcedNameIDFormat)
    {
        NameIDPolicy nameIDPolicy = null;

        String nameIDFormat = null;
        if (forcedNameIDFormat != null)
        {
            nameIDFormat = forcedNameIDFormat;
        }
        else if (descriptor != null)
        {//try metadata
            List<NameIDFormat> metadataNIFs = descriptor.getNameIDFormats();
             
            if (metadataNIFs != null && !metadataNIFs.isEmpty())
            {//DD Always using the first NameIDFormat that is available in the metadata of the organization
                nameIDFormat = metadataNIFs.get(0).getFormat();
                
                _logger.debug("Using first NameIDFormat from IdP metadata: " + nameIDFormat);
            }
        }
        
        if (nameIDFormat != null)
        {
            NameIDPolicyBuilder nidpBuilder =
                (NameIDPolicyBuilder)Configuration.getBuilderFactory()
                .getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME);
            nameIDPolicy = nidpBuilder.buildObject();
            nameIDPolicy.setFormat(nameIDFormat);
            
            Boolean boolAllowCreate = (Boolean)session.getAttributes().get(ProxyAttributes.class, ProxyAttributes.ALLOW_CREATE);
            if (boolAllowCreate != null)
            {//allow create has been proxied
                nameIDPolicy.setAllowCreate(boolAllowCreate);
            }
            else if (useAllowCreate != null)
            {//the allow create is explicitly configured
                nameIDPolicy.setAllowCreate(useAllowCreate);
            }
        }
        
        return nameIDPolicy;
    }
    
    /**
     * Builds NameID.
     *
     * @param sNameID UserID
     * @param sFormat The format of the NameID or NULL if none.
     * @param sNameQualifier The NameQualifier of the NameID or NULL if none.
     * @return The NameID object.
     */
    protected NameID buildNameID(String sNameID, String sFormat, String sNameQualifier)
    {
        NameIDBuilder nameidBuilder = (NameIDBuilder)
        Configuration.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME);
    
        if (_idMapper != null)
        {
            try
            {
                String mappedUID = _idMapper.map(sNameID);
                if (mappedUID != null)
                {
                    sNameID = mappedUID;
                }
            }
            catch (OAException e)
            {
                _logger.debug("Could not map OA UID to ext. ID");
                return null;
            }
        }
        
        NameID nid = nameidBuilder.buildObject();
        
        nid.setValue(sNameID);
        
        //DD currently the SPProvidedID is not supported
        //nid.setSPProvidedID();
        
        if (sFormat != null)
            nid.setFormat(sFormat);
        
        if (sNameQualifier != null)
            nid.setNameQualifier(sNameQualifier);
        
        return nid;
    }
    
    /**
     * Builds a subject SAML object based on a User ID.
     *
     * @param sNameID The UID.
     * @param sNameIDFormat The nameid format or NULL if none.
     * @param sNameQualifier The NameQualifier of the NameID or NULL if none.
     * @param bAvoidSubjectConfirmation When true, do not include any SubjectConfirmation elements
     * 		in the Subject
     * @return The <code>Subject</code> object.
     */
    protected Subject buildSubject(String sNameID, String sNameIDFormat, String sNameQualifier,
    		boolean bAvoidSubjectConfirmation)
    {
        SubjectBuilder subjBuilder = (SubjectBuilder)
            Configuration.getBuilderFactory().getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        
        Subject subj = subjBuilder.buildObject();
        
        NameID nid = buildNameID(sNameID, sNameIDFormat, sNameQualifier);
        
        subj.setNameID(nid);
        
        if (!bAvoidSubjectConfirmation) {
	        SubjectConfirmationBuilder subjConfBuilder = (SubjectConfirmationBuilder)
	        Configuration.getBuilderFactory().getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
	        
	        SubjectConfirmation subjConf = subjConfBuilder.buildObject();
	        
	        SubjectConfirmationDataBuilder subjConfDataBuilder = (SubjectConfirmationDataBuilder)
	        Configuration.getBuilderFactory().getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
	        
	        SubjectConfirmationData scData = subjConfDataBuilder.buildObject();
	        
	        subjConf.setSubjectConfirmationData(scData);
	        
	        subjConf.setMethod(AuthnContext.UNSPECIFIED_AUTHN_CTX);
	        
	        subj.getSubjectConfirmations().add(subjConf);
        } else {
        	_logger.debug("Skipping '"+SubjectConfirmation.DEFAULT_ELEMENT_NAME.getLocalPart()+"' in "+
        			subj.DEFAULT_ELEMENT_NAME.getLocalPart());
        }
        
        return subj;
    }
    
    /**
     * Builds Scoping based on the proxy attributes.
     *
     * @param atts The session attributes to extract the proxy attributes from.
     * @param requestorID The ID of the requestor that initiated authentication.
     * @return The Scoping.
     */
    @SuppressWarnings("unchecked")
    protected Scoping buildScoping(ISessionAttributes atts, String requestorID)
    {
        ScopingBuilder scopBuilder = (ScopingBuilder)
            Configuration.getBuilderFactory().getBuilder(Scoping.DEFAULT_ELEMENT_NAME);
        
        Scoping scop = scopBuilder.buildObject();
        
        //Set ProxyCount
        Integer cnt = (Integer)atts.get(ProxyAttributes.class, ProxyAttributes.PROXYCOUNT);
        if (cnt != null)
        {
            scop.setProxyCount(cnt-1);
        }
        
        //Set IDPList
        List<SAML2IDPEntry> entries = (List<SAML2IDPEntry>)
            atts.get(ProxyAttributes.class, ProxyAttributes.IDPLIST);
        String sGetComplete = (String)
            atts.get(ProxyAttributes.class, ProxyAttributes.IDPLIST_GETCOMPLETE);
        if (entries != null || sGetComplete != null)
        {
            scop.setIDPList(buildIDPList(entries, sGetComplete));
        }
                
        RequesterIDBuilder ridBuilder = (RequesterIDBuilder)
        Configuration.getBuilderFactory().getBuilder(RequesterID.DEFAULT_ELEMENT_NAME);
        
        //Add RequesterIDs
        List<String> listRequesterIDs = (List<String>)atts.get(ProxyAttributes.class, ProxyAttributes.REQUESTORIDS);
        if (listRequesterIDs != null)
        {
            for (String requesterID : listRequesterIDs)
            {          
                RequesterID rid = ridBuilder.buildObject();
                rid.setRequesterID(requesterID);
                scop.getRequesterIDs().add(rid);
            }
        }
        
        //DD When in proxy mode the RequesterID must always be proxied
        RequesterID requestorRID = ridBuilder.buildObject();
        requestorRID.setRequesterID(requestorID);
        scop.getRequesterIDs().add(requestorRID);
        
        return scop;
    }
    
    /**
     * Build an IDP list based on the entries from the proxy attributes.
     *
     * @param entries The list of SAML2 provider entries.
     * @param sGetComplete The URL where a full list can be found.
     * @return The IDPList object.
     */
    protected IDPList buildIDPList(List<SAML2IDPEntry> entries, String sGetComplete)
    {
        IDPListBuilder idplBuilder = (IDPListBuilder)
            Configuration.getBuilderFactory().getBuilder(IDPList.DEFAULT_ELEMENT_NAME);
        
        IDPList idpl = idplBuilder.buildObject();
        
        if (entries != null)
        {
            for (SAML2IDPEntry entry : entries)
            {
                IDPEntry idpEntry = buildIDPEntry(entry);
                idpl.getIDPEntrys().add(idpEntry);
            }
        }
        
        if (sGetComplete != null)
        {
            GetCompleteBuilder gcBuilder = (GetCompleteBuilder)
                Configuration.getBuilderFactory().getBuilder(GetComplete.DEFAULT_ELEMENT_NAME);
            
            GetComplete gc = gcBuilder.buildObject();
            gc.setGetComplete(sGetComplete);
            idpl.setGetComplete(gc);
        }
        
        return idpl;
    }

    /**
     * TODO -MG: merge with AbstractSAML2Profile.logXML
     * 
     * Caller should perform debug enabled check
     * Logs the XML object as debug logging. 
     * @param xmlObject The XML object that must be logged.
     */
    protected void logXML(XMLObject xmlObject)
    {
        assert _logger.isDebugEnabled() : "Logger debug state not checked";
        Element eDOM = xmlObject.getDOM();
        if(eDOM == null)
        {
            Marshaller marshaller = 
                Configuration.getMarshallerFactory().getMarshaller(xmlObject);
            if (marshaller != null) 
            {
                try
                {
                    eDOM = marshaller.marshall(xmlObject);
                }
                catch (MarshallingException e)
                {
                    _logger.debug("Could not prettyPrint XML object", e);
                }
            }
        }
            
        if (eDOM != null)
        {
            String sXML = XMLHelper.prettyPrintXML(eDOM);
            _logger.debug(sXML);
        }
        
    }
    
    /**
     * Returns the IdP descriptor of the organization. 
     * 
     * @param organization The SAML2Organization
     * @return The IdP description object or <code>null</code> if no IdP descriptor can be found.
     */
    protected IDPSSODescriptor getIdPDescriptor(SAML2IDP organization)
    {
        IDPSSODescriptor idpSSODescriptor = null;
        try
        {
            MetadataProvider metadataProvider = 
                organization.getMetadataProvider();
                        
            if (metadataProvider != null)
            {
                idpSSODescriptor = 
                    (IDPSSODescriptor)metadataProvider.getRole(
                        organization.getID(), 
                        IDPSSODescriptor.DEFAULT_ELEMENT_NAME, 
                        SAMLConstants.SAML20P_NS);
            }
        }
        catch (Exception mpe)
        {
            _logger.debug("Could not retrieve metadata for requestor " + 
                organization.getID(), mpe);
        }
        
        if (idpSSODescriptor == null) 
            _logger.debug("Could not retrieve metadata (IDP Role) for IdP with ID: " + organization.getID());
        
        return idpSSODescriptor;
    }
    
    /**
     * Generate a requestor ID.
     * 
     * @param sSessionID The Session ID that will be used as postfix for the ID
     * @param sessionAttributes The session attributes where the generated 
     *  prefix in will be added. 
     * @return The Requestor ID prefix
     * @throws MessageEncodingException If secure random generator cannot be 
     *  created.
     * @since 1.2
     */
    protected String generateRequestID(String sSessionID, 
        ISessionAttributes sessionAttributes) throws MessageEncodingException
    {
        SecureRandomIdentifierGenerator idGenerator = null;
        try
        {
            idGenerator = new SecureRandomIdentifierGenerator();
        }
        catch (NoSuchAlgorithmException e)
        {
            String msg = "Could not generate ID for logout request";
            _logger.error(msg);
            throw new MessageEncodingException(msg, e);
        }
        
        String requestIDPrefix = idGenerator.generateIdentifier(
            SAML2AuthNConstants.REQUEST_ID_BYTE_SIZE);
        
        if (sessionAttributes != null) 
            sessionAttributes.put(SAML2AuthNConstants.class, 
                SAML2AuthNConstants.AUTHNREQUEST_ID_PREFIX, requestIDPrefix);

        return requestIDPrefix + sSessionID;
    }
    
    private IDPEntry buildIDPEntry(SAML2IDPEntry entry)
    {
        IDPEntryBuilder idpeBuilder = (IDPEntryBuilder)
            Configuration.getBuilderFactory().getBuilder(IDPEntry.DEFAULT_ELEMENT_NAME);
        
        IDPEntry idpe = idpeBuilder.buildObject();
        
        idpe.setLoc(entry.getLoc());
        idpe.setName(entry.getName());
        idpe.setProviderID(entry.getProviderID());
        
        return idpe;
    }

    private String getUID(NameID nid)
    {
        String sUID = null;
         
        if (nid == null)
        {
            _logger.debug("Message error: Subject NameID not found");
            return null;
        }
        
        //TODO -FO: determine what to do with NameQualifier and SPNameQualifier
//        else if(!nid.getNameQualifier().equals(issuer))
//        {
//            _logger.debug("Message error: Subject NameID NameQualifier (" 
//                + nid.getNameQualifier() 
//                + ") does not match issuer ("
//                + issuer + ").");
//            return null;
//        }
        
        sUID = nid.getValue();
        
        if (sUID == null)
        {
            //try SPProvided
            sUID = nid.getSPProvidedID();
        }
        
        if (_idMapper != null)
        {
            try
            {
                String remappedUID = _idMapper.remap(sUID);
                if (remappedUID != null)
                {
                    sUID = remappedUID;
                }
            }
            catch (OAException e)
            {
                _logger.debug("Could not remap ext. ID to OA UID");
                return null;
            }
        }

        return sUID;
    }
}
