/*
 * Asimba Server
 * 
 * Copyright (C) 2013 Asimba
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
package org.asimba.idp.profile.catalog.saml2;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.idp.profile.catalog.AbstractCatalog;
import org.asimba.idp.profile.catalog.saml2.builder.CatalogEntitiesDescriptorBuilder;
import org.asimba.util.saml2.metadata.provider.MetadataProviderUtil;
import org.asimba.utility.xml.XMLUtils;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.util.XMLObjectHelper;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.util.saml2.SAML2Exchange;
import com.alfaariss.oa.util.saml2.SAML2Requestor;
import com.alfaariss.oa.util.saml2.crypto.SAML2CryptoUtils;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;


/**
 * SAML2 Catalog
 * 
 * Configuration example:
 * <catalog id="catalog.saml2" class="...SAML2Catalog">
 *   <mp_manager id="[id-value]" />
 *   <requestorsigning default="[true/false]" />
 *   ..
 * </catalog>
 * 
 * @author mdobrinic
 *
 */
public class SAML2Catalog extends AbstractCatalog {
	/** Configuration element names */
	public static final String EL_REQUESTORSIGNING = "requestorsigning";
	public static final String ATTR_DEFAULT = "default";
	public static final String EL_SAML2REFERENCES = "saml2_refs";
	public static final String EL_IDP_PROFILE = "idp_profile";
	public static final String EL_SP_METHOD = "sp_method";
	public static final String ATTR_ID = "id";
	public static final String EL_METADATA = "metadata";
	
	/** Local logger instance */
	private Log _oLogger;

	
	/**
	 * Configurable setting to indicate default signing property 
	 * of a SAML2Requestor
	 * Default value: false 
	 */
	protected boolean _bDefaultRequestorSigning;
	
	
	/**
	 * Configurable SAML2 IDP Profile ID, to specify profile-scoped
	 * IDP configuration
	 * No default value, must be configured
	 */
	protected String _sLinkedSAML2IDPProfileID;
	
	/**
	 * Configurable SAML2 Authentication Method ID to specify
	 * authmethod-scoped SP configuration
	 * No default value, must be configured
	 */
	protected String _sLinkedSAML2SPAuthenticationMethodID;
	
	
	/**
	 * Configurable setting whether to enable LogoutService in
	 * proxied catalog
	 * Default value is false
	 */
	protected boolean _bEnableProxiedLogoutService = false;
	
	/**
	 * Configurable setting whether to enable ArtifactResolutionService in
	 * proxied catalog
	 * Default value is false
	 */
	protected boolean _bEnableProxiedArtifactResolutionService = false;
	
	/**
	 * Configurable id of a MetadataProviderManager that is responsible for 
	 * managing the MetadataProviders for entities used by the SAML2Catalog
	 * 
	 * This is used as a reference only for SAML2 Requestor instantiation!
	 */
	protected String _sMPMId;
	
	
	/** Locally maintained pool */
	protected BasicParserPool _oParserPool;
	
	
	/**
	 * Default constructor
	 */
	public SAML2Catalog() {
		super();
		_oLogger = LogFactory.getLog(SAML2Catalog.class);
		
		_oParserPool = new BasicParserPool();
		_oParserPool.setNamespaceAware(true);
		synchronized (this) {
			if (Configuration.getParserPool() == null) {	// don't know why.. but cloning fails to work otherwise.
				Configuration.setParserPool(_oParserPool);
			}
		}
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public void start(IConfigurationManager oConfigManager,
			Element eConfig) throws OAException 
	{
		super.start(oConfigManager, eConfig);
		
		Element elSAML2Profile = oConfigManager.getSection(eConfig, EL_SAML2REFERENCES);
		if (elSAML2Profile == null) {
			_oLogger.error("Missing element '"+EL_SAML2REFERENCES+"' in SAML2Catalog configuration.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		readLinkedProfiles(oConfigManager, elSAML2Profile);
		
		_bDefaultRequestorSigning = false;
		Element elRequestorSigning = oConfigManager.getSection(eConfig, EL_REQUESTORSIGNING);
		if (elRequestorSigning != null) {
			String s = oConfigManager.getParam(elRequestorSigning, ATTR_DEFAULT);
			if (s!=null) {
				if ("TRUE".equalsIgnoreCase(s)) {
					_bDefaultRequestorSigning = true;
				} else {
					if (!"FALSE".equalsIgnoreCase(s)) {
						_oLogger.warn("Invalid value provided for '"+ATTR_DEFAULT+"' attribute for '"+
								EL_REQUESTORSIGNING+"': "+s);
					}
					
					throw new OAException(SystemErrors.ERROR_CONFIG_READ);
				}
			}
		}
		
		
		// Establish MetadataProviderManager Id that refers to existing IMetadataProviderManager
		_sMPMId = null;
        Element elMPManager = oConfigManager.getSection(eConfig, MetadataProviderUtil.EL_MPM);
        if (elMPManager == null) {
        	_oLogger.info("No '"+MetadataProviderUtil.EL_MPM+"'@'id' configured for catalog '"+_sID+"'; "+
        				"ensure that no SAML2Requestors are used in the catalog");
        } else {
        	_sMPMId = oConfigManager.getParam(elMPManager, ATTR_ID);
        	if (_sMPMId == null) {
        		_oLogger.error("Missing @'"+ATTR_ID+"' attribute for '"+MetadataProviderUtil.EL_MPM+"' configuration");
        		throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        	}
        	_oLogger.info("Using MetadataProviderManager Id from configuration: '"+_sMPMId+"'");
        }

		_oLogger.info("Started SAML2Catalog profile '"+getID()+"'");
	}
	
	/**
	 * {@inheritDoc}
	 */
	public void stop() {
		super.stop();
	}

	
	
	/**
	 * Local helper to initialize the linked profiles
	 * @param oConfigManager ConfigManager to use
	 * @param eConfig Element containing the SP and IDP settings
	 * @throws OAException When something goes really wrong
	 */
	protected void readLinkedProfiles(IConfigurationManager oConfigManager,
			Element eConfig) throws OAException
	{
		_sLinkedSAML2IDPProfileID = null;
		
		Element eIDP = oConfigManager.getSection(eConfig, EL_IDP_PROFILE);
		if (eIDP == null) {
			_oLogger.error("No '"+EL_IDP_PROFILE+"' configured.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		} else {
			_sLinkedSAML2IDPProfileID = oConfigManager.getParam(eIDP, ATTR_ID);
			if (_sLinkedSAML2IDPProfileID == null) {
				_oLogger.error("No '"+ATTR_ID+"' configured for '"+EL_IDP_PROFILE+"'.");
				throw new OAException(SystemErrors.ERROR_CONFIG_READ);
			}
		}

		_sLinkedSAML2SPAuthenticationMethodID = null;
		
		Element eSP = oConfigManager.getSection(eConfig, EL_SP_METHOD);
		if (eSP == null) {
			_oLogger.warn("No '"+EL_SP_METHOD+"' configured.");
		} else {
			_sLinkedSAML2SPAuthenticationMethodID = oConfigManager.getParam(eSP, ATTR_ID);
			if (_sLinkedSAML2SPAuthenticationMethodID == null) {
				_oLogger.error("No '"+ATTR_ID+"' configured for '"+EL_SP_METHOD+"'.");
				throw new OAException(SystemErrors.ERROR_CONFIG_READ);
			}
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	public void service(HttpServletRequest oRequest,
			HttpServletResponse oResponse) throws OAException 
	{
		// Prepare requestors first:
		List<IRequestor> lRequestors = getRequestors(oRequest);		// low-cost
		
		// Prepare identity providers next:
		List<IIDP> lIDPs = getIDPs(oRequest);
		
		// Build catalog in EntitiesDescriptor
		CatalogEntitiesDescriptorBuilder oCatalogRoot = 
				new CatalogEntitiesDescriptorBuilder(_oConfigManager, Engine.getInstance().getServer());

		// Establish our local EntityDescriptor that is the endpoint
		// on behalf of the proxied system
		EntityDescriptor oTheAsimbaEntityDescriptor = SAML2Exchange.getEntityDescriptor(_sLinkedSAML2IDPProfileID);
		
		// Add SP's
		for (IRequestor r: lRequestors) {
			SAML2Requestor s2req = getSAML2Requestor(r);
			
			// In transparant mode, we just echo the endpoints of the SP
			if (_sPublishMode.equals(PUBLISHMODE_TRANSPARANT)) {
				if (s2req == null) {
					_oLogger.info("Skipping SP '"+r.getID()+"' in SAML2 Catalog because it is not a SAML2 SP");
					continue;
				}
				
				EntityDescriptor oED = getTransparantSPEntityDescriptor(s2req);
				if (oED != null) {
					oCatalogRoot.addEntityDescriptor(oED);
				}
				
				continue;
			}
			
			// In proxy-mode, we rewrite the endpoints to the linked SAML SP profile (authmethod)
			if (_sPublishMode.equals(PUBLISHMODE_PROXY)) {
				EntityDescriptor oED = getProxiedSPEntityDescriptor(r, oTheAsimbaEntityDescriptor);
				
				if (oED != null) {
					oCatalogRoot.addEntityDescriptor(oED);
				}
				
				continue;
			}
		}
		
		
		// Add IDP's
		for (IIDP idp: lIDPs) {
			SAML2IDP oSAML2IDP = getSAML2IDP(idp);
			
			if (_sPublishMode.equals(PUBLISHMODE_TRANSPARANT)) {
				if (oSAML2IDP == null) {
					_oLogger.warn("Skipping IDP '"+idp.getID()+"' in SAML2 Catalog because it is not a SAML2 IDP");
					continue;
				}
				
				EntityDescriptor oED = getTransparantIDPEntityDescriptor(oSAML2IDP);
				if (oED != null) {
					oCatalogRoot.addEntityDescriptor(oED);
				}
				
				continue;
			}

			// In proxy-mode, we rewrite the endpoints to the linked SAML SP profile (authmethod)
			if (_sPublishMode.equals(PUBLISHMODE_PROXY)) {
				EntityDescriptor oED = getProxiedIDPEntityDescriptor(idp, oTheAsimbaEntityDescriptor);
				
				if (oED != null) {
					oCatalogRoot.addEntityDescriptor(oED);
				}
				
				continue;
			}			
		}
		
		EntitiesDescriptor o = oCatalogRoot.getEntitiesDescriptor();
		
		// Now marshall this to XML
		try {
			MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
			Marshaller marshaller = marshallerFactory.getMarshaller(o);
			Element e = marshaller.marshall(o);
			
			PrintWriter oPW = oResponse.getWriter();
			String s = XMLUtils.getStringFromDocument(e.getOwnerDocument()); 
			oPW.write(s);
			oPW.close();
			
			return;
			
		} catch (MarshallingException e) {
			_oLogger.error("Could not marshall EntitiesDescriptor catalog to DOM: "+e.getMessage());
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		} catch (IOException e) {
			_oLogger.error("Could not write output: "+e.getMessage());
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		}
	}
	
	
	protected EntityDescriptor getTransparantSPEntityDescriptor(SAML2Requestor oS2Req)
	{
		// In transparant mode, we just echo the endpoints of the SP
		// S2Requestor.metadataprovider is already managed
		MetadataProvider oMP = oS2Req.getMetadataProvider();
		
		if (oMP != null) {
			EntityDescriptor oED;
			try {
				oED = oMP.getEntityDescriptor(oS2Req.getID());
				if (_oLogger.isTraceEnabled()) _oLogger.trace("Adding SP '"+oS2Req.getID()+"' to catalog.");
				return oED;
				
			} catch (MetadataProviderException e) {
				_oLogger.warn("Could not retrieve metadata for '"+oS2Req.getID()+"'; omitting from catalog.");
			}
		} else {
			_oLogger.warn("Exclude requestor '"+oS2Req.getID()+"' from proxy-catalog, not a SAML2 SP");
		}
		
		return null;
	}

	
	protected EntityDescriptor getTransparantIDPEntityDescriptor(SAML2IDP oS2IDP)
	{
		MetadataProvider oMP = null;
		try {
			oMP = oS2IDP.getMetadataProvider();

			/* why managed????
			// Get MetadataProvider through Manager when possible
			if (_oMetadataProviderManager!=null) {
				oMP = _oMetadataProviderManager.getProviderFor(oS2IDP.getID(), null);
				
				if (oMP == null) {
					oMP = oS2IDP.getMetadataProvider();
					_oMetadataProviderManager.setProviderFor(oS2IDP.getID(), oMP, null);
				}
			}
			*/
			
			if (oMP != null) {
				EntityDescriptor oED;
				oED = oMP.getEntityDescriptor(oS2IDP.getID());
				
				if (_oLogger.isTraceEnabled()) _oLogger.trace("Adding IDP '"+oS2IDP.getID()+"' to catalog.");
				
				return oED;
			}
		} catch (OAException e) {
			_oLogger.warn("Could not retrieve metadataprovider for IDP '"+oS2IDP.getID()+"': "+e.getMessage());
		} catch (MetadataProviderException e) {
			_oLogger.warn("Could not retrieve metadata for IDP '"+oS2IDP.getID()+"': "+e.getMessage());
		}
		
		
		_oLogger.warn("Exclude IDP '"+oS2IDP.getID()+"' from proxy-catalog, metadata is not available.");
		return null;
	}
	
	/**
	 * Create a proxied SP EntityDescriptor<br/>
	 * This EntityDescriptor contains the EntityID of the supplied Requestor, but
	 * the ACS URLs are rewritten, so they are routed through this Asimba SAML2 SP
	 * 
	 * Whenever an (external) IDP wants to deliver an identity for a service, it can do
	 * so to this (external) SP ACS URL; this means that Asimba can act on behalf of
	 * other SP's. This can be relevant when translating protocols with being as invisible
	 * as possible.
	 * Are there other use cases? Probably. 
	 * 
	 * <b>note</b> This requires Shadow-SP mode to be enabled for the SAML2 AuthMethod 
	 * to make it actually work.
	 * 
	 * @param oRequestor
	 * @param oTheAsimbaEntityDescriptor 
	 * @return
	 * @throws OAException
	 */
	protected EntityDescriptor getProxiedSPEntityDescriptor(IRequestor oRequestor,
			EntityDescriptor oTheAsimbaEntityDescriptor)
		throws OAException
	{
		// Prepare to build
		XMLObjectBuilderFactory oBuilder = Configuration.getBuilderFactory();

		SPSSODescriptor oTheAsimbaSPSSODescriptor = 
				oTheAsimbaEntityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
		
		// 1. Get EntityDescriptorBuilder (opensaml class!)
		org.opensaml.saml2.metadata.impl.EntityDescriptorBuilder oBuilder_ED = 
				(org.opensaml.saml2.metadata.impl.EntityDescriptorBuilder)
					oBuilder.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
		
		EntityDescriptor oED_publish = oBuilder_ED.buildObject(); 
		
		// Set main properties:
		oED_publish.setEntityID(oRequestor.getID());
		
		// 2. Get RoleDescriptorBuilder for SPSSODescriptor:
		SPSSODescriptorBuilder oBuilder_SPSSO = 
        	(SPSSODescriptorBuilder) oBuilder.getBuilder(
        			SPSSODescriptor.DEFAULT_ELEMENT_NAME);
		
		SPSSODescriptor oSPSSO_publish = oBuilder_SPSSO.buildObject();
		oSPSSO_publish.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		
		// 2.1. Copy some SPSSO attributes:
		if (oTheAsimbaSPSSODescriptor.getWantAssertionsSigned()) {
			oSPSSO_publish.setWantAssertionsSigned(true);
		}
		
		// 2.2. Add our LOCAL bindings for receiving the response:
		try {
			List<AssertionConsumerService> lACS = oTheAsimbaSPSSODescriptor.getAssertionConsumerServices();
			for (AssertionConsumerService oACS: lACS) {
				AssertionConsumerService oACS_new = (AssertionConsumerService) XMLObjectHelper.cloneXMLObject(oACS, true);
				
				// 2.2.1. Consider: adding (shadowed?) SP-context to the endpoints to recognize on
				// behalf of which SP the ACS URL is being requested?
				oSPSSO_publish.getAssertionConsumerServices().add(oACS_new);
			}
		} catch (MarshallingException e) {
			_oLogger.warn("Could not add SP '"+oRequestor.getID()+"'; due to marshalling problem with ACS.");
			return null;
		} catch (UnmarshallingException e) {
			_oLogger.warn("Could not add SP '"+oRequestor.getID()+"'; due to unmarshalling problem with ACS.");
			return null;
		}
			
		// 2.3. Add our LOCAL signing key
		KeyDescriptor oKD = getSigningKeyDescriptor(
				oBuilder, Engine.getInstance().getCryptoManager(), oRequestor.getID());
		
		if (oKD != null) {
			oSPSSO_publish.getKeyDescriptors().add(oKD);
		}
		
		// 2.5. Add results
		oED_publish.getRoleDescriptors().add(oSPSSO_publish);
		
		// 2.6. Add to catalog
		return oED_publish;
	}
	
	
	/**
	 * Create a proxied IDP EntityDescriptor<br/>
	 * This EntityDescriptor contains the EntityID of the supplied IDP, but
	 * the endpoints are rewritten, so they are routed through this Asimba SAML2 IDP<br/>
	 * 
	 * Supports:<br/>
	 * <ul>
	 * <li>NameIDFormat from Asimba SAML2 IDP</li>
	 * <li>SingleSignOnService, SingleLogoutService, ArtifactResolutionService from SAML2 IDP</li>
	 * </ul>
	 * 
	 * The reference that is added to the SSO/SLO/AR endpoints, is encoded like:
	 * [endpoint]/i=[sha1-hash-of-entity-id||lowercase-hexstring-encoded]
	 * Example (for EntityID = '12345' (without the quotes)):
	 * https://www.asimba.org/profiles/saml2/sso/web/i=2672275fe0c456fb671e4f417fb2f9892c7573ba
	 * 
	 * <b>note</b> Requires ShadowIDP support to be enabled in the SAML2 IDP Profile!
	 * 
	 * @param oIDP
	 * @param oTheAsimbaEntityDescriptor
	 * @return
	 * @throws OAException
	 */
	protected EntityDescriptor getProxiedIDPEntityDescriptor(IIDP oIDP,
			EntityDescriptor oTheAsimbaEntityDescriptor)
		throws OAException
	{
		// Prepare to build
		XMLObjectBuilderFactory oBuilder = Configuration.getBuilderFactory();

		IDPSSODescriptor oTheAsimbaIDPSSODescriptor = 
				oTheAsimbaEntityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
		
		// 1. Get EntityDescriptorBuilder (opensaml class!)
		org.opensaml.saml2.metadata.impl.EntityDescriptorBuilder oBuilder_ED = 
				(org.opensaml.saml2.metadata.impl.EntityDescriptorBuilder)
					oBuilder.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);
		
		EntityDescriptor oED_publish = oBuilder_ED.buildObject(); 

		// Set main properties:
		oED_publish.setEntityID(oIDP.getID());

		// 2. Get RoleDescriptorBuilder for IDPSSODescriptor:
		org.opensaml.saml2.metadata.impl.IDPSSODescriptorBuilder oBuilder_IDPSSO = 
        	(org.opensaml.saml2.metadata.impl.IDPSSODescriptorBuilder) oBuilder.getBuilder(
        			IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

		IDPSSODescriptor oIDPSSO_publish = oBuilder_IDPSSO.buildObject();
		oIDPSSO_publish.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		
		// 3. Copy some local properties:
		if (oTheAsimbaIDPSSODescriptor.getWantAuthnRequestsSigned()) {
			oIDPSSO_publish.setWantAuthnRequestsSigned(true);
		}
		
		// 3.1. Copy NameIDFormat from Asimba's config:
		try {
			List<NameIDFormat> l = oTheAsimbaIDPSSODescriptor.getNameIDFormats();
			if (l != null) {
				for (NameIDFormat nf: l) {
					NameIDFormat oNF_new;
					// oNF_new = (NameIDFormat) cloneXMLObject_usingDOM(nf);
					// oNF_new = (NameIDFormat) cloneXMLObject(nf);
					oNF_new = (NameIDFormat) XMLObjectHelper.cloneXMLObject(nf, true);
					
					oIDPSSO_publish.getNameIDFormats().add(oNF_new);
				}
			}
		} catch (MarshallingException e) {
			_oLogger.warn("Could not add IDP '"+oIDP.getID()+"'; due to marshalling problem with NameIDFormat.");
			return null;
		} catch (UnmarshallingException e) {
			_oLogger.warn("Could not add IDP '"+oIDP.getID()+"'; due to unmarshalling problem with NameIDFormat.");
			return null;
		}
		
		String sShadowIDPAlias = DigestUtils.shaHex(oIDP.getID());
		
		// 3.2. Copy (and remap?) SingleSignOnService, SingleLogoutService, ArtifactResolutionService endpoints
		try {
			List<SingleSignOnService> lsso = oTheAsimbaIDPSSODescriptor.getSingleSignOnServices();
			if (lsso != null) {
				for (SingleSignOnService ssos: lsso) {
					SingleSignOnService oSSOS_new;
					// oSSOS_new = (SingleSignOnService) cloneXMLObject_usingDOM(ssos);
					oSSOS_new = (SingleSignOnService) XMLObjectHelper.cloneXMLObject(ssos, true);
					
					// Rewrite endpoint to include entityid-reference:
					String sEndpoint = ssos.getLocation();
					sEndpoint = sEndpoint + "/i="+sShadowIDPAlias;
					oSSOS_new.setLocation(sEndpoint);
					
					oIDPSSO_publish.getSingleSignOnServices().add(oSSOS_new);
				}
			}
			
			if (_bEnableProxiedLogoutService) {
				List<SingleLogoutService> lsl = oTheAsimbaIDPSSODescriptor.getSingleLogoutServices();
				if (lsl != null) {
					for (SingleLogoutService sls: lsl) {
						SingleLogoutService oSLS_new;
						// oSLS_new = (SingleLogoutService) cloneXMLObject_usingDOM(sls);
						oSLS_new = (SingleLogoutService) XMLObjectHelper.cloneXMLObject(sls, true);
	
						// Rewrite endpoint to include entityid-reference:
						String sEndpoint = sls.getLocation();
						sEndpoint = sEndpoint + "/i="+sShadowIDPAlias;
						oSLS_new.setLocation(sEndpoint);
	
						oIDPSSO_publish.getSingleLogoutServices().add(oSLS_new);
					}
				}
			}
			
			if (_bEnableProxiedArtifactResolutionService) {
				List<ArtifactResolutionService> lars = oTheAsimbaIDPSSODescriptor.getArtifactResolutionServices();
				if (lars != null) {
					for (ArtifactResolutionService ars: lars) {
						ArtifactResolutionService oARS_new;
						// oARS_new = (ArtifactResolutionService) cloneXMLObject_usingDOM(ars);
						oARS_new = (ArtifactResolutionService) XMLObjectHelper.cloneXMLObject(ars, true);
						
						// Rewrite endpoint to include entityid-reference:
						String sEndpoint = ars.getLocation();
						sEndpoint = sEndpoint + "/i="+sShadowIDPAlias;
						oARS_new.setLocation(sEndpoint);
	
						oIDPSSO_publish.getArtifactResolutionServices().add(oARS_new);
					}
				}
			}
			
		} catch (MarshallingException e) {
			_oLogger.warn("Could not add IDP '"+oIDP.getID()+"'; due to marshalling problem with Services.");
			return null;
		} catch (UnmarshallingException e) {
			_oLogger.warn("Could not add IDP '"+oIDP.getID()+"'; due to unmarshalling problem with Services.");
			return null;
		}
		
		// 3.3. Copy <extensions> when they exist 
		try {
			Extensions ext = oTheAsimbaIDPSSODescriptor.getExtensions();
			if (ext != null) {
				// Extensions oExt_new = (Extensions) cloneXMLObject_usingDOM(ext);
				Extensions oExt_new = (Extensions) XMLObjectHelper.cloneXMLObject(ext, true);
				oIDPSSO_publish.setExtensions(oExt_new);
			}
		} catch (MarshallingException e) {
			_oLogger.warn("Could not add IDP '"+oIDP.getID()+"'; due to marshalling problem with Extensions.");
			return null;
		} catch (UnmarshallingException e) {
			_oLogger.warn("Could not add IDP '"+oIDP.getID()+"'; due to unmarshalling problem with Extensions.");
			return null;
		}
		
		// 3.4. Add our LOCAL signing key
		KeyDescriptor oKD = getSigningKeyDescriptor(
				oBuilder, Engine.getInstance().getCryptoManager(), oIDP.getID());
		
		if (oKD != null) {
			oIDPSSO_publish.getKeyDescriptors().add(oKD);
		}
		
		// 3.5. Add results
		oED_publish.getRoleDescriptors().add(oIDPSSO_publish);
		
		// 3.6. Add to catalog
		return oED_publish;
	}

	
	
	/**
	 * Create a new KeyDescriptor instance based on Asimba Engine's crypto
	 * configuration settings
	 *  
	 * @param oBuilder Initialized OpenSAML XMLObjectBuilderFactory to use
	 * @param oCrypto Configured Asimba CryptoManager
	 * @param sEntityID EntityID used to publish specific signing credentials in KeyDescriptor (?)
	 * @return
	 * @throws OAException
	 */
    public KeyDescriptor getSigningKeyDescriptor(XMLObjectBuilderFactory oBuilder,
    		CryptoManager oCrypto, String sEntityID) throws OAException
    {
        try
        {
            //Build signing key descriptor
            KeyDescriptorBuilder oKeyDescriptorBuilder = 
                (KeyDescriptorBuilder) oBuilder.getBuilder(
                    KeyDescriptor.DEFAULT_ELEMENT_NAME);       
            KeyDescriptor oKeyDescriptor = oKeyDescriptorBuilder.buildObject();
    
            oKeyDescriptor.setUse(UsageType.SIGNING);
            
            //Build credential
            X509Credential signingCredential = 
                SAML2CryptoUtils.retrieveMySigningCredentials(
                    oCrypto, sEntityID);
            
            // Using default: Configuration.getGlobalSecurityConfiguration and XMLSignature
            SecurityConfiguration oSecConfig = Configuration.getGlobalSecurityConfiguration();
            NamedKeyInfoGeneratorManager oKIGMgr = oSecConfig.getKeyInfoGeneratorManager();
            KeyInfoGeneratorFactory oKIGFactory = oKIGMgr.getDefaultManager().getFactory(signingCredential);
               
            KeyInfoGenerator kiGenerator = oKIGFactory.newInstance();
            if (kiGenerator != null) 
            {
                KeyInfo keyInfo = kiGenerator.generate(signingCredential);
                oKeyDescriptor.setKeyInfo(keyInfo);  
            }
            
            return oKeyDescriptor;    
        }
        catch (SecurityException e)
        {
           _oLogger.error("Could not generate SigningKeyDescriptor", e);
           throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
	
	
	
	/**
	 * Instantiate a new SAML2Requestor from a IRequestor instance
	 * Uses IRequestor-properties for the extra information
	 * @param r
	 * @return
	 * @throws OAException
	 */
	private SAML2Requestor getSAML2Requestor(IRequestor r) 
		throws OAException
	{
		SAML2Requestor o = null;
		
		try {
			// The Linked Profile ID is used to lookup profile-specific 
			// requestor-properties by the SAML2Requestor initialization procedure
			o = new SAML2Requestor(r, _bDefaultRequestorSigning, _sLinkedSAML2IDPProfileID, _sMPMId);
			
		} catch (OAException e) {
			_oLogger.error("Could not create SAML2Requestor for requestor '"+r.getID()+"'");
		}
		
		return o;
	}
	
	
	/**
	 * Returns a SAML2IDP version of the IIDP or null if the IDP was no SAML2 IDP
	 * @param i the IIDP instance
	 * @return
	 * @throws OAException
	 */
	private SAML2IDP getSAML2IDP(IIDP i)
	{
		if (!(i instanceof SAML2IDP)) return null;
		
		SAML2IDP oSAML2IDP = (SAML2IDP) i;
		return oSAML2IDP;
	}
	
	
	
	private <T extends XMLObject> T cloneXMLObject_usingDOM(XMLObject oSource) 
			throws MarshallingException, UnmarshallingException
	{
        try {

			Element elSource = oSource.getDOM();
			
			// Element elSource = oMarshaller.marshall(oSource, oDocument);	// is this right: .getDOM() ??
			
			Element clonedElement = (Element) elSource.cloneNode(true);	// deep clone
			
			Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(clonedElement);
	        T clonedXMLObject = (T) unmarshaller.unmarshall(clonedElement);
	        
	        return clonedXMLObject;
		} catch (UnmarshallingException e) {
			_oLogger.warn("Could not unmarshall element '"+oSource.getElementQName()+"'");
			return null;
		}
        finally {}
	}
	
	/**
	 * Private helper to clone XMLObjects
	 * @param oSource
	 * @return
	 * @throws OAException
	 */
	private <T extends XMLObject> T cloneXMLObject(XMLObject oSource) 
		throws MarshallingException, UnmarshallingException
	{
		Marshaller oMarshaller = Configuration.getMarshallerFactory().getMarshaller(oSource);
        try {
            if (oMarshaller == null) {
                _oLogger.warn("Unknown element '"+oSource.getElementQName()+"'; no marshaller available");
                return null;
            }
            
            // go through process of creating a new Document as intermediate:
            DocumentBuilderFactory oDBFactory = DocumentBuilderFactory.newInstance();
			oDBFactory.setNamespaceAware(true);
            DocumentBuilder oDocBuilder = oDBFactory.newDocumentBuilder();
			DOMImplementation oDOMImpl = oDocBuilder.getDOMImplementation();
			Document oDocument = oDOMImpl.createDocument(null, null, null); 
            
			Element elSource = oSource.getDOM();
			
			// Element elSource = oMarshaller.marshall(oSource, oDocument);	// is this right: .getDOM() ??
			
			Element clonedElement = (Element) elSource.cloneNode(true);	// deep clone
			
			Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(clonedElement);
	        T clonedXMLObject = (T) unmarshaller.unmarshall(clonedElement);
	        
	        return clonedXMLObject;
			
//		} catch (MarshallingException e) {
//			_oLogger.warn("Could not marshall element '"+oSource.getElementQName()+"'");
//			return null;
		} catch (UnmarshallingException e) {
			_oLogger.warn("Could not unmarshall element '"+oSource.getElementQName()+"'");
			return null;
		} catch (ParserConfigurationException e) {
			_oLogger.warn("Exception when creating intermedia document for cloning: "+e.getMessage());
			return null;
		}
		
	}
	
}
