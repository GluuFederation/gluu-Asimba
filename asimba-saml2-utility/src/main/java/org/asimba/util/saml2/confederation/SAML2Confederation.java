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
package org.asimba.util.saml2.confederation;

import java.util.List;
import java.util.Map;
import java.util.Timer;

import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.util.URIUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.engine.core.confederation.IConfederation;
import org.asimba.util.saml2.metadata.provider.IMetadataProviderManager;
import org.asimba.util.saml2.metadata.provider.MetadataProviderUtil;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;

/**
 * Implementation of a confederation, that references a remote
 * SAML confederation. Consumes the remote metadata as trusted
 * source for remote IDP's and SP's
 * 
 * Global configuration like:
 * <confederation id="[the-id]" class="...SAMLConfederation" enabled="[true/false]">
 *   <disable_sso>false</disable_sso>
 * </confederation>
 *  
 * disable_sso: (optional) configure whether SSO should be disabled when a user
 *    authenticates with a IDP from the remote federation. Could be used
 *    whenever the authentication context of an AuthnRequest has to be
 *    enforced at the remote federation instead of in our SSO server 
 *  
 * @author mdobrinic
 *
 */
public class SAML2Confederation implements IConfederation, IComponent {
	/** Configuration elements */
	public static final String EL_IDP_CATALOG = "idp_catalog";
	public static final String EL_SP_CATALOG = "sp_catalog";
	public static final String EL_DISABLE_SSO = "disable_sso";
	
	/** Local logger instance */
	private static Log _oLogger = LogFactory.getLog(SAML2Confederation.class);
	
	/** Local reference to configmanager for reloading configuration */
    private IConfigurationManager _oConfigManager;
    
    /** Configurable ID of the confederation */
    protected String _sID;
    
    /** 
     * Configurable option to disable SSO when authentication from an IDP from
     * this federation is performed
     * Default: false
     */
    protected boolean _bDisableSSOForIDPs;
    
    
    /**
     * MetadataProviderManager for this SAML2Catalog instance
     * The MetadataProviderManager manages multiple MetadataProviders for
     * different views on the catalog. This results from possible
     * filters that are applied by the source.
     * Example of different sources managed by the MetadataProviderManager:
     * <ul>
     * <li>FilesystemMetadataProvider: /metadata/generic-source.xml </li>
     * <li>FilesystemMetadataProvider: /metadata/specific-source[urn:sp:1].xml </li>
     * <li>FilesystemMetadataProvider: /metadata/specific-source[urn:sp:2].xml </li>
     * <li>...etc</li>
     * </ul>
     * This example is configued for an idp_catalog like: 
     * 		&lt;idp_catalog generic="/metadata/generic-source.xml"
     * 		specific="/metadata/specific-source[${sourceref}].xml" /&gt;
     */
    protected IMetadataProviderManager _oMetadataProviderManager;

    
    /**
     * Inner Class that holds configuration for metadata source
     * 
     * @author mdobrinic
     */
    class MetadataSourceDefinition {
    	public String _sId;		// ID of the MetadataSourceDefinition
    	public String sType;	// "file" or "url"
    	public String _sGenericSourceLocation;
    	public String _sSpecificSourceLocation;
    }

    /** Configured source for IDP-catalog metadata */
    protected MetadataSourceDefinition _oIDPCatalogSource;
    
    /** Configured source for SP-catalog metadata */
    protected MetadataSourceDefinition _oSPCatalogSource;
    
    
    /**
     * Default constructor
     */
    public SAML2Confederation() {
    	_oLogger.trace("SAML2Confederation instance created.");
    }
    
	
    /**
     * Create a new MetadataProvider, that uses the provided parameters to establish
     * the type and source of the provider
     * @param sParamSourceRef The source of the metadata that is passed to a MetadataProvider
     * @param oMSD The MetadataSource descriptor that is used to decide whether the 
     * 	sParamSourceRef parameter is a file or a URL 
     * @param oRefreshTimer The Timer thread that is used for scheduling reloading metadata
     * @return The MetadataProvider that was created, or null when the type of the Provider could
     *   not be established (should be {"url", "file"}).
     * @throws OAException
     */
	protected MetadataProvider createMetadataProviderFor(String sParamSourceRef, 
			MetadataSourceDefinition oMSD, Timer oRefreshTimer)
		throws OAException
	{
		if ("url".equals(oMSD.sType)) {
			MetadataProvider oMP = MetadataProviderUtil.createProviderForURL(sParamSourceRef, 
					MetadataProviderUtil.DEFAULT_PARSERPOOL,
					oRefreshTimer,
					MetadataProviderUtil.DEFAULT_HTTPCLIENT);
			return oMP;
		} else if ("file".equals(oMSD.sType)) {
			MetadataProvider oMP = MetadataProviderUtil.createProviderForFile(sParamSourceRef, 
					MetadataProviderUtil.DEFAULT_PARSERPOOL, 
					oRefreshTimer);
			
			return oMP;
		}
		
		return null;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public List<? extends IIDP> getIDPs(String sRequestor, Map<String, String> mContext)
		throws OAException
	{
		// Translate to fullqualified source reference, depending on which Requestor we want IDPs for
		String sParamSourceRef = getParamSourceRef(_oIDPCatalogSource, sRequestor);
		
		if (! _oMetadataProviderManager.existsFor(sParamSourceRef)) {
			// Create Timer instance, so we can manage it:
			String sTimername = "Metadata_SAML2Confed_IDPs_"+_oIDPCatalogSource._sId;
			if (sRequestor == null) {	// generic:
				sTimername += "[--generic--]";
			} else {
				if (_oIDPCatalogSource._sSpecificSourceLocation.equals(sParamSourceRef)) {	// specific:generic
					sTimername += "[--specific--]";
				} else {	// specific:specif
					sTimername += "[" + sRequestor +"]";
				}
			}
			sTimername += "-Timer";
			
			Timer oRefreshTimer = new Timer(sTimername, true);
			
			// Create provider for the specific IDP catalog
			MetadataProvider oMP = createMetadataProviderFor(sParamSourceRef, _oIDPCatalogSource, oRefreshTimer);
			
			// Start managing the MetadataProvider
			_oMetadataProviderManager.setProviderFor(sParamSourceRef, oMP, oRefreshTimer);
		}
		
		// Return a list of SAML2IDP's, as we're a SAML2Confederation
		List<IIDP> oIDPList = _oMetadataProviderManager.getIDPs(sParamSourceRef);
		
		// Override the SAML2 IDP configuration with confederation defaults
		for(IIDP oIDP: oIDPList) {
			if (!(oIDP instanceof SAML2IDP)) {
				_oLogger.warn("Non-SAML2IDP in SAML2Confederation: "+oIDP.getID());
				continue;
			}
			SAML2IDP oSAML2IDP = (SAML2IDP) oIDP;
			
			// Disable SSO for this IDP from confederation configuration
			oSAML2IDP.setDisableSSOForIDP(_bDisableSSOForIDPs);
		}
		
		return oIDPList; 
	}
	
	/**
	 * {@inheritDoc}
	 */
    public List<IRequestor> getSPs(String sIDP, Map<String, String> mContext)
    		throws OAException
    {
		// Translate to fullqualified source, because multiple idp's can have the same source
		String sParamSourceRef = getParamSourceRef(_oSPCatalogSource, sIDP);
		
		if (! _oMetadataProviderManager.existsFor(sParamSourceRef)) {
			// Create Timer instance, so we can manage it:
			String sTimername = "Metadata_SAML2Confed_SPs_"+_oIDPCatalogSource._sId;
			if (sIDP == null) {	// generic:
				sTimername += "[--generic--]";
			} else {
				if (_oIDPCatalogSource._sSpecificSourceLocation.equals(sParamSourceRef)) {	// specific:generic
					sTimername += "[--specific--]";
				} else {	// specific:specif
					sTimername += "[" + sIDP +"]";
				}
			}
			sTimername += "-Timer";
			
			Timer oRefreshTimer = new Timer(sTimername, true);
			
			MetadataProvider oMP = createMetadataProviderFor(sParamSourceRef, _oSPCatalogSource, oRefreshTimer);

			_oMetadataProviderManager.setProviderFor(sParamSourceRef, oMP, oRefreshTimer);
		}
		
		// Return a list of SAML2IDP's, as we're a SAML2Confederation
		List<IRequestor> oSPList = null;
//		oSPList = _oMetadataProviderManager.getSPs(sParamSourceRef);
		
		return oSPList; 
	}

	
    /**
     * Helper function that creates a SAML2IDP instance from an IIDP instance
     * @param oIDP IIDP instance to upgrade
     * @return
     */
    protected SAML2IDP getSAML2IDPFromIDP(IIDP oIDP) {
    	_oLogger.error("Not yet implemented: getSAML2IDPFromIDP()");
    	SAML2IDP oSAML2IDP = null;
    	return oSAML2IDP;
    }
    

	/**
	 * Helper to establish the full source of the MetadataProvider for a requestor or idp
	 * @param sSourceRef ID of the requestor or IDP; if null, the generic source is used
	 * @return Full qualified path to the metadata-source for the provided entity 
	 * @throws OAException
	 */
	protected String getParamSourceRef(MetadataSourceDefinition oMSDef, String sSourceRef)
		throws OAException
	{
		try {
			if (sSourceRef == null) {
				return oMSDef._sGenericSourceLocation;
			} else { 
				// Establish location:
				String sEncodedSourceReg = URIUtil.encodeQuery(sSourceRef);
			
				String re = "${sourceref}";
				String search = "\\"+re.replace("{","\\{").replace("}","\\}");
			
				return oMSDef._sSpecificSourceLocation.replaceAll(search, sEncodedSourceReg); 
			}
		} catch (URIException ue) {
			_oLogger.error("Exception occurred when encoding URI: "+ue.getMessage());
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		}
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public void start(IConfigurationManager oConfigManager,
			Element eConfig) throws OAException 
	{
		_oConfigManager = oConfigManager;
		
		_oLogger.info("Starting SAMLconfederation");
		
		
		_sID = oConfigManager.getParam(eConfig, "id");
		if (_sID == null) {
			_oLogger.error("No 'id' configured for confederation");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		// Initialize the MetadataProviderManager
		Element elMPMConfig = oConfigManager.getSection(eConfig, MetadataProviderUtil.EL_MPM);
		if (elMPMConfig != null) {
			_oMetadataProviderManager = 
					MetadataProviderUtil.getMetadataProviderManagerFromConfig(oConfigManager, elMPMConfig);
			_oLogger.info("MetadataProvider initialized for SAML2Confederation '"+_sID+"'");
		} else {
			_oLogger.error("No '"+MetadataProviderUtil.EL_MPM+"' configured for confederation");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}

		// Initialize catalog source configuration
		Element elIDPSource = oConfigManager.getSection(eConfig, EL_IDP_CATALOG);
		if (elIDPSource != null) {
			_oIDPCatalogSource = getMSD(oConfigManager, elIDPSource);
		} else {
			_oIDPCatalogSource = null;
		}

		Element elSPSource = oConfigManager.getSection(eConfig, EL_SP_CATALOG);
		if (elSPSource != null) {
			_oSPCatalogSource = getMSD(oConfigManager, elSPSource);
		} else {
			_oSPCatalogSource = null;
		}
		
		if (_oIDPCatalogSource == null && _oSPCatalogSource == null) {
			_oLogger.error("Confederation '"+_sID+"' has no configured SP- or IDP-catalog");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		String sDisableSSO = oConfigManager.getParam(eConfig, EL_DISABLE_SSO);
		if (sDisableSSO != null) {
			if ("true".equalsIgnoreCase(sDisableSSO)) {
				_bDisableSSOForIDPs = true;
			} else if (! "false".equalsIgnoreCase(sDisableSSO)) {
				_oLogger.error("Invalid value configured for "+EL_DISABLE_SSO+": '"+sDisableSSO+"'");
				throw new OAException(SystemErrors.ERROR_CONFIG_READ);
			} else {
				_bDisableSSOForIDPs = false;
			}
			
		} else {
			_bDisableSSOForIDPs = false;
		}
		
		_oLogger.info("SSO for IDPs from remote federation is "+
				(_bDisableSSOForIDPs?"disabled":"enabled")+" by default ");
		
		_oLogger.info("Started SAMLconfederation from asimba.xml");
	}

	
	private MetadataSourceDefinition getMSD(IConfigurationManager oConfigManager, Element elMSD)
		throws OAException
	{
		MetadataSourceDefinition oMSD = new MetadataSourceDefinition();
		
		oMSD._sId = oConfigManager.getParam(elMSD, "id");
		if (oMSD._sId == null) {
			_oLogger.error("No 'id' attribute provided with confederation SP or IDP catalog");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		Element elFile = oConfigManager.getSection(elMSD, "file");
		if (elFile!=null) {
			oMSD.sType = "file";
			oMSD._sGenericSourceLocation = oConfigManager.getParam(elFile, "generic");
			oMSD._sSpecificSourceLocation = oConfigManager.getParam(elFile, "specific");
			
			return oMSD;
		}

		Element elURL = oConfigManager.getSection(elMSD, "url");
		if (elURL!=null) {
			oMSD.sType = "url";
			oMSD._sGenericSourceLocation = oConfigManager.getParam(elURL, "generic");
			oMSD._sSpecificSourceLocation = oConfigManager.getParam(elURL, "specific");
			
			return oMSD;
		}

		_oLogger.error("No 'file' and not 'url' configured for catalog source.");
		throw new OAException(SystemErrors.ERROR_CONFIG_READ);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public void restart(Element eConfig) throws OAException {
        synchronized(this) {
			stop();
			start(_oConfigManager,eConfig);
        }
	}

	/**
	 * {@inheritDoc}
	 */
	public void stop() {
		if (_oMetadataProviderManager!=null) // Clean up references to MetadataProviderManager
			((IComponent)_oMetadataProviderManager).stop();
		
	}

	/**
	 * {@inheritDoc}
	 */
	public String getID() {
		return _sID;
	}
}
