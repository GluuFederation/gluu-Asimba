package org.asimba.util.saml2.metadata.provider.management;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.metadata.provider.IMetadataProviderManager;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.provider.AbstractObservableMetadataProvider;
import org.opensaml.saml2.metadata.provider.AbstractReloadingMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ObservableMetadataProvider.Observer;
import org.opensaml.samlext.saml2mdui.UIInfo;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;

/**
 * Manager for MetadataProviders
 * Designed as general purpose manager, as well as for generic and specific
 * providers, that use a specification for setting a filter on the source of
 * the metadata
 * 
 * @author mdobrinic
 *
 */
public class StandardMetadataProviderManager implements
	IMetadataProviderManager, IComponent,
	Observer 
{
	/**
	 * Local logger instance
	 */
	private static final Log _oLogger = LogFactory.getLog(StandardMetadataProviderManager.class);

	/**
	 * Reference to ConfiManager for reloading state
	 */
	protected IConfigurationManager _oConfigManager;


	/**
	 * MetadataProvider with some metadata for local administration
	 */
	protected class StoredMetadataProvider {
		public String _sID;
		public MetadataProvider _oProvider;
		
		/** Timer that does background reloading */
		public Timer _oBackgroundTimer;
		
		/** Timestamp in ms when the provider was last used */
		public long _lastUsed;

		/** List of IDPs - intermediary result processed to Asimba Model */
		public List<IIDP> _lCachedIDPs;

		/**
		 * Parameterized constructor
		 * @param sID
		 * @param oProvider
		 * @param oTimer Timer that manages background metadata refreshes; must be specific for this oProvider
		 */
		public StoredMetadataProvider(String sID, MetadataProvider oProvider, Timer oTimer) {
			_sID = sID;
			_oProvider = oProvider;
			_oBackgroundTimer = oTimer;
			_lCachedIDPs = new ArrayList<IIDP>();
			_lastUsed = System.currentTimeMillis();
		}

		/** Clean up */
		public void destroy() {
			_oProvider = null;
		}

		/** Touch access */
		public void touch() {
			_lastUsed = System.currentTimeMillis();
		}
	}

	/** Map of managed StoredMetadataProvider-instances */
	protected Map<String, StoredMetadataProvider> _hmSpecificProviders;

	/** Timeout in milliseconds after which resources of a MetadataProvider are released */
	protected int _iCacheInterval;

	/** Shared timer for all MetadataProviders */
	protected Timer _oMetadataProviderTimer = null;


	
	/**
	 * Temporary constructor :: DEVELOP VERSION
	 */
	public StandardMetadataProviderManager() {
		_hmSpecificProviders = new HashMap<String, StoredMetadataProvider>();
	}
	
	/**
	 * {@inheritDoc}
	 */
	public void setCacheInterval(int iTimeoutMS) {
		_iCacheInterval = iTimeoutMS;
	}

	/**
	 * {@inheritDoc}
	 */
	public int getCacheInterval() {
		return _iCacheInterval;
	}

	/**
	 * {@inheritDoc}
	 */
	public void setTimer(Timer oTimer) {
		if (_oMetadataProviderTimer!=null) {
			_oMetadataProviderTimer.cancel();
			_oMetadataProviderTimer = null;	// and release
		}
		_oMetadataProviderTimer = oTimer;
	}

	/**
	 * {@inheritDoc}
	 */
	public Timer getTimer() {
		return _oMetadataProviderTimer;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean existsFor(String sSourceRef) {
		return _hmSpecificProviders.containsKey(sSourceRef);
	}

	/**
	 * {@inheritDoc}
	 */
	public MetadataProvider getProviderFor(String sSourceRef)
			throws OAException
	{
		StoredMetadataProvider oSMP = _hmSpecificProviders.get(sSourceRef);

		if (oSMP == null) {
			return null;
		}

		// Touch MetadataProvider access:
		oSMP.touch();

		// And return instance
		return oSMP._oProvider;
	}

	/**
	 * {@inheritDoc}
	 */
	public List<IIDP> getIDPs(String sSourceRef) {
		String sRef;

		if (sSourceRef == null) {
			sRef = "unspecified";	// <-- not good
		} else {
			sRef = sSourceRef;
		}

		StoredMetadataProvider oSMP = _hmSpecificProviders.get(sRef);

		if (oSMP == null) {
			return null;
		}

		// Touch MetadataProvider access:
		oSMP.touch();

		// Return results
		return oSMP._lCachedIDPs;
	}


	/**
	 * {@inheritDoc}
	 */
	public void setProviderFor(String sSourceRef, MetadataProvider oProvider, Timer oTimer)
			throws OAException
	{
		if (existsFor(sSourceRef)) {
			MetadataProvider oMP = removeProviderFor(sSourceRef);
			oMP = null;	// remove it, so it can be replaced for a new one
		}

		StoredMetadataProvider oSMP = new StoredMetadataProvider(sSourceRef, oProvider, oTimer);

		// Store provider in local map
		_hmSpecificProviders.put(sSourceRef, oSMP);

		if (oProvider instanceof AbstractObservableMetadataProvider) {
			// If we can, we want to act when new metadata arrives
			((AbstractObservableMetadataProvider) oProvider).getObservers().add(this);
		}

		// Initialize IDP cache
		oSMP._lCachedIDPs = createIDPList(oProvider);
	}


	/**
	 * {@inheritDoc}
	 */
	public MetadataProvider removeProviderFor(String sSourceRef)
			throws OAException
	{
		if (! existsFor(sSourceRef)) {
			return null;
		}
		StoredMetadataProvider oSMP = _hmSpecificProviders.get(sSourceRef);

		// Get reference for returning later
		MetadataProvider oMP = oSMP._oProvider;

		// Now clean up all tracks in our own state
		_hmSpecificProviders.remove(sSourceRef);

		if (oMP instanceof AbstractObservableMetadataProvider) {
			// We want to remove ourself from observers
			((AbstractObservableMetadataProvider) oMP).getObservers().remove(this);
		}
		
		// Clear all tasks from the timer of the MetadataProvider
		oSMP._oBackgroundTimer.cancel();
		oSMP._oBackgroundTimer = null;	// remove reference

		oSMP.destroy();
		oSMP = null;

		// Return provider
		return oMP;
	}

	
	/**
	 * Local helper to establish a StoredMetadataProvider instance from managed list 
	 */
	protected StoredMetadataProvider getFromProvider(MetadataProvider oProvider) {
		for(StoredMetadataProvider smp: _hmSpecificProviders.values()) {
			if (smp._oProvider == oProvider) {
				return smp;
			}
		}
		return null;
	}


	/**
	 * Local helper to build the cached IDPList for a MetadataProvider
	 * @param oProvider
	 * @return list with IDPs, or empty list when no IDPs were established
	 */
	protected List<IIDP> createIDPList(MetadataProvider oProvider) {

		try {
			List<IIDP> oIDPs = new ArrayList<IIDP>();

			XMLObject x = (XMLObject) oProvider.getMetadata();

			if (! (x instanceof EntitiesDescriptor)) {
				_oLogger.info("No EntitiesDescriptor was returned.");
				return oIDPs;
			}

			EntitiesDescriptor oEntitiesDescriptor = (EntitiesDescriptor)x;
			List<EntityDescriptor> lEntityDescriptors = oEntitiesDescriptor.getEntityDescriptors();

			for (EntityDescriptor e: lEntityDescriptors) {
				IIDP i = idpFromEntityDescriptor(e);
				if (i != null) {
					oIDPs.add(i);
				}
			}

			return oIDPs;

		} catch (MetadataProviderException e) {
			_oLogger.error("Exception when updating cached IDP list after metadata refresh: "+e.getMessage());
			return null;
		} catch (OAException e) {
			_oLogger.error("OAException while creating SAML2 IDP list: "+e.getMessage());
			return null;
		}
	}


	/**
	 * onEvent is called when fresh metadata is initialized by the MetadataProvider
	 * Use this moment to do a translation to cache to Asimba SAML2IDP list format  
	 */
	public void onEvent(MetadataProvider provider) {
		StoredMetadataProvider oSMP = getFromProvider(provider);
		if (oSMP == null) {
			_oLogger.error("Inconsistent state: no instance known for provider "+provider);
			return;
		}

		List<IIDP> oIDPList = createIDPList(provider);

		synchronized(this) {
			if (oIDPList == null) {
				oSMP._lCachedIDPs.clear();
			} else {
				oSMP._lCachedIDPs = oIDPList;
			}
			oSMP.touch();
		}

		return;
	}



	/**
	 * Create a SAMLIDP instance from the provided EntityDescriptor
	 * 
	 * @param oED EntityDescriptor of the SAML entity
	 * @return SAMPIDP instance, or null when the EntityDescriptor did not 
	 * 	contain an IDPSSO definition
	 * @throws OAException
	 */
	protected IIDP idpFromEntityDescriptor(EntityDescriptor oED)
			throws OAException 
			{
		/* 
		SAML2IDP(String sID, byte[] baSourceID, String sFriendlyName,
        	String sMetadataFile, String sMetadataURL, 
        	int iMetadataTimeout, Boolean useACSIndex, Boolean useAllowCreate, 
        	Boolean useScoping, Boolean useNameIDPolicy, String forceNameIDFormat)
		 */
		SAML2IDP oSAML2IDP = null;

		List<RoleDescriptor> lRoles = oED.getRoleDescriptors();

		if (lRoles.size() == 0) {
			// No roles contained in the EntityDescriptor
			return null;
		}

		boolean bIDPDescriptorProcessed = false;

		// Only use the first IDPSSODescriptor definition:
		for(RoleDescriptor r: lRoles) {

			// ::: wrong logics:  vvvv
			if (bIDPDescriptorProcessed || (! (r instanceof IDPSSODescriptor))) {
				if (bIDPDescriptorProcessed) {
					_oLogger.info("IDP "+oED.getEntityID()+" defines more than one IDPSSODescriptor roles; only using the first one.");
				}
				continue;
			}

			bIDPDescriptorProcessed = true;

			_oLogger.info("Entity '"+oED.getEntityID());
			_oLogger.info("  Supported protocols: "+r.getSupportedProtocols().toString());

			String sFriendlyname = oED.getEntityID();


			// try to work with mdui extension:
			Extensions ext = r.getExtensions();

			if (ext != null) {
				List<XMLObject> lx = ext.getOrderedChildren();
				for(XMLObject x: lx) {
					if (x instanceof UIInfo) {
						UIInfo u = (UIInfo) x;
						if (u.getDisplayNames().size() > 0) {
							sFriendlyname = u.getDisplayNames().get(0).getName().getLocalString();
						}
					}
				}
			}

			String sMetadataFile = null;	// no file source
			String sMetadataURL = null;	// no (direct) metadata source
			int iMetadataTimeout = -1;	// use default
			boolean useACSIndex = false;	// default: no ACS use
			boolean bAllowCreate = true; 	// default: yes, allow create new transit id's
			boolean bUseScoping = true;	// default: true; configurable?
			boolean bUseNameIDPolicy = false;	// default: do not force NameID policy in requests
			String sForceNameIDFormat = null;	// default: no specific NameIDFormat is requested

			// No MetadataProviderManager needed, as the SAML2IDP MetadataProvider is already managed
			oSAML2IDP = new SAML2IDP(oED.getEntityID(), null,
					sFriendlyname, sMetadataFile, sMetadataURL, iMetadataTimeout,
					useACSIndex, bAllowCreate, bUseScoping, bUseNameIDPolicy, sForceNameIDFormat, null);

			// Instead, set the SAML2IDP's metadata to live XML-document's format
			oSAML2IDP.setMetadataXMLObject(oED);
		}

		if (! bIDPDescriptorProcessed) {
			return null;	// no IDP descriptor processed
		}

		return oSAML2IDP;
	}

	/**
	 * {@inheritDoc}
	 */
	public void destroy() {
		for(String s: _hmSpecificProviders.keySet()) {
			try {
				removeProviderFor(s);
			} catch (OAException oae) {
				_oLogger.warn("OAException when removing MetadataProvider for "+s);
			}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void start(IConfigurationManager oConfigManager,
			Element eConfig) throws OAException 
			{
		_oConfigManager = oConfigManager;
		_hmSpecificProviders = new HashMap<String, StoredMetadataProvider>();

		_oMetadataProviderTimer = new Timer(this.getClass().getName());
			}

	/**
	 * {@inheritDoc}
	 */
	public void restart(Element eConfig) throws OAException {
		synchronized (this) {
			stop();
			start(_oConfigManager, eConfig);
		}

	}

	/**
	 * {@inheritDoc}
	 */
	public void stop() {
		if (_oMetadataProviderTimer!=null) {
			_oMetadataProviderTimer.cancel();
			_oMetadataProviderTimer = null;	// and release
		}
		
		// Clean up the rest.
		destroy();
	}
}
