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
package org.asimba.util.saml2.metadata.provider;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Timer;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.utility.xml.XMLUtils;
import org.opensaml.saml2.metadata.provider.DOMMetadataProvider;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Utilities for working with MetadataProviders
 * 
 * @author mdobrinic
 *
 */
public class MetadataProviderUtil {
	/** Configuration elements */
	public static final String EL_MPM = "mp_manager";
	
	/**
	 * Local logger instance
	 */
    private static final Log _oLogger = LogFactory.getLog(MetadataProviderUtil.class);

    
    /**
     * Default time in milliseconds to wait for a response from a remote URL source
     */
    protected static int DEFAULT_METADATA_URL_TIMEOUT = 60*1000;
    
    /**
     * Use default, shared, timer instance
     */
    public static final Timer DEFAULT_TIMER = null;
    
    /**
     * Use default, shared, ParserPool
     */
    public static final ParserPool DEFAULT_PARSERPOOL = null;
    
    /**
     * Use default basic HTTPClient instance 
     */
    public static final HttpClient DEFAULT_HTTPCLIENT = null;
    
    /**
     * ParserPool instance that is used as fallback, when none provided
     * Will be initialized to BasicParserPool when not yet initialized before
     * first use
     */
    protected static ParserPool _oSharedParserPool = null;
    
    
    /**
     * Timer instance that is used as fallback, when none provided
     * Responsible for (synchronous) scheduling of metadata refresh actions.
     * Problem: the timer is owned by nobody; who takes care of its lifecycle?????
     */
    protected static Timer _oSharedTimer = null;
    
    
    private static Timer getTimer(Timer oTimer) {
		if (oTimer == null) {
			if (_oSharedTimer == null) {
				// Create named timer as daemon thread
				// Be warned that this is not managed anywhere!
				_oSharedTimer = new Timer("MetadataProviderUtil-Timer", true);
				_oLogger.info("Creating static Timer thread for MetadataProviderUtil: " + _oSharedTimer.toString());
			}
			if (_oLogger.isTraceEnabled()) {
				_oLogger.trace("Using shared Timer instance.");
			}
			
			oTimer = _oSharedTimer;
		}
		
		return oTimer;
    }
    
    
    private static ParserPool getParserPool(ParserPool oParserPool) {
		if (oParserPool == null) {
			if (_oSharedParserPool == null) {
				_oSharedParserPool = new BasicParserPool();
				((BasicParserPool)_oSharedParserPool).setNamespaceAware(true);
			}
			if (_oLogger.isTraceEnabled()) {
				_oLogger.trace("Using shared ParserPool instance.");
			}
			
			oParserPool = _oSharedParserPool;
		}
		
		return oParserPool;
    }
    
	/**
	 * Utility for creating MetadataProvider source, performing some integrity
	 * checks and using some default settings
	 * @param sMetadataSource String containing the source address for the 
	 *  metadata
	 * @param oParserPool that is responsible for processing retrieved metadata;
	 *  when using null, a common (shared within MDUtil-context) ParserPool is used
	 * @param oTimer timer that is used for scheduling the cache refresh of the
	 *  metadata source; if null is passed, a common (shared within MDUtil-context)
	 *  timer is used
	 * @return
	 * @throws exception when URL was invalid or unreachable or another error
	 * 	occurred that could not be recovered from  
	 */
	public static MetadataProvider createProviderForURL(String sMetadataSource, 
			ParserPool oParserPool, Timer oTimer, HttpClient oHttpClient)
	{
		// No source provided, so no MetadataProvider returned: 
		if (sMetadataSource == null) {
			return null;
		}
		
		try {
			new URL(sMetadataSource);
		} catch (MalformedURLException mfue) {
			_oLogger.error("Invalid URL provided: " + sMetadataSource);
			return null;
		}
		
		oParserPool = getParserPool(oParserPool);
		oTimer = getTimer(oTimer);
		
		// Use default HttpClient when none was provided
		if (oHttpClient == null) {
			oHttpClient = new HttpClient();
		}
		
		HTTPMetadataProvider oHTTPMetadataProvider = null;
		
		try {
			oHTTPMetadataProvider = new HTTPMetadataProvider(oTimer, oHttpClient, sMetadataSource);
			
			oHTTPMetadataProvider.setParserPool(oParserPool);
			oHTTPMetadataProvider.initialize();
			
		} catch (MetadataProviderException e) {
			_oLogger.error("Exception when creating HTTPMetadataProvider: "+e.getMessage());
			return null;
		}
		
		return oHTTPMetadataProvider;
	}
	

	/**
	 * Wrapper that uses default HttpProvider, parserpool and timer
	 * @param sMetadataSource
	 * @param oParserPool
	 * @param oTimer
	 * @return
	 * @throws OAException
	 */
    public static MetadataProvider createProviderForURL(String sMetadataSource)
	{
    	return createProviderForURL(sMetadataSource, 
    			DEFAULT_PARSERPOOL, DEFAULT_TIMER, DEFAULT_HTTPCLIENT);
	}

	/**
	 * Wrapper that uses HttpProvider with specified timeout, default parserpool and timer
	 * @param sMetadataSource
	 * @param oParserPool
	 * @param oTimer
	 * @return
	 * @throws OAException
	 */
    public static MetadataProvider createProviderForURL(String sMetadataSource, int iTimeoutMs)
	{
    	HttpClient oHttpClient;
    	
    	oHttpClient = new HttpClient();
    	oHttpClient.getParams().setSoTimeout(iTimeoutMs);
    	
    	return createProviderForURL(sMetadataSource, 
    			DEFAULT_PARSERPOOL, DEFAULT_TIMER, oHttpClient);
	}

    
    /**
     * Establich MetadataProvider for provided filename
     * @param sMetadataSource
     * @param oParserPool
     * @param oTimer
     * @return
     * @throws OAException
     */
    public static MetadataProvider createProviderForFile(String sMetadataSource, 
			ParserPool oParserPool, Timer oTimer)
	{
		// No source provided, so no MetadataProvider returned: 
		if (sMetadataSource == null) {
			return null;
		}
		File fMetadata = null;
		
		fMetadata = new File(sMetadataSource);
		if (!fMetadata.exists()) {
			_oLogger.warn("Provided filename for metadata does not exist: " +sMetadataSource);
			return null;
		}
		
		oParserPool = getParserPool(oParserPool);
		oTimer = getTimer(oTimer);
		
		NamedFilesystemMetadataProvider oFileMetadataProvider = null;
		
		try {
			oFileMetadataProvider = new NamedFilesystemMetadataProvider(oTimer, fMetadata);
			
			oFileMetadataProvider.setParserPool(oParserPool);
			oFileMetadataProvider.initialize();

		} catch (MetadataProviderException e) {
			_oLogger.error("Exception when creating HTTPMetadataProvider: "+e.getMessage());
			return null;
		}
		
		return oFileMetadataProvider;
	}
    
    
    public static MetadataProvider createProviderForFile(String sMetadataSource)
    {
    	return createProviderForFile(sMetadataSource, 
    			DEFAULT_PARSERPOOL, DEFAULT_TIMER);
    }
    
    
    /**
     * Helper function to instantiate a MetadataProviderManager from configured source
     * @param oConfigManager
     * @param elMPMConfig
     * @return
     */
	public static IMetadataProviderManager getMetadataProviderManagerFromConfig(
			IConfigurationManager oConfigManager, Element elMPMConfig)
		throws OAException
	{
		String sClass = oConfigManager.getParam(elMPMConfig, "class");
		if (sClass == null) {
			_oLogger.error("No 'class' item found in '"+EL_MPM+"' section");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
	        
		Class<?> oClass = null;
		try {
			oClass = Class.forName(sClass);
		}
		catch (Exception e) {
			_oLogger.error("No 'class' found with name: " + sClass, e);
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
			
		IMetadataProviderManager oMPM = null;
		try {
			oMPM = (IMetadataProviderManager) oClass.newInstance();
		}
		catch (Exception e) {
			_oLogger.error("Could not create 'IMetadataProviderManager' instance of the 'class' with name: " 
					+ sClass, e);
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
	        
		// Initialize the IMetadataProviderManager
		((IComponent)oMPM).start(oConfigManager, elMPMConfig);

		return oMPM;
	}


    /**
     * Establish the fingerprint of the actual MetadataProvider
     * results in a string containing
     * 		provider-type,identifying-attributes
     * @param oMP
     * @return
     */
    public static String getMetadataProviderFingerprint(MetadataProvider oMP) {
    	StringBuilder oResult = new StringBuilder();
    	
    	if (oMP instanceof HTTPMetadataProvider) {
    		HTTPMetadataProvider oHMP = (HTTPMetadataProvider) oMP;
    		
    		oResult.append(MetadataProviderConfiguration.FINGERPRINT_PROVIDER_HTTP);
    		oResult.append(","+oHMP.getMetadataURI());
    		oResult.append(","+oHMP.getRequestTimeout());
    		
    		return oResult.toString();
    	}
    	
    	if (oMP instanceof NamedFilesystemMetadataProvider) {
    		NamedFilesystemMetadataProvider oNFMP = (NamedFilesystemMetadataProvider) oMP;
    		
    		oResult.append(MetadataProviderConfiguration.FINGERPRINT_PROVIDER_FILE);
    		oResult.append(","+oNFMP.getFilename());
    		
    		return oResult.toString();
    	}
    	
    	return MetadataProviderConfiguration.FINGERPRINT_PROVIDER_UNKNOWN;
    	
    }
    
    
    /**
     * Create a new MetadataProvider instance from the provided configuration.<br/>
     * The order of creation is:<br/>
     * <ul><li>When a URL is configured, a HTTP Metadata Provider is created</li>
     * <li>Otherwise, when a file is configured, a Filesystem Metadata Provider is created</li> 
     * <li>Otherwise, when metadata itself is configured, a DOMMetadata Provider is created</li>
     * </ul> <br/>
     * When none of the above was found, no metadata provider is created and null is returned
     * 
     * @param sId The EntityId (RequestorId or IDP-Id that the provider is to be created for)  
     * @param oMPC MetadataProvider configuration
     * @param oMPM MetadataProviderManager that will be managing the new provider
     * @return
     * @throws OAException when initialization failed without possible recovery
     */
    public static MetadataProvider createMetadataProvider(String sId, 
    		MetadataProviderConfiguration oMPC, IMetadataProviderManager oMPM)
    				throws OAException
    {
    	// Initialize a ParserPool to use
    	BasicParserPool oParserPool = new BasicParserPool();
    	oParserPool.setNamespaceAware(true);
    	
    	// When a URL is configured, return a HTTPMetadataProvider
    	try {
	    	if (oMPC._sURL != null) {
	    		_oLogger.trace("Using HTTPMetadataProvider for "+sId);
	    		return newHTTPMetadataProvider(sId, oMPC._sURL, oMPC._iTimeout, oParserPool, oMPM);
	    	}
    	} catch (OAException oae) {
    		_oLogger.warn("Exception: '"+oae.getMessage()+"'; Could not create HTTPMetadataProvider for '"+sId+"'; skipping.");
    	}

    	// When a File is configured, return a NamedFilesystemMetadataProvider
    	try {
	    	if (oMPC._sFilename != null) {
	    		_oLogger.trace("Using FileMetadataProvider for "+sId);
	    		return newFileMetadataProvider(sId, oMPC._sFilename, oParserPool, oMPM);
	    	}
    	} catch (OAException oae) {
    		_oLogger.warn("Exception: '"+oae.getMessage()+"'; Could not create FileMetadataProvider for '"+sId+"'; skipping.");
    	}
    	
    	// When metadata itself is configured, return DOMMetadataProvider
    	if (oMPC._sMetadata != null) {
    		_oLogger.trace("Using DOMMetadataProvider for "+sId);
    		return newDOMMetadataProvider(sId, oMPC._sMetadata, oParserPool, oMPM);
    	}
    	
    	return null;

    }
    
    
    /**
     * Create a new Filesystem Metadata Provider from the provided filename<br/>
     * An exception is thrown when the file does not exist.
     * 
     * @param sId Entity Id that the metadata is being created for 
     * @param sMetadataFile
     * @param oParserPool
     * @param oMPM
     * @return
     * @throws OAException
     */
    public static MetadataProvider newFileMetadataProvider(String sId, String sMetadataFile, ParserPool oParserPool, 
    		IMetadataProviderManager oMPM)
                throws OAException
    {
        MetadataProvider oProvider = null;

    	// Check whether file exists
        File fMetadata = new File(sMetadataFile);
        if (!fMetadata.exists()) {
        	_oLogger.error("The metadata file doesn't exist: " + sMetadataFile);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        // Establish dedicated refresh timer:
        String sTimername = "Metadata_File-"+(oMPM==null?"":oMPM.getId()+"-")+sId+"-Timer";
        Timer oRefreshTimer = new Timer(sTimername, true);
        
    	oProvider = MetadataProviderUtil.createProviderForFile(sMetadataFile, oParserPool, 
    			oRefreshTimer);
        
    	if (oProvider != null) {
	    	// Start managing it:
	    	if (oMPM != null) {
	    		oMPM.setProviderFor(sId, oProvider, oRefreshTimer);
	    	}
    	} else {
    		// Unsuccessful creation; clean up created Timer
    		oRefreshTimer.cancel();
    	}

        return oProvider;
    }
    
    
    /**
     * Create a new HTTP Metadata Provider from the provided URL and HTTP settings<br/>
     * An exception is thrown when the provider could not be initiated.
     * 
     * @param sMetadataURL
     * @param sMetadataTimeout
     * @param oParserPool
     * @param oMPM
     * @return
     * @throws OAException
     */
    public static MetadataProvider newHTTPMetadataProvider(String sId, String sMetadataURL,
    		int iTimeout, ParserPool oParserPool, IMetadataProviderManager oMPM) 
    				throws OAException
    {
        MetadataProvider oProvider = null;
        
        // Check URL format
        URL oURLTarget = null;
        try {
            oURLTarget = new URL(sMetadataURL);
        } catch (MalformedURLException e) {
        	_oLogger.error("Invalid url for metadata: " + sMetadataURL, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        // Check valid and existing destination (with configured timeout settings)
        try {
            URLConnection oURLConnection = oURLTarget.openConnection();
            if (iTimeout == 0) {
	            oURLConnection.setConnectTimeout(3000);
	            oURLConnection.setReadTimeout(3000);
            } else {
            	oURLConnection.setConnectTimeout(iTimeout);
	            oURLConnection.setReadTimeout(iTimeout);
            }
            
            oURLConnection.connect();
        } catch (IOException e) {
        	_oLogger.warn("Could not connect to metadata url: " + sMetadataURL +
            		"(using timout "+(iTimeout==0?"3000":iTimeout) +"ms)", e);
        }

        // Establish dedicated refresh timer:
        String sTimername = "Metadata_HTTP-"+(oMPM==null?"":oMPM.getId()+"-")+sId+"-Timer";
        Timer oRefreshTimer = new Timer(sTimername, true);
        
        // Establish HttpClient
    	HttpClient oHttpClient = new HttpClient();
        
        if (iTimeout > 0) {
            // Set configured Timeout settings
        	oHttpClient.getParams().setSoTimeout(iTimeout);
        }
        
    	oProvider = MetadataProviderUtil.createProviderForURL(sMetadataURL, oParserPool, 
    			oRefreshTimer, oHttpClient);
        
    	if (oProvider != null) {
	    	// Start managing it:
	    	if (oMPM != null) {
	    		oMPM.setProviderFor(sId, oProvider, oRefreshTimer);
	    	}
    	} else {
    		// Unsuccessful creation; clean up created Timer
    		oRefreshTimer.cancel();
    	}

        return oProvider;
    }

    
    /**
     * Create a new DOM Metadata Provider from the provided metadata<br/>
     * An exception is thrown when the provider could not be initiated.
     * 
     * <br/><br/>
     * Note that a DOM Metadata Provider is not refreshed, and as such,
     * does not own a Timer thread 
     * @param sMetadata
     * @param oParserPool
     * @return
     */
    public static MetadataProvider newDOMMetadataProvider(String sId, String sMetadata, 
    		ParserPool oParserPool, IMetadataProviderManager oMPM) 
    {
    	if (sMetadata == null) return null;
    	
		try {
			Document d = XMLUtils.getDocumentFromString(sMetadata);
			Element elMetadata = d.getDocumentElement();
			
	    	DOMMetadataProvider oProvider = new DOMMetadataProvider(elMetadata);
	    	oProvider.setParserPool(oParserPool);
	    	
	    	if (oMPM != null) {
	    		oMPM.setProviderFor(sId, oProvider, null);
	    	}
	    	
	    	return oProvider;
		} catch (OAException e) {
			_oLogger.warn("Could not parse provided metadata document.");
		}
		
		return null;
    }
	
}
