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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Timer;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
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
    public static Timer DEFAULT_TIMER = null;
    
    /**
     * Use default, shared, ParserPool
     */
    public static ParserPool DEFAULT_PARSERPOOL = null;
    
    /**
     * Use default basic HTTPClient instance 
     */
    public static HttpClient DEFAULT_HTTPCLIENT = null;
    
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
				_oSharedTimer = new Timer();
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
		throws OAException
	{
		// No source provided, so no MetadataProvider returned: 
		if (sMetadataSource == null) {
			return null;
		}
		
		try {
			new URL(sMetadataSource);
		} catch (MalformedURLException mfue) {
			_oLogger.error("Invalid URL provided: " + sMetadataSource);
			throw new OAException(SystemErrors.ERROR_INTERNAL);
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
			throw new OAException(SystemErrors.ERROR_INTERNAL);
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
		throws OAException
	{
    	return createProviderForURL(sMetadataSource, 
    			DEFAULT_PARSERPOOL, DEFAULT_TIMER, DEFAULT_HTTPCLIENT);
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
		throws OAException
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
		
		FilesystemMetadataProvider oFileMetadataProvider = null;
		
		try {
			oFileMetadataProvider = new FilesystemMetadataProvider(oTimer, fMetadata);
			
			oFileMetadataProvider.setParserPool(oParserPool);
			oFileMetadataProvider.initialize();
			
		} catch (MetadataProviderException e) {
			_oLogger.error("Exception when creating HTTPMetadataProvider: "+e.getMessage());
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		}
		
		return oFileMetadataProvider;
	}
    
    
    public static MetadataProvider createProviderForFile(String sMetadataSource)
    	throws OAException
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


    
}
