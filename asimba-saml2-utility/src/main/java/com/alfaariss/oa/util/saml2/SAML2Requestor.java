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
package com.alfaariss.oa.util.saml2;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.Vector;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.metadata.provider.IMetadataProviderManager;
import org.asimba.util.saml2.metadata.provider.MetadataProviderUtil;
import org.asimba.util.saml2.metadata.provider.management.MdMgrManager;
import org.asimba.utility.filesystem.PathTranslator;
import org.asimba.utility.xml.XMLUtils;
import org.joda.time.DateTime;
import org.joda.time.format.ISODateTimeFormat;
import org.opensaml.saml2.metadata.provider.ChainingMetadataProvider;
import org.opensaml.saml2.metadata.provider.DOMMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;

/**
 * Requestor object containing requestor specific configuration items.
 * 
 * @author MHO
 * @author Alfa & Ariss 
 */
public class SAML2Requestor implements Serializable
{
    /** Default request timeout */
    public final static int HTTP_METADATA_REQUEST_TIMEOUT = 5000;
       
    /**
     * ID
     */
    protected String _sID;
    
    /**
     * Metadata URL
     */
    protected String _sMetadataURL;
    
    /**
     * Metadata file
     */
    protected File _fMetadata;
    
    /**
     * Timeout
     */
    protected int _iMetadataURLTimeout;
    
    /**
     * Metadata data 
     */
    protected String _sMetadata;
    
    /**
     * Signing mandatory.
     */
    protected boolean _bSigning;
   
    /**
     * Metadata Provider.
     */
    protected MetadataProvider _oMetadataProvider;

    private final static long serialVersionUID = 2093412253512956567L;
    
    private final static String PROPERTY_SIGNING = ".signing";
    private final static String PROPERTY_METADATA_HTTP_TIMEOUT = ".metadata.http.timeout";
    private final static String PROPERTY_METADATA_HTTP_URL = ".metadata.http.url";
    private final static String METADATA_FILE = ".metadata.file";
    private final static String METADATA = ".metadata";
    
    private Log _logger;
    
    /**
     * Constructor.
     * 
     * @param configurationManager The config manager.
     * @param config Configuration section.
     * @param bSigning Default signing boolean.
     * @throws OAException If creation fails.
     */
    public SAML2Requestor(IConfigurationManager configurationManager, 
        Element config, boolean bSigning, String sProfileID) throws OAException
    {
        _logger = LogFactory.getLog(SAML2Requestor.class);
        try
        {
            _sID = configurationManager.getParam(config, "id");
            if (_sID == null) {
                _logger.error("No 'id' item found in 'requestor' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _bSigning = false;
            String sSigning = configurationManager.getParam(config, "signing");
            if (sSigning == null) {
                _logger.warn("No optional 'signing' item found in configuration for requestor with id: " 
                    + _sID);
                _bSigning = bSigning;
            }
            else
            {
                if (sSigning.equalsIgnoreCase("TRUE")) {
                    _bSigning = true;
                }
                else {
                	if (!sSigning.equalsIgnoreCase("FALSE")){
	                    _logger.error("Invalid 'signing' item found in configuration (must be true or false) for requestor with id: "
	                        + _sID);
	                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
	                }
                }
            }
            
            String sDateLastModified = configurationManager.getParam(config, "lastmodified");
            Date dLastModified = null;
            
            if (sDateLastModified != null) {
            	// Convert to java.util.Date
            	try {
	            	DateTime dt = ISODateTimeFormat.dateTimeNoMillis().parseDateTime(sDateLastModified);
            		dLastModified = dt.toDate();
            	} catch (IllegalArgumentException iae) {
            		_logger.info("Invalid 'lastmodified' timestamp provided: "+sDateLastModified+"; ignoring.");
            		dLastModified = null;
            	}
            }

            
            _oMetadataProvider = null;
            _sMetadataURL = null;
            _fMetadata = null;
            _sMetadata = null;	// metadata contents never initialized from configuration
            _iMetadataURLTimeout = HTTP_METADATA_REQUEST_TIMEOUT;
            
            Element eMetadata = configurationManager.getSection(config, "metadata");
            if (eMetadata != null)
            {
            	// Establish MetadataProvider for Requestor:
            	IMetadataProviderManager oMPM = null;
            	MetadataProvider oMP = null;

            	oMPM = MdMgrManager.getInstance().getMetadataProviderManager(sProfileID);
            	
            	// Try to get MetadataProvider from manager
            	if (oMPM != null) {
            		oMP = oMPM.getProviderFor(_sID, dLastModified);
            	}
            	
            	if (oMP == null) {
        			// Create new MetadataProvider
        			List<MetadataProvider> listMetadataProviders = 
                            readMetadataProviders(configurationManager, eMetadata, oMPM);
        			
        			if (!listMetadataProviders.isEmpty()) {
            			// Only one is used:
        				oMP = listMetadataProviders.get(0);
        				_logger.info("MetadataProviders was be established for "+_sID);
        			} else {
        				_logger.info("No MetadataProviders could be established for "+_sID);
        			}
        		}
            	
            	_oMetadataProvider = oMP;
            	
            	if (_oMetadataProvider == null) {
            		_logger.info("No MetadataProviders was found for "+_sID);
            	}
            }
            else
                _logger.warn(
                    "No optional 'metadata' section found in configuration for requestor with id: " 
                    + _sID);
            
            _logger.info("Using signing enabled: " + _bSigning);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error while reading requestors configuration", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Constructor which uses business logic requestor properties.
     *  
     * @param requestor The OA Requestor object
     * @param bSigning Default signing boolean.
     * @param sProfileID The SAML2 OA Profile id for resolving the attributes.
     * @throws OAException If creation fails.
     * @since 1.1
     */
    public SAML2Requestor(IRequestor requestor, boolean bSigning, String sProfileID) 
        throws OAException
    {
        try
        {
        	_logger = LogFactory.getLog(SAML2Requestor.class);
            _sID = requestor.getID();

            Map<?, ?> mProperties = requestor.getProperties();
        	initFromProperties(mProperties, bSigning, sProfileID);

        	// Establish MetadataProvider for Requestor:
        	IMetadataProviderManager oMPM = null;
        	MetadataProvider oMP = null;
        	
        	oMPM = MdMgrManager.getInstance().getMetadataProviderManager(sProfileID);
        	
        	// Try to get MetadataProvider from manager
        	if (oMPM != null) {
        		oMP = oMPM.getProviderFor(_sID, requestor.getLastModified());
        	}
        	
        	if (oMP == null) {
    			// Create new MetadataProvider
                _oMetadataProvider = null;
                _sMetadataURL = null;
                _fMetadata = null;
                _iMetadataURLTimeout = HTTP_METADATA_REQUEST_TIMEOUT;
                
                String sMetadataURL = (String)mProperties.get(sProfileID + PROPERTY_METADATA_HTTP_URL);
                String sMetadataTimeout = (String)mProperties.get(sProfileID + PROPERTY_METADATA_HTTP_TIMEOUT);
                String sMetadataFile = (String)mProperties.get(sProfileID + METADATA_FILE);
                _sMetadata = (String)mProperties.get(sProfileID + METADATA);
                
                List<MetadataProvider> listMetadataProviders = 
                    readMetadataProviders(sMetadataURL, sMetadataTimeout, sMetadataFile, _sMetadata, oMPM);
    			
    			if (!listMetadataProviders.isEmpty()) {
        			// Use the first one:
    				oMP = listMetadataProviders.get(0);
    				_logger.info("MetadataProviders was be established for "+_sID);
    			} else {
    				_logger.info("No MetadataProviders could be established for "+_sID);
    			}
    		}
        	
        	_oMetadataProvider = oMP;
        	
        	if (_oMetadataProvider == null) {
        		_logger.info("No MetadataProvider was found for "+_sID);
        	}
        	
        }
        catch (OAException oae) {
    		_logger.error("Exception when initializing MetadataProvider: "+oae.getMessage());
    		throw oae;
        } catch(Exception e) {
            _logger.fatal("Internal error while reading SAML2 attributes for requestor: " 
                + requestor.getID(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    
    /**
     * Constructor which uses business logic requestor properties; also accept an already initialized
     * MetadatProvider so it can be reused
     * @param requestor
     * @param bSigning
     * @param sProfileID
     * @param oMetadataProvider
     * @throws OAException
     */
    public SAML2Requestor(IRequestor oRequestor, boolean bSigning, String sProfileID,
    		MetadataProvider oMetadataProvider) 
        throws OAException
    {
    	try {
	        _logger = LogFactory.getLog(SAML2Requestor.class);
	        _sID = oRequestor.getID();
	        Map<?, ?> mProperties = oRequestor.getProperties();
	
	    	initFromProperties(mProperties, bSigning, sProfileID);
	    	
	    	// Skip MetadataProvider initialization if it is already provided
	        if (oMetadataProvider == null) {
	        	
	        	// Establish MetadataProvider for Requestor:
	        	IMetadataProviderManager oMPM = null;
	        	MetadataProvider oMP = null;
	        	
	        	oMPM = MdMgrManager.getInstance().getMetadataProviderManager(sProfileID);
	        	
	        	// Try to get MetadataProvider from manager
	        	if (oMPM != null) {
	        		oMP = oMPM.getProviderFor(_sID, oRequestor.getLastModified());
	        	}
	        	
	        	if (oMP == null) {
	    			// Create new MetadataProvider
	                _oMetadataProvider = null;
	                _sMetadataURL = null;
	                _fMetadata = null;
	                _iMetadataURLTimeout = HTTP_METADATA_REQUEST_TIMEOUT;
	                
	                String sMetadataURL = (String)mProperties.get(sProfileID + PROPERTY_METADATA_HTTP_URL);
	                String sMetadataTimeout = (String)mProperties.get(sProfileID + PROPERTY_METADATA_HTTP_TIMEOUT);
	                String sMetadataFile = (String)mProperties.get(sProfileID + METADATA_FILE);
	                _sMetadata = (String)mProperties.get(sProfileID + METADATA);
	                
	                List<MetadataProvider> listMetadataProviders = 
	                    readMetadataProviders(sMetadataURL, sMetadataTimeout, sMetadataFile, _sMetadata, oMPM);
	    			
	    			if (!listMetadataProviders.isEmpty()) {
	        			// Use the first one:
	    				oMP = listMetadataProviders.get(0);
	    				_logger.info("MetadataProviders was be established for "+_sID);
	    			} else {
	    				_logger.info("No MetadataProviders could be established for "+_sID);
	    			}
	    		}
	        	
	        	_oMetadataProvider = oMP;
	        	
	        } else {
	        	_oMetadataProvider = oMetadataProvider;
	        }
    	} catch (OAException oae) {
    		_logger.error("Exception when initializing MetadataProvider: "+oae.getMessage());
    		throw oae;
        } catch(Exception e) {
            _logger.fatal("Internal error while reading SAML2 attributes for requestor: " 
                + oRequestor.getID(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
        

    /**
     * Helper to initialize local instance from provided requestor properties
     * @param oRequestor
     * @param bSigning
     * @param sProfileID
     * @throws OAException
     */
    protected void initFromProperties(Map<?,?> mProperties, boolean bSigning, String sProfileID)
    	throws OAException
    {
        _bSigning = false;
        String sSigning = (String)mProperties.get(sProfileID + PROPERTY_SIGNING);
        if (sSigning == null) {
            _bSigning = bSigning;
            if (_logger.isDebugEnabled()) {
                _logger.debug("No optional '"+sProfileID+PROPERTY_SIGNING+"' property found for requestor '"+
                				_sID+"'; Using default value: "+_bSigning);
            }
        } else {
            if (sSigning.equalsIgnoreCase("TRUE")) {
                _bSigning = true;
            } else if (!sSigning.equalsIgnoreCase("FALSE")) {
                _logger.error("Invalid '"+sProfileID+PROPERTY_SIGNING+"' property found for requestor '"+
                				_sID+"'; Invalid value: "+sSigning);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
    }
    
    
    /**
     * Returns the OA Request ID. 
     * @return String with the Request ID.
     */
    public String getID()
    {
        return _sID;
    }
    
    /**
     * Returns the requestor specific ChainingMetadataProvider.
     *
     * @return the ChainingMetadataProvider or <code>null</code> if no provider 
     * is configured.
     */
    public MetadataProvider getMetadataProvider()
    {
        return _oMetadataProvider;
    }
    
    /**
     * Returns TRUE if requests from this Requestor must be signed.
     * 
     * @return TRUE if signing is required for this requestor.
     */
    public boolean isSigningEnabled()
    {
        return _bSigning;
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        StringBuffer sbInfo = new StringBuffer();
        sbInfo.append("Requestor '");
        sbInfo.append(_sID);
        sbInfo.append("'");
        sbInfo.append(": ");
        
        if (_fMetadata != null)
        {
            sbInfo.append("[");
            sbInfo.append(_fMetadata.getAbsolutePath());
            sbInfo.append("]");
        }
        
        if (_sMetadataURL != null)
        {
            sbInfo.append("[");
            sbInfo.append(_sMetadataURL);
            sbInfo.append("]");
        }
        return sbInfo.toString();
    }
    
    private List<MetadataProvider> readMetadataProviders(
        IConfigurationManager configurationManager, 
        Element config, IMetadataProviderManager oMPM) throws OAException
    {
        List<MetadataProvider> lMetadataProviders = new Vector<MetadataProvider>();
        
        try {
            BasicParserPool parserPool = new BasicParserPool();
            parserPool.setNamespaceAware(true);
            
            MetadataProvider fileProvider = readFileMetadataProvider(
                    configurationManager, config, parserPool, oMPM);
            if (fileProvider != null) {
                lMetadataProviders.add(fileProvider);
                _logger.info("Using File Provider Metadata: " + _fMetadata.getName());
            }
            
            MetadataProvider oURLProvider = 
                readHTTPMetadataProvider(
                    configurationManager, config, parserPool, oMPM);
            if (oURLProvider != null) {
                lMetadataProviders.add(oURLProvider);
                _logger.info("Using HTTP Provider Metadata: " + _sMetadataURL);
            }
            
            MetadataProvider domProvider = readDOMMetadataProvider(configurationManager, config, parserPool);
            if (domProvider != null) {
            	lMetadataProviders.add(domProvider);
            	_logger.debug("Using static DOM Metadata Provider");
            }

        } catch (OAException e) {
            throw e;
        } catch(Exception e) {
            _logger.fatal("Internal error while creating metadata providers", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }   
        
        return lMetadataProviders;
    }

    
    private MetadataProvider readHTTPMetadataProvider(
        IConfigurationManager configurationManager, Element config,
        ParserPool parserPool, IMetadataProviderManager oMPM) 
        throws OAException
    {
        MetadataProvider oProvider = null;
        
        Element eHttp = configurationManager.getSection(config, "http");
        if (eHttp == null) {
            _logger.warn("No optional 'http' section in 'metadata' section found in configuration for requestor with id: " 
                + _sID);
            return null;
        }
        
        _sMetadataURL = configurationManager.getParam(eHttp, "url");
        if (_sMetadataURL == null) {
            _logger.error("No 'url' item in 'http' section found in configuration for requestor with id: " 
                + _sID);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
                    
        // Check URL format
        URL oURLTarget = null;
        try {
            oURLTarget = new URL(_sMetadataURL);
        } catch (MalformedURLException e) {
            _logger.error("Invalid 'url' item in 'http' section found in configuration: " 
                + _sMetadataURL, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        // Establish optional configurable connection timeout setting
        _iMetadataURLTimeout = 0;	// default
        String sTimeout = configurationManager.getParam(eHttp, "timeout");
        if (sTimeout != null) {
            try {
                _iMetadataURLTimeout = Integer.parseInt(sTimeout);
            } catch (NumberFormatException e) {
                _logger.error("Invalid 'timeout' item in 'http' section found in configuration (must be a number): " 
                    + sTimeout, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        
        // Check valid and existing destination (with configured timeout settings)
        try {
            URLConnection oURLConnection = oURLTarget.openConnection();
            if (_iMetadataURLTimeout == 0) {
	            oURLConnection.setConnectTimeout(3000);
	            oURLConnection.setReadTimeout(3000);
            } else {
            	oURLConnection.setConnectTimeout(_iMetadataURLTimeout);
	            oURLConnection.setReadTimeout(_iMetadataURLTimeout);
            }
            
            oURLConnection.connect();
        } catch (IOException e) {
            _logger.warn("Could not connect to metadata url: " + _sMetadataURL +
            		"(using timout "+(_iMetadataURLTimeout==0?"3000":_iMetadataURLTimeout) +"ms)", e);
        }

        // Establish dedicated refresh timer:
        Timer oRefreshTimer = new Timer("Metadata_SP-"+_sID+"-Timer", true);
        
        // Establish HttpClient
    	HttpClient oHttpClient = new HttpClient();
        
        if (_iMetadataURLTimeout > 0) {
            // Set configured Timeout settings
        	oHttpClient.getParams().setSoTimeout(_iMetadataURLTimeout);
        }
        
    	oProvider = MetadataProviderUtil.createProviderForURL(_sMetadataURL, parserPool, 
    			oRefreshTimer, oHttpClient);
        
    	// Start managing it:
    	if (oMPM != null) {
    		oMPM.setProviderFor(_sID, oProvider, oRefreshTimer);
    	}
    	
        return oProvider;
    }
    
    
    private MetadataProvider readFileMetadataProvider(
        IConfigurationManager configurationManager, Element config,
        ParserPool parserPool, IMetadataProviderManager oMPM) 
        throws OAException
    {
        MetadataProvider oProvider = null;
        String sFile = configurationManager.getParam(config, "file");
        if (sFile == null) {
            _logger.warn("No optional 'file' item in 'metadata' section found in configuration for requestor with id: " 
                + _sID);
            return null;
        }
        
    	// Establish real filename (filter virtual mounts)
    	sFile = PathTranslator.getInstance().map(sFile);
    	
    	// Check whether file exists
        _fMetadata = new File(sFile);
        if (!_fMetadata.exists()) {
            _logger.error("Configured metadata 'file' doesn't exist: " + sFile);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        // Establish dedicated refresh timer:
        Timer oRefreshTimer = new Timer("Metadata_SP-"+_sID+"-Timer", true);
        
    	oProvider = MetadataProviderUtil.createProviderForFile(sFile, parserPool, 
    			oRefreshTimer);
        
    	// Start managing it:
    	if (oMPM != null) {
    		oMPM.setProviderFor(_sID, oProvider, oRefreshTimer);
    	}

        return oProvider;
    }
    
    
    private MetadataProvider readDOMMetadataProvider(IConfigurationManager configurationManager, Element config,
    		ParserPool parserPool) 
        throws OAException
    {
    	String sRawMetadata = configurationManager.getParam(config, "raw");
        if (sRawMetadata == null) {
            _logger.warn("No optional 'raw' item in 'metadata' section found in configuration "+
            				" for requestor with id: "+ _sID);
            return null;
        } else {
        	_sMetadata = sRawMetadata;
        	return readDOMMetadataProvider(_sMetadata, parserPool);
        }
    }
    
    
    private List<MetadataProvider> readMetadataProviders(String sMetadataURL,
        String sMetadataTimeout, String sMetadataFile, String sMetadata,
        IMetadataProviderManager oMPM) throws OAException
    {
        List<MetadataProvider> lMetadataProviders = new Vector<MetadataProvider>();
        try {
            BasicParserPool parserPool = new BasicParserPool();
            parserPool.setNamespaceAware(true);
                        
            MetadataProvider fileProvider = 
                readFileMetadataProvider(sMetadataFile, parserPool, oMPM);
            if (fileProvider != null) {
                lMetadataProviders.add(fileProvider);
                _logger.debug("Using File Provider Metadata: " + _fMetadata.getName());
            }
            
            MetadataProvider urlProvider = 
                readHTTPMetadataProvider(sMetadataURL, sMetadataTimeout, parserPool, oMPM);
            if (urlProvider != null) {
                lMetadataProviders.add(urlProvider);
                _logger.debug("Using HTTP Provider Metadata: " + _sMetadataURL);
            }
            
            MetadataProvider domProvider = readDOMMetadataProvider(_sMetadata, parserPool);
            if (domProvider != null) {
            	lMetadataProviders.add(domProvider);
            	_logger.debug("Using static DOM Metadata Provider");
            }
        } catch (OAException e) {
            throw e;
        } catch(Exception e) {
            _logger.fatal("Internal error while creating metadata providers", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }   
        
        return lMetadataProviders;
    }

    private MetadataProvider readHTTPMetadataProvider(String sMetadataURL,
        String sMetadataTimeout, ParserPool parserPool, IMetadataProviderManager oMPM) 
        throws OAException
    {
        MetadataProvider oProvider = null;
        
        if (sMetadataURL == null) {
            _logger.debug("No optional metadata url configured for requestor with id: " + _sID);
            return null;
        }
        
        _sMetadataURL = sMetadataURL;
        
        // Check URL format
        URL oURLTarget = null;
        try {
            oURLTarget = new URL(_sMetadataURL);
        } catch (MalformedURLException e) {
            _logger.error("Invalid 'url' item in 'http' section found in configuration: " 
                + _sMetadataURL, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        // Establish optional configurable connection timeout setting
        _iMetadataURLTimeout = 0;	// default
        if (sMetadataTimeout != null) {
            try {
                _iMetadataURLTimeout = Integer.parseInt(sMetadataTimeout);
            } catch (NumberFormatException e) {
                _logger.debug("Invalid metadata timeout configured (must be a number): " 
                    + sMetadataTimeout, e);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        
        // Check valid and existing destination (with configured timeout settings)
        try {
            URLConnection oURLConnection = oURLTarget.openConnection();
            if (_iMetadataURLTimeout == 0) {
	            oURLConnection.setConnectTimeout(3000);
	            oURLConnection.setReadTimeout(3000);
            } else {
            	oURLConnection.setConnectTimeout(_iMetadataURLTimeout);
	            oURLConnection.setReadTimeout(_iMetadataURLTimeout);
            }
            
            oURLConnection.connect();
        } catch (IOException e) {
            _logger.warn("Could not connect to metadata url: " + _sMetadataURL +
            		"(using timout "+(_iMetadataURLTimeout==0?"3000":_iMetadataURLTimeout) +"ms)", e);
        }

        // Establish dedicated refresh timer:
        Timer oRefreshTimer = new Timer("Metadata_SP-"+_sID+"-Timer", true);
        
        // Establish HttpClient
    	HttpClient oHttpClient = new HttpClient();
        
        if (_iMetadataURLTimeout > 0) {
            // Set configured Timeout settings
        	oHttpClient.getParams().setSoTimeout(_iMetadataURLTimeout);
        }
        
    	oProvider = MetadataProviderUtil.createProviderForURL(_sMetadataURL, parserPool, 
    			oRefreshTimer, oHttpClient);
        
    	// Start managing it:
    	if (oMPM != null) {
    		oMPM.setProviderFor(_sID, oProvider, oRefreshTimer);
    	}

        return oProvider;
    }
    
    
    private MetadataProvider readFileMetadataProvider(
        String sMetadataFile, ParserPool oParserPool, IMetadataProviderManager oMPM) 
        throws OAException
    {
        MetadataProvider oProvider = null;
        if (sMetadataFile == null) {
            _logger.debug("No optional metadata file configured for requestor with id: " + _sID);
            return null;
        }

        // Establish real filename (filter virtual mounts)
    	sMetadataFile = PathTranslator.getInstance().map(sMetadataFile);

    	// Check whether file exists
        _fMetadata = new File(sMetadataFile);
        if (!_fMetadata.exists()) {
            _logger.error("Configured metadata 'file' doesn't exist: " + sMetadataFile);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        // Establish dedicated refresh timer:
        Timer oRefreshTimer = new Timer("Metadata_SP-"+_sID+"-Timer", true);
        
    	oProvider = MetadataProviderUtil.createProviderForFile(sMetadataFile, oParserPool, 
    			oRefreshTimer);
        
    	// Start managing it:
    	if (oMPM != null) {
    		oMPM.setProviderFor(_sID, oProvider, oRefreshTimer);
    	}

        return oProvider;
    }
    
    
    /**
     * Create a MetadataProvider based on the static XML document of the entity
     * @param sMetadata Metadata of the entity to create provider for
     * @param oParserPool
     * @return Initialized MetadataProvider for the provided metadata
     */
    private MetadataProvider readDOMMetadataProvider(String sMetadata, 
    		ParserPool oParserPool) 
    {
    	if (sMetadata == null) return null;
    	
		try {
			Document d = XMLUtils.getDocumentFromString(sMetadata);
			Element elMetadata = d.getDocumentElement();
			
	    	DOMMetadataProvider oProvider = new DOMMetadataProvider(elMetadata);
	    	oProvider.setParserPool(oParserPool);
	    	
	    	return oProvider;
		} catch (OAException e) {
			_logger.warn("Could not parse provided metadata document.");
		}
		
		return null;
    }

}
