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
package com.alfaariss.oa.util.saml2.idp;

import java.io.File;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Date;
import java.util.Timer;

import org.apache.commons.httpclient.HttpClient;
import org.asimba.util.saml2.metadata.provider.IMetadataProviderManager;
import org.asimba.util.saml2.metadata.provider.MetadataProviderUtil;
import org.asimba.util.saml2.metadata.provider.XMLObjectMetadataProvider;
import org.asimba.utility.filesystem.PathTranslator;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.XMLObjectHelper;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.engine.core.idp.storage.AbstractIDP;

/**
 * SAML2 remote organization object.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.1
 */
public class SAML2IDP extends AbstractIDP
	implements Serializable
{
    
    /** Type: id */
    public final static String TYPE_ID = "id";
    /** Type: sourceid */
    public final static String TYPE_SOURCEID = "sourceid";
    
    private static final long serialVersionUID = -3291910972515606397L;

    private static final int HTTP_METADATA_REQUEST_TIMEOUT = 5000;
    
    private byte[] _baSourceID;
    private String _sMetadataFile;
    private String _sMetadataURL;
    private int _iMetadataTimeout;
    private Boolean _boolACSIndex;
    private Boolean _boolScoping;
    private Boolean _boolNameIDPolicy;
    private Boolean _boolAllowCreate;    
    private String _sNameIDFormat;
    
    /** When set, MetadataProvider is/must be managed through _oMPM */
    transient private IMetadataProviderManager _oMPM;
    
    /**
     * Element containing the parsed XMLObject of the metadata document
     * 
     * Does not serialize, so marshall to _sMetadata upon serialization
     */
    transient protected XMLObject _oMetadataXMLObject = null;
    
    /**
     * Keep reference to MetadataProvider for this IDP
     * 
     * Does not serialize, so it is lost whenever it has been resuscitated
     */
    transient protected MetadataProvider _oMetadataProvider = null;
    
    /**
     * Contains the string version of the XMLObject's metadata
     * Only used for transit, so object instance can be serialized, so
     * will be set before serializing, and will be set when un-serialized from instance
     *   that was serialized before 
     */
    protected String _sMetadata = null;
    
    
    /**
     * Creates an organization object.
     *
     * @param sID The id of the organization
     * @param baSourceID the SourceID of the organization
     * @param sFriendlyName the organization friendly name
     * @param sMetadataFile The location of the metadata file or NULL if none 
     * @param sMetadataURL The url of the metadata or NULL if none
     * @param iMetadataTimeout The timeout to be used in connecting the the url 
     * metadata or -1 when default must be used
     * @param useACSIndex TRUE if ACS should be set as Index
     * @param useAllowCreate AllowCreate value or NULL if disabled
     * @param useScoping TRUE if Scoping element must be send
     * @param useNameIDPolicy TRUE if NameIDPolicy element must be send
     * @param forceNameIDFormat The NameIDFormat to be set in the NameIDPolicy 
     * or NULL if resolved from metadata
     * @throws OAException if invalid data supplied
     */
    public SAML2IDP(String sID, byte[] baSourceID, String sFriendlyName,
        String sMetadataFile, String sMetadataURL, 
        int iMetadataTimeout, Boolean useACSIndex, Boolean useAllowCreate, 
        Boolean useScoping, Boolean useNameIDPolicy, String forceNameIDFormat,
        Date dLastModified, IMetadataProviderManager oMPM) 
        		throws OAException
    {
        super(sID, sFriendlyName, dLastModified);
        
        _baSourceID = baSourceID;
        _sMetadataFile = sMetadataFile;
        if (_sMetadataFile != null)
        {
            File fMetadata = new File(_sMetadataFile);
            if (!fMetadata.exists())
            {
                StringBuffer sbError = new StringBuffer("Supplied metadata file for organization '" );
                sbError.append(_sID);
                sbError.append("' doesn't exist: ");
                sbError.append(_sMetadataFile);
                _logger.error(sbError.toString());
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        
        _sMetadataURL = sMetadataURL;
        if (_sMetadataURL != null)
        {
            try
            {
                new URL(_sMetadataURL);
            }
            catch (MalformedURLException e)
            {
                StringBuffer sbError = new StringBuffer("Invalid metadata URL supplied for organization '" );
                sbError.append(_sID);
                sbError.append("': ");
                sbError.append(_sMetadataURL);
                _logger.error(sbError.toString(), e);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        
        _iMetadataTimeout = iMetadataTimeout;
        if (_iMetadataTimeout < 0)
        {
            _iMetadataTimeout = HTTP_METADATA_REQUEST_TIMEOUT;
            
            StringBuffer sbDebug = new StringBuffer("Supplied HTTP metadata timeout for organization '" );
            sbDebug.append(_sID);
            sbDebug.append("' is smaller then zero, using default: ");
            sbDebug.append(_iMetadataTimeout);
            _logger.debug(sbDebug.toString());
        }
        
        _boolACSIndex = useACSIndex;
        _boolScoping = useScoping;
        _boolNameIDPolicy = useNameIDPolicy;
        _boolAllowCreate = useAllowCreate;
        _sNameIDFormat = forceNameIDFormat;
        
        // Keep reference to MetadataProviderManager as it was passed
        _oMPM = oMPM;
    }
    
    /**
     * Returns the SourceID of the organization.
     * @return the source id
     */
    public byte[] getSourceID()
    {
        return _baSourceID;
    }
    
    
    /**
     * Return whether the SAML2IDP is initialized with a MetadataProvider
     * @return
     */
    public boolean isMetadataProviderSet() {
    	return (_oMetadataProvider != null);
    }
    
    /**
     * Set MetadataProvider for this SAML2IDP
     * Note: no responsibility is taken for managing it; must have been taken care of
     * @param oMetadataProvider
     */
    public void setMetadataProvider(MetadataProvider oMetadataProvider) {
    	_oMetadataProvider = oMetadataProvider;
    	
    	// Reset context:
    	try {
        	_sMetadata = null;
			_oMetadataXMLObject = oMetadataProvider.getMetadata();
		} catch (MetadataProviderException e) {
			_logger.warn("Could not get Metadata for SAML2IDP '"+getID()+"'");
		}
    }
    
    /**
     * Returns a metadata provider with the metadata of the organization.
     * <br>
     * If the provider was set externally, this provider is returned. <br/>
     * When the SAML2IDP has been serialized/deserialized, a MetadataProvider based
     * on the (static) metadata is returned.
     * Otherwise, a new MetadataProvider is constructed that retrieves its
     * metadata from the configured file- and/or url-source.
     * 
     * @return The initialized MetadataProvider with the metadata 
     * for this organization or NULL when no metadata is available.
     * @throws OAException If metadata is invalid or could not be accessed
     */
    public MetadataProvider getMetadataProvider() throws OAException
    {
    	if (_oMetadataProvider != null) {
    		return _oMetadataProvider;
    	}
    	
    	// If there is a local metadata document available, return the
    	// MetadataProvider that is based on this document
    	if (_oMetadataXMLObject != null) {
    		XMLObjectMetadataProvider oMP = new XMLObjectMetadataProvider(_oMetadataXMLObject);
			oMP.initialize();
			return oMP;
			
    	} else if (_sMetadata != null) {
    		try {
	    		BasicParserPool parserPool = new BasicParserPool();
	            parserPool.setNamespaceAware(true);
	            
	            StringReader oSR = new StringReader(_sMetadata);
            
				_oMetadataXMLObject = XMLObjectHelper.unmarshallFromReader(parserPool, oSR);
				
				XMLObjectMetadataProvider oMP = new XMLObjectMetadataProvider(_oMetadataXMLObject);
				oMP.initialize();
				
				return oMP; 

    		} catch (XMLParserException e) {
				_logger.warn("XMLParser exception with establishing metadata for SAML2IDP, trying file/url: "+e.getMessage());
			} catch (UnmarshallingException e) {
				_logger.warn("Unmarshalling exception with establishing metadata for SAML2IDP, trying file/url: "+e.getMessage());
			}
    	}

    	MetadataProvider oMP = null;
    	
    	// Can we get a managed MetadataProvider?
    	if (_oMPM != null) {
    		oMP = _oMPM.getProviderFor(_sID, _dLastModified);
    		
    		// When successfull, be done.
    		if (oMP != null) {
    			_oMetadataProvider = oMP;
    			return _oMetadataProvider;
    		}
    	}
    	
        try
        {
            BasicParserPool parserPool = new BasicParserPool();
            parserPool.setNamespaceAware(true);

            oMP = createFileMetadataProvider(_sMetadataFile, parserPool, _oMPM);
            if (oMP != null) {
            	_logger.info("Using File MetadataProvider: "+_sMetadataFile);
            	_oMetadataProvider = oMP;
            } else {
	            // No file, try HTTP:
	            oMP = createHTTPMetadataProvider(_sMetadataURL, _iMetadataTimeout, parserPool, _oMPM);
	            if (oMP != null) {
	            	_logger.info("Using HTTP MetadataProvider: "+_sMetadataURL);
	            	_oMetadataProvider = oMP;
	            }
            }
            
            if (_oMetadataProvider == null) {
                _logger.warn("No MetadataProvider could be created for SAML2IDP "+_sID);
                return null;
            }
            
        	return _oMetadataProvider;
         
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error while creating metadata providers", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Indicates whether the ACS location in the AuthnRequest must be an Index.
     * 
     * Values are:
     * <ul>
     * <li>TRUE - AssertionConsumerServiceIndex must be set <b>(default)</b></li>
     * <li>FALSE - AssertionConsumerServiceURL and ProtocolBinding must be set</li>
     * </ul>
     * @return TRUE if the ACS location must be an index.
     * @since 1.2
     */
    public Boolean useACSIndex()
    {
        return _boolACSIndex;
    }
    
    /**
     * Indicates what the value of AllowCreate in the NameIDPolicy of the AuthnRequest must be.
     * 
     * Values are:
     * <ul>
     * <li>NULL - AllowCreate is not send in the AuthnRequest <b>(default unless it's proxied)</b></li>
     * <li>TRUE - AllowCreate=true</li>
     * <li>FALSE - AllowCreate=false</li>
     * </ul>
     * @return the preferred AllowCreate value.
     * @since 1.2
     */
    public Boolean useAllowCreate()
    {
        return _boolAllowCreate;
    }
    
    /**
     * Indicates what the value of Scoping in the AuthnRequest must be.
     * 
     * Values are:
     * <ul>
     * <li>TRUE - Scoping element will be send <b>(default)</b></li>
     * <li>FALSE - Scoping element will not be send </li>
     * </ul>
     * @return TRUE if the Scoping element must be send.
     * @since 1.2
     */
    public Boolean useScoping()
    {
        return _boolScoping;
    }
    
    /**
     * Indicates what the value of NameIDPolicy in the AuthnRequest must be.
     * 
     * Values are:
     * <ul>
     * <li>TRUE - NameIDPolicy element will be send <b>(default)</b></li>
     * <li>FALSE - NameIDPolicy element will not be send </li>
     * </ul>
     * @return TRUE if the NameIDPolicy element must be send.
     * @since 1.2
     */
    public Boolean useNameIDPolicy()
    {
        return _boolNameIDPolicy;
    }
    
    /**
     * Indicates what the value of Format in the NameIDPolicy of the AuthnRequest must be.
     * 
     * Values are:
     * <ul>
     * <li>NULL - The first NameIDFormat in the IdP Metadata should be used OR 
     * no format when a NameIDFormat is not available in that metadata<b>(default)</b></li>
     * <li>NOT NULL - The Format should be overrulen with the configured format</li>
     * </ul>
     * This functionality will only be used when the NameIDPolicy is used.
     * 
     * @return the preferred NameIDFormat value.
     * @since 1.2
     */
    public String getNameIDFormat()
    {
        return _sNameIDFormat;
    }


    /**
     * Set Metadata of the IDP to be the provided (OpenSAML2) parsed XML document
     * @param elMetadataDocument
     */
    public void setMetadataXMLObject(XMLObject oMetadataXMLObject) {
    	_oMetadataXMLObject = oMetadataXMLObject;
    }
    
    
    private MetadataProvider createHTTPMetadataProvider(String sMetadataURL,
        int iMetadataTimeout, ParserPool parserPool, IMetadataProviderManager oMPM) 
        throws OAException
    {
        MetadataProvider oProvider = null;
        
        if (sMetadataURL == null) {
            return null;
        }
        
        // Check URL format
        URL oURLTarget = null;
        try {
            oURLTarget = new URL(sMetadataURL);
        } catch (MalformedURLException e) {
            _logger.error("Invalid 'url' item in 'http' section found in configuration: " 
                + sMetadataURL, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        // Set (configurable) timeout settings
        try {
            URLConnection oURLConnection = oURLTarget.openConnection();
            if (iMetadataTimeout == 0) {
	            oURLConnection.setConnectTimeout(3000);
	            oURLConnection.setReadTimeout(3000);
            } else {
            	oURLConnection.setConnectTimeout(iMetadataTimeout);
	            oURLConnection.setReadTimeout(iMetadataTimeout);
            }
            
            oURLConnection.connect();
        } catch (IOException e) {
            _logger.warn("Could not connect to metadata url: " + _sMetadataURL +
            		"(using timout "+(iMetadataTimeout==0?"3000":iMetadataTimeout) +"ms)", e);
        }
        
        // Establish dedicated refresh timer:
        Timer oRefreshTimer = new Timer("Metadata_IDP-"+_sID+"-Timer", true);
        
        // Establish HttpClient
    	HttpClient oHttpClient = new HttpClient();
        
        if (iMetadataTimeout > 0) {
            // Set configured Timeout settings
        	oHttpClient.getParams().setSoTimeout(iMetadataTimeout);
        }        
        
    	oProvider = MetadataProviderUtil.createProviderForURL(sMetadataURL, parserPool, 
    			oRefreshTimer, oHttpClient);
    	
    	// Start managing it:
    	if (oMPM != null) {
    		oMPM.setProviderFor(_sID, oProvider, oRefreshTimer);
    	}
    	
        return oProvider;
    }
    
    
    private MetadataProvider createFileMetadataProvider(
        String sMetadataFile, ParserPool parserPool, IMetadataProviderManager oMPM) 
        throws OAException
    {
        MetadataProvider oProvider = null;
        if (sMetadataFile == null) {
            return null;
        }

        // Establish real filename (filter virtual mounts)
    	sMetadataFile = PathTranslator.getInstance().map(sMetadataFile);
    	
    	// Check whether file exists
        File fMetadata = new File(sMetadataFile);
        if (!fMetadata.exists()) {
            _logger.error("Configured metadata 'file' doesn't exist: " + sMetadataFile);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        // Establish dedicated refresh timer:
        Timer oRefreshTimer = new Timer("Metadata_IDP-"+_sID+"-Timer", true);
        
    	oProvider = MetadataProviderUtil.createProviderForFile(sMetadataFile, parserPool, 
    			oRefreshTimer);
        
    	// Start managing it:
    	if (oMPM != null) {
    		oMPM.setProviderFor(_sID, oProvider, oRefreshTimer);
    	}
        
        return oProvider;
    }
    
    
    /**
     * Deal with internally stored metadata stuff
     * @param oOutputStream
     */
    private void writeObject(ObjectOutputStream oOutputStream)
    		throws java.io.IOException
    {
		try {
			if (_sMetadata == null) {
				// Create the MetadataXMLObject so we can extract the XML-string from it:
				if (_oMetadataXMLObject == null && _oMetadataProvider != null) {
					_oMetadataXMLObject = _oMetadataProvider.getMetadata();
				}
				
				if (_oMetadataXMLObject != null) {
					StringWriter oSW = new StringWriter();
					XMLObjectHelper.marshallToWriter(_oMetadataXMLObject, oSW);
					_sMetadata = oSW.toString();
				}
			}
		} catch (MarshallingException e) {
			_logger.error("Exception when marshalling XMLObject to Writer for SAML2IDP, dropping metadata: "+e.getMessage());
			return;
		} catch (MetadataProviderException e) {
			_logger.error("Exception when serializing and retrieving Metadata for SAML2IDP '"+_sID+"':" +e.getMessage());
			throw new IOException(e);
		}
		
    	// Do its thing:
    	oOutputStream.defaultWriteObject();
    }
    
    
    // TEST:
    @Override
    public String getFriendlyName() {
    	return super.getFriendlyName();
    }
}
