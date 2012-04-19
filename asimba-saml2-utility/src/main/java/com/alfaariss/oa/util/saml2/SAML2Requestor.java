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
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.utility.filesystem.PathTranslator;
import org.opensaml.saml2.metadata.provider.ChainingMetadataProvider;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
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
     * Signing mandatory.
     */
    protected boolean _bSigning;
   
    /**
     * Metadata Provider.
     */
    protected ChainingMetadataProvider _chainingMetadataProvider;

    private final static long serialVersionUID = 2093412253512956567L;
    
    private final static String PROPERTY_SIGNING = ".signing";
    private final static String PROPERTY_METADATA_HTTP_TIMEOUT = ".metadata.http.timeout";
    private final static String PROPERTY_METADATA_HTTP_URL = ".metadata.http.url";
    private final static String METADATA_FILE = ".metadata.file";
    
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
        Element config, boolean bSigning) throws OAException
    {
        _logger = LogFactory.getLog(SAML2Requestor.class);
        try
        {
            _sID = configurationManager.getParam(config, "id");
            if (_sID == null)
            {
                _logger.error(
                    "No 'id' item found in 'requestor' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _bSigning = false;
            String sSigning = configurationManager.getParam(config, "signing");
            if (sSigning == null)
            {
                _logger.warn(
                    "No optional 'signing' item found in configuration for requestor with id: " 
                    + _sID);
                _bSigning = bSigning;
            }
            else
            {
                if (sSigning.equalsIgnoreCase("TRUE"))
                    _bSigning = true;
                else if (!sSigning.equalsIgnoreCase("FALSE"))
                {
                    _logger.error(
                        "Invalid 'signing' item found in configuration (must be true or false) for requestor with id: "
                        + _sID);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            _chainingMetadataProvider = null;
            _sMetadataURL = null;
            _fMetadata = null;
            _iMetadataURLTimeout = HTTP_METADATA_REQUEST_TIMEOUT;
            
            Element eMetadata = configurationManager.getSection(config, "metadata");
            if (eMetadata != null)
            {
                List<MetadataProvider> listMetadataProviders = 
                    readMetadataProviders(configurationManager, eMetadata);
                if (!listMetadataProviders.isEmpty())
                {
                    _chainingMetadataProvider = new ChainingMetadataProvider();
                    _chainingMetadataProvider.setProviders(listMetadataProviders);
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
            _bSigning = false;
            String sSigning = (String)mProperties.get(sProfileID + PROPERTY_SIGNING);
            if (sSigning == null)
            {
                _bSigning = bSigning;
                if (_logger.isDebugEnabled())
                {
                    StringBuffer sbDebug = new StringBuffer("No optional '");
                    sbDebug.append(sProfileID);
                    sbDebug.append(PROPERTY_SIGNING);
                    sbDebug.append("' property found for requestor with id '");
                    sbDebug.append(_sID);
                    sbDebug.append("'; Using default value: ");
                    sbDebug.append(_bSigning);
                    _logger.debug(sbDebug.toString());
                }
            }
            else
            {
                if (sSigning.equalsIgnoreCase("TRUE"))
                    _bSigning = true;
                else if (!sSigning.equalsIgnoreCase("FALSE"))
                {
                    StringBuffer sbError = new StringBuffer("Invalid '");
                    sbError.append(sProfileID);
                    sbError.append(PROPERTY_SIGNING);
                    sbError.append("' property found for requestor with id '");
                    sbError.append(_sID);
                    sbError.append("'; Invalid value: ");
                    sbError.append(sSigning);
                    
                    _logger.error(sbError.toString());
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
            }
            
            _chainingMetadataProvider = null;
            _sMetadataURL = null;
            _fMetadata = null;
            _iMetadataURLTimeout = HTTP_METADATA_REQUEST_TIMEOUT;
            
            String sMetadataURL = (String)mProperties.get(sProfileID + PROPERTY_METADATA_HTTP_URL);
            String sMetadataTimeout = (String)mProperties.get(sProfileID + PROPERTY_METADATA_HTTP_TIMEOUT);
            String sMetadataFile = (String)mProperties.get(sProfileID + METADATA_FILE);
            
            List<MetadataProvider> listMetadataProviders = 
                readMetadataProviders(sMetadataURL, sMetadataTimeout, sMetadataFile);
            if (!listMetadataProviders.isEmpty())
            {
                _chainingMetadataProvider = new ChainingMetadataProvider();
                _chainingMetadataProvider.setProviders(listMetadataProviders);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error while reading SAML2 attributes for requestor: " 
                + requestor.getID(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
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
    public ChainingMetadataProvider getChainingMetadataProvider()
    {
        return _chainingMetadataProvider;
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
        Element config) throws OAException
    {
        List<MetadataProvider> listMetadataProviders = 
            new Vector<MetadataProvider>();
        try
        {
            BasicParserPool parserPool = new BasicParserPool();
            parserPool.setNamespaceAware(true);
            
            FilesystemMetadataProvider fileProvider = 
                readFileMetadataProvider(
                    configurationManager, config, parserPool);
            if (fileProvider != null)
            {
                listMetadataProviders.add(fileProvider);
                _logger.info(
                    "Using File Provider Metadata: " + _fMetadata.getName());
            }
            
            HTTPMetadataProvider urlProvider = 
                readHTTPMetadataProvider(
                    configurationManager, config, parserPool);
            if (urlProvider != null)
            {
                listMetadataProviders.add(urlProvider);
                _logger.info(
                    "Using HTTP Provider Metadata: " + _sMetadataURL);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error while creating metadata providers", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }   
        
        return listMetadataProviders;
    }

    private HTTPMetadataProvider readHTTPMetadataProvider(
        IConfigurationManager configurationManager, Element config,
        ParserPool parserPool) 
        throws OAException
    {
        HTTPMetadataProvider urlProvider = null;
        
        Element eHttp = configurationManager.getSection(config, "http");
        if (eHttp == null)
        {
            _logger.warn(
                "No optional 'http' section in 'metadata' section found in configuration for requestor with id: " 
                + _sID);
        }
        else
        {
            _sMetadataURL = configurationManager.getParam(eHttp, "url");
            if (_sMetadataURL == null)
            {
                _logger.error(
                    "No 'url' item in 'http' section found in configuration for requestor with id: " 
                    + _sID);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
                        
            URL urlTarget = null;
            try
            {
                urlTarget = new URL(_sMetadataURL);
            }
            catch (MalformedURLException e)
            {
                _logger.error(
                    "Invalid 'url' item in 'http' section found in configuration: " 
                    + _sMetadataURL, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            try
            {
                URLConnection urlConnection = urlTarget.openConnection();
                urlConnection.setConnectTimeout(3000);
                urlConnection.setReadTimeout(3000);
                urlConnection.connect();
            }
            catch (IOException e)
            {
                _logger.warn(
                    "Could not connect to 'url' item in 'http' section found in configuration: " 
                    + _sMetadataURL, e);
            }
                        
            String sTimeout = configurationManager.getParam(eHttp, "timeout");
            if (sTimeout != null)
            {
                try
                {
                    _iMetadataURLTimeout = Integer.parseInt(sTimeout);
                }
                catch (NumberFormatException e)
                {
                    _logger.error(
                        "Invalid 'timeout' item in 'http' section found in configuration (must be a number): " 
                        + sTimeout, e);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            try
            {
                urlProvider = new HTTPMetadataProvider(_sMetadataURL, 
                    _iMetadataURLTimeout);
                urlProvider.setParserPool(parserPool);
                urlProvider.initialize();
            }
            catch (MetadataProviderException e)
            {
                StringBuffer sbWarn = new StringBuffer();
                sbWarn.append("No metadata available at configured URL '");
                sbWarn.append(_sMetadataURL);
                sbWarn.append("': Disabling http metadata for this requestor");
                
                _logger.warn(sbWarn.toString(), e);
                
                urlProvider = null;
            }
        }
        return urlProvider;
    }
    
    private FilesystemMetadataProvider readFileMetadataProvider(
        IConfigurationManager configurationManager, Element config,
        ParserPool parserPool) 
        throws OAException
    {
        FilesystemMetadataProvider fileProvider = null;
        String sFile = configurationManager.getParam(config, "file");
        if (sFile == null)
        {
            _logger.warn(
                "No optional 'file' item in 'metadata' section found in configuration for requestor with id: " 
                + _sID);
        }
        else
        {
        	// Establish real filename (filter virtual mounts)
        	sFile = PathTranslator.getInstance().map(sFile);
        	
            _fMetadata = new File(sFile);
            if (!_fMetadata.exists())
            {
                _logger.error("Configured metadata 'file' doesn't exist: " 
                    + sFile);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            try
            {
                fileProvider = new FilesystemMetadataProvider(_fMetadata);
            }
            catch (MetadataProviderException e)
            {
                _logger.error("No metadata available in configured file: " 
                    + sFile, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            fileProvider.setParserPool(parserPool);
            try
            {
                fileProvider.initialize();
            }
            catch (MetadataProviderException e)
            {
                _logger.error("No metadata available in configured file: " 
                    + sFile, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        return fileProvider;
    }
    
    private List<MetadataProvider> readMetadataProviders(String sMetadataURL,
        String sMetadataTimeout, String sMetadataFile) throws OAException
    {
        List<MetadataProvider> listMetadataProviders = 
            new Vector<MetadataProvider>();
        try
        {
            BasicParserPool parserPool = new BasicParserPool();
            parserPool.setNamespaceAware(true);
                        
            FilesystemMetadataProvider fileProvider = 
                readFileMetadataProvider(sMetadataFile, parserPool);
            if (fileProvider != null)
            {
                listMetadataProviders.add(fileProvider);
                _logger.debug(
                    "Using File Provider Metadata: " + _fMetadata.getName());
            }
            
            HTTPMetadataProvider urlProvider = 
                readHTTPMetadataProvider(sMetadataURL, sMetadataTimeout, parserPool);
            if (urlProvider != null)
            {
                listMetadataProviders.add(urlProvider);
                _logger.debug(
                    "Using HTTP Provider Metadata: " + _sMetadataURL);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error while creating metadata providers", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }   
        
        return listMetadataProviders;
    }

    private HTTPMetadataProvider readHTTPMetadataProvider(String sMetadataURL,
        String sMetadataTimeout, ParserPool parserPool) 
        throws OAException
    {
        HTTPMetadataProvider urlProvider = null;
        
        if (sMetadataURL == null)
        {
            _logger.debug(
                "No optional metadata url configured for requestor with id: " 
                + _sID);
        }
        else
        {
            _sMetadataURL = sMetadataURL;
            
            URL urlTarget = null;
            try
            {
                urlTarget = new URL(_sMetadataURL);
            }
            catch (MalformedURLException e)
            {
                _logger.error(
                    "Invalid 'url' item in 'http' section found in configuration: " 
                    + _sMetadataURL, e);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            try
            {
                URLConnection urlConnection = urlTarget.openConnection();
                urlConnection.setConnectTimeout(3000);
                urlConnection.setReadTimeout(3000);
                urlConnection.connect();
            }
            catch (IOException e)
            {
                _logger.warn(
                    "Could not connect to metadata url: " + _sMetadataURL, e);
            }
            
            if (sMetadataTimeout != null)
            {
                try
                {
                    _iMetadataURLTimeout = Integer.parseInt(sMetadataTimeout);
                }
                catch (NumberFormatException e)
                {
                    _logger.debug(
                        "Invalid metadata timeout configured (must be a number): " 
                        + sMetadataTimeout, e);
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
            }

            try
            {
                urlProvider = new HTTPMetadataProvider(_sMetadataURL, 
                    _iMetadataURLTimeout);
                urlProvider.setParserPool(parserPool);
                urlProvider.initialize();
            }
            catch (MetadataProviderException e)
            {
                StringBuffer sbDebug = new StringBuffer();
                sbDebug.append("No metadata available at configured URL '");
                sbDebug.append(_sMetadataURL);
                sbDebug.append("': Disabling http metadata for this requestor");
                _logger.debug(sbDebug.toString(), e);
                
                urlProvider = null;
            }
        }
        return urlProvider;
    }
    
    private FilesystemMetadataProvider readFileMetadataProvider(
        String sMetadataFile, ParserPool parserPool) 
        throws OAException
    {
        FilesystemMetadataProvider fileProvider = null;
        if (sMetadataFile == null)
        {
            _logger.debug(
                "No optional metadata file configured for requestor with id: " 
                + _sID);
        }
        else
        {
        	// Establish real filename (filter virtual mounts)
        	sMetadataFile = PathTranslator.getInstance().map(sMetadataFile);

            _fMetadata = new File(sMetadataFile);
            if (!_fMetadata.exists())
            {
                _logger.error("Configured metadata 'file' doesn't exist: " 
                    + sMetadataFile);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            try
            {
                fileProvider = new FilesystemMetadataProvider(_fMetadata);
            }
            catch (MetadataProviderException e)
            {
                _logger.error("No metadata available in configured file: " 
                    + sMetadataFile, e);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            fileProvider.setParserPool(parserPool);
            try
            {
                fileProvider.initialize();
            }
            catch (MetadataProviderException e)
            {
                _logger.error("No metadata available in configured file: " 
                    + sMetadataFile, e);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        return fileProvider;
    }

}
