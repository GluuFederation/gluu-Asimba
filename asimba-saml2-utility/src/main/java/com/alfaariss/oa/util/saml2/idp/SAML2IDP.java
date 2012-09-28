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
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;
import java.util.Vector;

import org.opensaml.saml2.metadata.provider.ChainingMetadataProvider;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;

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
        Boolean useScoping, Boolean useNameIDPolicy, String forceNameIDFormat) 
        throws OAException
    {
        super(sID, sFriendlyName);
        
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
     * Returns a chaining metadata provider with the metadata of the organization.
     * <br>
     * The provider contains the file and url metadata of the organization if 
     * available and creates the metadata provider everytime this method is 
     * called.
     * 
     * @return The MetadataProvider (ChainingMetadataProvider) with the metadata 
     * for this organization or NULL when no metadata is available.
     * @throws OAException If metadata is invalid or could not be accessed
     */
    public MetadataProvider getMetadataProvider() throws OAException
    {
        ChainingMetadataProvider chainingMetadataProvider = null;
        
        try
        {
            BasicParserPool parserPool = new BasicParserPool();
            parserPool.setNamespaceAware(true);
            
            List<MetadataProvider> listMetadataProviders = 
                new Vector<MetadataProvider>();
            
            MetadataProvider mpFile = createFileMetadataProvider(_sMetadataFile, 
                parserPool);
            if (mpFile != null)
                listMetadataProviders.add(mpFile);
            
            MetadataProvider mpHttp = createHTTPMetadataProvider(_sMetadataURL, 
                _iMetadataTimeout, parserPool);
            if (mpHttp != null)
                listMetadataProviders.add(mpHttp);
            
            if (!listMetadataProviders.isEmpty())
            {
                chainingMetadataProvider = new ChainingMetadataProvider();
                chainingMetadataProvider.setProviders(listMetadataProviders);
            }
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
        return chainingMetadataProvider;
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

    private HTTPMetadataProvider createHTTPMetadataProvider(String sMetadataURL,
        int iMetadataTimeout, ParserPool parserPool) 
        throws OAException
    {
        HTTPMetadataProvider urlProvider = null;
        
        if (sMetadataURL == null)
        {
            return null;
        }
          
        URL urlTarget = null;
        try
        {
            urlTarget = new URL(sMetadataURL);
        }
        catch (MalformedURLException e)
        {
            _logger.error(
                "Invalid 'url' item in 'http' section found in configuration: " 
                + sMetadataURL, e);
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
                "Could not connect to metadata url: " + sMetadataURL, e);
        }
        
        try
        {
            urlProvider = new HTTPMetadataProvider(sMetadataURL, 
                iMetadataTimeout);
            urlProvider.setParserPool(parserPool);
            urlProvider.initialize();
        }
        catch (MetadataProviderException e)
        {
            StringBuffer sbDebug = new StringBuffer();
            sbDebug.append("No metadata available at configured URL '");
            sbDebug.append(sMetadataURL);
            sbDebug.append("': Disabling http metadata for this IDP");
            _logger.warn(sbDebug.toString(), e);
            
            urlProvider = null;
        }

        return urlProvider;
    }
    
    private FilesystemMetadataProvider createFileMetadataProvider(
        String sMetadataFile, ParserPool parserPool) 
        throws OAException
    {
        FilesystemMetadataProvider fileProvider = null;
        if (sMetadataFile == null)
        {
            return null;
        }

        File fMetadata = new File(sMetadataFile);
        if (!fMetadata.exists())
        {
            _logger.error("Configured metadata 'file' doesn't exist: " 
                + sMetadataFile);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        try
        {
            fileProvider = new FilesystemMetadataProvider(fMetadata);
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
        return fileProvider;
    }
}
