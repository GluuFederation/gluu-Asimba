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
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.metadata.provider.IMetadataProviderManager;
import org.asimba.util.saml2.metadata.provider.MetadataProviderConfiguration;
import org.asimba.util.saml2.metadata.provider.MetadataProviderUtil;
import org.asimba.util.saml2.metadata.provider.XMLObjectMetadataProvider;
import org.asimba.util.saml2.metadata.provider.management.MdMgrManager;
import org.joda.time.DateTime;
import org.opensaml.saml2.metadata.provider.AbstractReloadingMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.XMLObjectHelper;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.engine.core.idp.storage.AbstractIDP;
import org.gluu.asimba.util.ldap.idp.IDPEntry;

/**
 * SAML2 remote organization object.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.1
 */
public class SAML2IDP extends AbstractIDP
        implements Serializable {

    /**
     * Local logger instance
     */
    private static final Log _oLogger = LogFactory.getLog(SAML2IDP.class);
    ;
	
    /** Type: id */
    public final static String TYPE_ID = "id";
    /**
     * Type: sourceid
     */
    public final static String TYPE_SOURCEID = "sourceid";

    private static final long serialVersionUID = -3291910972515606397L;

    private static final int HTTP_METADATA_REQUEST_TIMEOUT = 5000;

    /**
     * SourceID is a 20-byte sequence used by the artifact receiver to determine
     * artifact issuer identity and the set of possible resolution endpoints.
     * <br/>
     * The issuer constructs the SourceID component of the artifact by taking
     * the SHA-1 hash of the identification URL. The hash value is NOT encoded
     * into hexadecimal.
     */
    private byte[] _baSourceID;
    private String _sMetadataFile;
    private String _sMetadataURL;
    private int _iMetadataTimeout;
    private Boolean _boolACSIndex;
    private Boolean _boolScoping;
    private Boolean _boolNameIDPolicy;
    private Boolean _boolAllowCreate;
    /**
     * _boolAvoidSubjectConfirmations indicates whether avoid including
     * SubjectConfirmation in an AuthnRequest to this IDP; used for
     * compatibility with Microsoft ADFS Default should be false
     */
    protected Boolean _boolAvoidSubjectConfirmations;

    /**
     * _boolDisableSSOForIDP indicates whether SSO should be disabled when
     * authentication is performed by this IDP. Default should be false
     */
    protected Boolean _boolDisableSSOForIDP = false;

    private String _sNameIDFormat;

    /**
     * The name of the MetadataProviderManager that manages this SAML2IDP
     */
    protected String _sMPMId = null;

    /**
     * Element containing the parsed XMLObject of the metadata document
     *
     * Does not serialize, so marshall to _sMetadata upon serialization
     */
    transient protected XMLObject _oMetadataXMLObject = null;

    /**
     * Keep reference to MetadataProvider for this IDP
     *
     * Does not serialize, so it is lost whenever it has been resuscitated. This
     * should not present any problem, as the MetadataProviderManager can
     * re-deliver the MetadataProvider, or when it can not, the SAML2IDP can
     * re-create one
     */
    transient protected MetadataProvider _oMetadataProvider = null;

    /**
     * Contains the string version of the XMLObject's metadata Only used for
     * transit, so object instance can be serialized, so will be set before
     * serializing, and will be set when un-serialized from instance that was
     * serialized before
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
     * @param avoidSubjectConfirmations TRUE if ConfirmationData must not be
     * included in an AuthnRequest to this IDP
     * @param disableSSOForIDP Configure whether the SSO should be disabled for
     * this IDP
     * @param dLastModified Timestamp when SAML2IDP was last modified, or null
     * when unknown
     * @param sMPMId Id of the MetadataProviderManager that manages
     * MetadataProvider for this IDP i.e. the name of the IDPStorage
     * @throws OAException if invalid data supplied
     */
    public SAML2IDP(String sID, byte[] baSourceID, String sFriendlyName,
            String sMetadataFile, String sMetadataURL,
            int iMetadataTimeout, Boolean useACSIndex, Boolean useAllowCreate,
            Boolean useScoping, Boolean useNameIDPolicy, String forceNameIDFormat,
            Boolean avoidSubjectConfirmations, Boolean disableSSOForIDP,
            Date dLastModified, String sMPMId)
            throws OAException {
        super(sID, sFriendlyName, dLastModified);

        init(sID, baSourceID, sFriendlyName,
                sMetadataFile, sMetadataURL,
                iMetadataTimeout, useACSIndex, useAllowCreate,
                useScoping, useNameIDPolicy, forceNameIDFormat,
                avoidSubjectConfirmations, disableSSOForIDP,
                dLastModified, sMPMId);
    }

    /**
     * Creates an organization object from LDAP entry object..
     */
    public SAML2IDP(IDPEntry entry, byte[] baSourceID, String _sMPMId) throws OAException {
        super(entry.getId(), entry.getFriendlyName(), entry.getLastModified());

        init(entry.getId(), baSourceID, entry.getFriendlyName(),
                entry.getMetadataFile(), entry.getMetadataUrl(),
                entry.getMetadataTimeout(), entry.isAcsIndex(), entry.isAllowCreate(),
                entry.isScoping(), entry.isNameIdPolicy(), entry.getNameIdFormat(),
                entry.isAvoidSubjectConfirmations(), entry.isDisableSSOForIDP(),
                entry.getLastModified(), _sMPMId
        );
    }

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
     * @param avoidConfirmationData TRUE if ConfirmationData must not be
     * included in an AuthnRequest to this IDP
     * @param disableSSOForIDP Configure whether the SSO should be disabled for
     * this IDP
     * @param dLastModified Timestamp when SAML2IDP was last modified, or null
     * when unknown
     * @param sMPMId Id of the MetadataProviderManager that manages
     * MetadataProvider for this IDP i.e. the name of the IDPStorage
     * @throws OAException if invalid data supplied
     */
    private void init(String sID, byte[] baSourceID, String sFriendlyName,
            String sMetadataFile, String sMetadataURL,
            int iMetadataTimeout, Boolean useACSIndex, Boolean useAllowCreate,
            Boolean useScoping, Boolean useNameIDPolicy, String forceNameIDFormat,
            Boolean avoidSubjectConfirmations, Boolean disableSSOForIDP,
            Date dLastModified, String sMPMId)
            throws OAException {
        _baSourceID = baSourceID;

        _sMetadataFile = sMetadataFile;
        if (_sMetadataFile != null && !"".equals(_sMetadataFile)) {
            File fMetadata = new File(_sMetadataFile);
            if (!fMetadata.exists()) {
                StringBuffer sbError = new StringBuffer("Supplied metadata file for organization '");
                sbError.append(_sID);
                sbError.append("' doesn't exist: ");
                sbError.append(_sMetadataFile);
                _oLogger.error(sbError.toString());
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        } else {
            // set null to prevent empty string
            _sMetadataFile = null;
        }

        _sMetadataURL = sMetadataURL;
        if (_sMetadataURL != null && !"".equals(_sMetadataURL)) {
            try {
                new URL(_sMetadataURL);
            } catch (MalformedURLException e) {
                StringBuffer sbError = new StringBuffer("Invalid metadata URL supplied for organization '");
                sbError.append(_sID);
                sbError.append("': ");
                sbError.append(_sMetadataURL);
                _oLogger.error(sbError.toString(), e);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        } else {
            // set null to prevent empty string
            _sMetadataURL = null;
        }

        _iMetadataTimeout = iMetadataTimeout;
        if (_iMetadataTimeout <= 0) {
            _iMetadataTimeout = HTTP_METADATA_REQUEST_TIMEOUT;

            StringBuffer sbDebug = new StringBuffer("Supplied HTTP metadata timeout for organization '");
            sbDebug.append(_sID);
            sbDebug.append("' is equal or smaller then zero, using default: ");
            sbDebug.append(_iMetadataTimeout);
            _oLogger.debug(sbDebug.toString());
        }

        _boolACSIndex = useACSIndex;
        _boolScoping = useScoping;
        _boolNameIDPolicy = useNameIDPolicy;
        _boolAllowCreate = useAllowCreate;
        _boolAvoidSubjectConfirmations = avoidSubjectConfirmations;
        _boolDisableSSOForIDP = disableSSOForIDP;
        _sNameIDFormat = forceNameIDFormat;

        // Initialize the name of the MetadataProviderManager
        _sMPMId = sMPMId;
    }

    /**
     * Returns the SourceID of the organization.
     *
     * @return the source id
     */
    public byte[] getSourceID() {
        return _baSourceID;
    }

    /**
     * Return whether the SAML2IDP is initialized with a MetadataProvider
     *
     * @return
     */
    public boolean isMetadataProviderSet() {
        return (_oMetadataProvider != null);
    }

    /**
     * Returns a metadata provider with the metadata of the organization.
     * <br>
     * If the provider was set externally, this provider is returned. <br/>
     * When the SAML2IDP has been serialized/deserialized, a MetadataProvider
     * based on the (static) metadata is returned. Otherwise, a new
     * MetadataProvider is constructed that retrieves its metadata from the
     * configured file- and/or url-source.
     *
     * @return The initialized MetadataProvider with the metadata for this
     * organization or NULL when no metadata is available.
     * @throws OAException If metadata is invalid or could not be accessed
     */
    public MetadataProvider getMetadataProvider() throws OAException {
        if (_oMetadataProvider != null) {
            _oLogger.debug("Returning existing MetadataProvider for SAML2 IDP '" + _sID + "'");
            return _oMetadataProvider;
        }

        // If there is a local metadata document available, return the
        // MetadataProvider that is based on this document
        if (_oMetadataXMLObject != null) {
            _oLogger.debug("Creating new XMLObject MetadataProvider for SAML2 IDP '" + _sID + "'");

            XMLObjectMetadataProvider oMP = new XMLObjectMetadataProvider(_oMetadataXMLObject);
            oMP.initialize();
            _oMetadataProvider = oMP;
            return oMP;

        }
        if (_sMetadata != null) {
            _oLogger.debug("Creating new XML-String MetadataProvider for SAML2 IDP '" + _sID + "'");

            // This is the case after de-serialization (i.e. when session resumes)
            // Re-instantiate XMLProvider from retrieved metadata
            // No cache re-evaluation, but this performs better
            try {
                BasicParserPool parserPool = new BasicParserPool();
                parserPool.setNamespaceAware(true);

                StringReader oSR = new StringReader(_sMetadata);

                _oMetadataXMLObject = XMLObjectHelper.unmarshallFromReader(parserPool, oSR);

                XMLObjectMetadataProvider oMP = new XMLObjectMetadataProvider(_oMetadataXMLObject);
                oMP.initialize();

                _oMetadataProvider = oMP;
                return oMP;

            } catch (XMLParserException e) {
                _oLogger.warn("XMLParser exception with establishing metadata for SAML2IDP, trying file/url: " + e.getMessage());
            } catch (UnmarshallingException e) {
                _oLogger.warn("Unmarshalling exception with establishing metadata for SAML2IDP, trying file/url: " + e.getMessage());
            }
        }

        _oLogger.debug("Creating new MetadataProvider from configured source for SAML2 IDP '" + _sID + "'");

        // First time a MetadataProvider request is being handled for this SAML2IDP instance:
        MetadataProviderConfiguration oMPC = new MetadataProviderConfiguration(
                _sMetadataURL, _iMetadataTimeout, _sMetadataFile, _sMetadata);
        String sConfiguredProviderFingerprint = oMPC.getFingerprint();

        IMetadataProviderManager oMPM = null;
        MetadataProvider oMP = null;

        if (_sMPMId != null) {
            oMPM = MdMgrManager.getInstance().getMetadataProviderManager(_sMPMId);
        }

        // Can we get a managed MetadataProvider?
        if (oMPM != null) {
            oMP = oMPM.getProviderFor(_sID, _dLastModified);
        }

        if (oMP != null) {
            // Is it still valid?
            String sCachedProviderFingerprint = MetadataProviderUtil.getMetadataProviderFingerprint(oMP);

            if (!sCachedProviderFingerprint.equals(sConfiguredProviderFingerprint)) {
                _oLogger.info("Metadata configuration changed; re-initializing metadata for IDP " + _sID);
                // No longer valid; invalidate the version from cache
                oMPM.removeProviderFor(_sID);
                oMP = null;
            } else // For the purpose of logging:
            if (_oLogger.isDebugEnabled()) {
                String sNextRefresh = null;

                if (oMP instanceof AbstractReloadingMetadataProvider) {
                    DateTime oNextRefresh = ((AbstractReloadingMetadataProvider) oMP).getNextRefresh();
                    sNextRefresh = oNextRefresh.toString();
                }
                _oLogger.debug("Using cached MetadataProvider for IDP " + _sID
                        + (sNextRefresh == null ? "" : " (next refresh: " + sNextRefresh + ")"));
            }
        }

        if (oMP == null) {
            oMP = MetadataProviderUtil.createMetadataProvider(_sID, oMPC, oMPM);
        }

        _oMetadataProvider = oMP;

        return _oMetadataProvider;
    }

    /**
     * Indicates whether the ACS location in the AuthnRequest must be an Index.
     *
     * Values are:
     * <ul>
     * <li>TRUE - AssertionConsumerServiceIndex must be set
     * <b>(default)</b></li>
     * <li>FALSE - AssertionConsumerServiceURL and ProtocolBinding must be
     * set</li>
     * </ul>
     *
     * @return TRUE if the ACS location must be an index.
     * @since 1.2
     */
    public Boolean useACSIndex() {
        return _boolACSIndex;
    }

    /**
     * Indicates what the value of AllowCreate in the NameIDPolicy of the
     * AuthnRequest must be.
     *
     * Values are:
     * <ul>
     * <li>NULL - AllowCreate is not send in the AuthnRequest <b>(default unless
     * it's proxied)</b></li>
     * <li>TRUE - AllowCreate=true</li>
     * <li>FALSE - AllowCreate=false</li>
     * </ul>
     *
     * @return the preferred AllowCreate value.
     * @since 1.2
     */
    public Boolean useAllowCreate() {
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
     *
     * @return TRUE if the Scoping element must be send.
     * @since 1.2
     */
    public Boolean useScoping() {
        return _boolScoping;
    }

    /**
     * Indicates what the value of NameIDPolicy in the AuthnRequest must be.
     *
     * Values are:
     * <ul>
     * <li>TRUE - NameIDPolicy element will be sent <b>(default)</b></li>
     * <li>FALSE - NameIDPolicy element will not be sent </li>
     * </ul>
     *
     * @return TRUE if the NameIDPolicy element must be send.
     * @since 1.2
     */
    public Boolean useNameIDPolicy() {
        return _boolNameIDPolicy;
    }

    /**
     * Return indication whether to avoid including SubjectConfirmation in an
     * AuthnRequest to this IDP; used for compatibility with Microsoft ADFS
     *
     * @return TRUE to avoid this element
     */
    public Boolean avoidSubjectConfirmations() {
        return _boolAvoidSubjectConfirmations;
    }

    /**
     * Set DisableSSOForIDP for this instance
     *
     * @param bDisableSSOForIDP
     */
    public void setDisableSSOForIDP(boolean bDisableSSOForIDP) {
        _boolDisableSSOForIDP = bDisableSSOForIDP;
    }

    @Override
    public boolean disableSSO() {
        return _boolDisableSSOForIDP;
    }

    /**
     * Indicates what the value of Format in the NameIDPolicy of the
     * AuthnRequest must be.
     *
     * Values are:
     * <ul>
     * <li>NULL - The first NameIDFormat in the IdP Metadata should be used OR
     * no format when a NameIDFormat is not available in that
     * metadata<b>(default)</b></li>
     * <li>NOT NULL - The Format should be overrulen with the configured
     * format</li>
     * </ul>
     * This functionality will only be used when the NameIDPolicy is used.
     *
     * @return the preferred NameIDFormat value.
     * @since 1.2
     */
    public String getNameIDFormat() {
        return _sNameIDFormat;
    }

    /**
     * Set Metadata of the IDP to be the provided (OpenSAML2) parsed XML
     * document
     *
     * @param elMetadataDocument
     */
    public void setMetadataXMLObject(XMLObject oMetadataXMLObject) {
        _oMetadataXMLObject = oMetadataXMLObject;
    }

    /**
     * Deal with internally stored metadata stuff
     *
     * @param oOutputStream
     */
    private void writeObject(ObjectOutputStream oOutputStream)
            throws java.io.IOException {
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
            _oLogger.error("Exception when marshalling XMLObject to Writer for SAML2IDP, dropping metadata: " + e.getMessage());
            return;
        } catch (MetadataProviderException e) {
            _oLogger.error("Exception when serializing and retrieving Metadata for SAML2IDP '" + _sID + "':" + e.getMessage());
            throw new IOException(e);
        }

        // Do its thing:
        oOutputStream.defaultWriteObject();
    }
}
