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

import org.apache.commons.codec.digest.DigestUtils;

/**
 * Helper class that contains all the configurable metadata properties
 */
public class MetadataProviderConfiguration {
	
    /** Tag of a HTTP provider in a fingerprint */
    public static final String FINGERPRINT_PROVIDER_HTTP = "httpprovider";
    /** Tag of a Filesystem provider in a fingerprint */
    public static final String FINGERPRINT_PROVIDER_FILE = "filesystemprovider";
    /** Tag of a String provider in a fingerprint */
    public static final String FINGERPRINT_PROVIDER_STRING = "stringprovider";
    /** Tag of unknown provider in a fingerprint */
    public static final String FINGERPRINT_PROVIDER_UNKNOWN = "unknown";
	
	/** HTTP source of the metadata */
	public String _sURL = null;
	/** Timeout setting for HTTP source */
	public int _iTimeout = 0;
	/** Metadata filename; note: this is always the Full Qualified (expanded!) filename! */
	public String _sFilename = null;
	/** Actual metadata */
	public String _sMetadata = null;

	
	/**
	 * Default constructor
	 */
	public MetadataProviderConfiguration() {};
	

	/**
	 * Initializing constructor
	 * @param sURL
	 * @param iTimeout
	 * @param sFilename
	 * @param sMetadata
	 */
	public MetadataProviderConfiguration(String sURL, int iTimeout, String sFilename, String sMetadata) {
		_sURL = sURL;
		_iTimeout = iTimeout;
		_sFilename = sFilename;
		_sMetadata = sMetadata;
	}
	
	/**
	 * Establish a fingerprint of the configuration
	 * @return
	 */
	public String getFingerprint() {
		StringBuilder oResult = new StringBuilder();
    	
    	if (_sURL != null) {
    		oResult.append(FINGERPRINT_PROVIDER_HTTP).append(",").append(_sURL).append(",").append(_iTimeout);
    	} else if (_sFilename != null) {
    		oResult.append(FINGERPRINT_PROVIDER_FILE).append(",").append(_sFilename);
    	} else if (_sMetadata != null) {
    		oResult.append(FINGERPRINT_PROVIDER_STRING).append(",").append(DigestUtils.shaHex(_sMetadata));
    	} else
    		oResult.append(FINGERPRINT_PROVIDER_UNKNOWN);
    	
		return oResult.toString();
	}
}