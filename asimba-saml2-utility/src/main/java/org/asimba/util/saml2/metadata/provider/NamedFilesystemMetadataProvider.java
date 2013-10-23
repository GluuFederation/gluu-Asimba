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
import java.util.Timer;

import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A <code>NamedFilesystemMetadataProvider</code> is an extension to the FilesystemMetadataProvider
 * that allows to look into the file that is used to provide the metadata
 * 
 * It is the responsibility of the caller to re-initialize, via {@link #initialize()}, if any properties of this
 * provider are changed.
 */
public class NamedFilesystemMetadataProvider extends FilesystemMetadataProvider {

	/** Local logger */
	private final Logger _oLogger = LoggerFactory.getLogger(NamedFilesystemMetadataProvider.class);
	
	/** Metadata file */
	protected File _oMetadataFile;
	
	/**
	 * Constructor
	 * @param oMetadataFile
	 * @throws MetadataProviderException
	 */
	public NamedFilesystemMetadataProvider(File oMetadataFile) throws MetadataProviderException {
        super(oMetadataFile);

        _oMetadataFile = oMetadataFile;
        _oLogger.info("Created for file with name "+getFilename());
	}
	
	/**
	 * Constructor with provided timer that is used for rescheduling reloads
	 * @param oTimer
	 * @param oMetadataFile
	 * @throws MetadataProviderException
	 */
	public NamedFilesystemMetadataProvider(Timer oTimer, File oMetadataFile) throws MetadataProviderException {
		super(oTimer, oMetadataFile);
		
        _oMetadataFile = oMetadataFile;
        _oLogger.info("Created for file with name "+getFilename());
	}
	
	/**
	 * Establish the name of the file that is used for reading metadata from
	 *  
	 * @return Filename of the metadata file
	 */
	public String getFilename() {
		return _oMetadataFile.getAbsolutePath();
	}

}
