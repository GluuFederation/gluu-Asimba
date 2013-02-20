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

import org.opensaml.saml2.metadata.provider.AbstractObservableMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A <code>MetadataProvider</code> implementation that retrieves metadata from a <code>XMLObject</code> as
 * supplied by the user.
 * 
 * The XMLObject is not filtered and not reloaded; this is the responsibility of the caller.
 * 
 * It is the responsibility of the caller to re-initialize, via {@link #initialize()}, if any properties of this
 * provider are changed.
 */
public class XMLObjectMetadataProvider extends AbstractObservableMetadataProvider implements MetadataProvider {

	/** Class logger. */
	private final Logger _oLogger = LoggerFactory.getLogger(XMLObjectMetadataProvider.class);

	/** Unmarshalled metadata. */
	private XMLObject _oMetadata;


	/**
	 * Constructor.
	 * 
	 * @param oMetadataXMLObject the metadata element
	 */
	public XMLObjectMetadataProvider(XMLObject oMetadataXMLObject) {
		super();
		_oMetadata = oMetadataXMLObject;
	}

	/** {@inheritDoc} */
	protected XMLObject doGetMetadata() throws MetadataProviderException {
		return _oMetadata;
	}

	@Override
	public synchronized void initialize() {
		try {
			super.initialize();
		} catch (MetadataProviderException e) {
			// This cannot occur, as no actual initialization is performed, see below
			// Safe to ignore.
		}
	};
	
	/** {@inheritDoc} */
	protected void doInitialization() throws MetadataProviderException {
		_oLogger.trace("doInitialization called.");
		emitChangeEvent();
	}
}


