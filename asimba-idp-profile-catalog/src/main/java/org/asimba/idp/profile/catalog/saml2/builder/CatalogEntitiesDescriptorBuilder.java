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
package org.asimba.idp.profile.catalog.saml2.builder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.impl.EntitiesDescriptorBuilder;
import org.opensaml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.server.Server;
import com.alfaariss.oa.util.saml2.metadata.AbstractMetadataBuilder;

public class CatalogEntitiesDescriptorBuilder extends AbstractMetadataBuilder {

	/**
	 * Local logger instance
	 */
	private static Log _oLogger;
	
	/**
	 * Local ConigManager reference for
	 */
	IConfigurationManager _oConfigManager;
	
	/**
	 * Reference to Asimba server to retrieve global properties
	 */
	Server _oServer;
	
	/**
	 * The element that is built in this context
	 */
	EntitiesDescriptor _oEntitiesDescriptor;
	
	
	/**
	 * Constructor that can initializes our context from the provided configuration
	 * @param oConfigManager
	 * @param eMetadata
	 * @param oServer
	 */
	public CatalogEntitiesDescriptorBuilder(IConfigurationManager oConfigManager, 
	        Server oServer)
	{
		super();
		
		_oLogger = LogFactory.getLog(CatalogEntitiesDescriptorBuilder.class);
		
		_oConfigManager = oConfigManager;
		_oServer = oServer;
		
		EntitiesDescriptorBuilder b = (EntitiesDescriptorBuilder) 
				_builderFactory.getBuilder(EntitiesDescriptor.DEFAULT_ELEMENT_NAME);
	
		_oEntitiesDescriptor = b.buildObject();
	}
	

	/**
	 * Add the providede EntityDescriptor to the (root) catalog
	 * @param oEntityDescriptor
	 */
	public void addEntityDescriptor(EntityDescriptor oEntityDescriptor) {
		if (_oLogger.isDebugEnabled()) _oLogger.debug("Adding EntityDescriptor for EntityId "+oEntityDescriptor.getEntityID());
		
		_oEntitiesDescriptor.getEntityDescriptors().add(oEntityDescriptor);
	}
	

	/**
	 * Return the created EntitiesDescriptor instance
	 * @return
	 */
	public EntitiesDescriptor getEntitiesDescriptor() {
		return _oEntitiesDescriptor;
	}
	
}
