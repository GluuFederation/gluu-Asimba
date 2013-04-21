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

import java.util.List;
import java.util.Timer;

import org.opensaml.saml2.metadata.provider.MetadataProvider;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;

/**
 * MetadataProviderManager takes care of keeping MetadataProviders alive,
 * allowing them to provide their caching services within the control
 * of a singleton-per-context manager instance.
 * 
 * Implementations should add smart resource management to the providers,
 * as they can be (memory) resource intensive when many large catalogs are 
 * used.
 * 
 * Limited to supporting File- and HTTP MetadataProvider instances
 * 
 * @author mdobrinic
 *
 */
public interface IMetadataProviderManager {
	
	
	/**
	 * Set the number of milliseconds after which an unused MetadataProvider
	 * is disposed of
	 * @param iTimeoutMS
	 */
	public void setCacheInterval(int iTimeoutMS);

	/**
	 * Return the number of milliseconds after which an unused 
	 * MetadataProvider is disposed of
	 * @return int
	 */
	public int getCacheInterval();

	/**
	 * Returns the Timer that is managing metadata reloads and cache
	 * control
	 * @return
	 */
	public Timer getTimer();
	
	/**
	 * Sets the timer for managing metadata reloads and cache control
	 * @param oTimer
	 */
	public void setTimer(Timer oTimer);
	
	/**
	 * Return whether a MetadataProvider is available for the provided
	 *   source reference
	 * HTTP metadata providers use the URL as source reference,
	 * File metadata providers use the filename as source reference
	 * @param sSourceRef Source Reference of a MetadataProvider
	 * @return true if exists, false if not
	 */
	public boolean existsFor(String sSourceRef)
			throws OAException;
	
	/**
	 * Return the MetadataProvider for the provided source reference
	 * or null if the MetadataProvider was not available
	 * 
	 * @param sSourceRef Source Reference or ID of a MetadataProvider
	 * @return true if exists, false if not
	 */
	public MetadataProvider getProviderFor(String sSourceRef)
			throws OAException;

	/**
	 * Set the MetadataProvider for a URL-source or a File-source
	 * MetadataProvider must be initialized and ready for use
	 * 
	 * @param sSourceRef Source Reference or ID of a MetadataProvider
	 * @param oMDP MetadataProvider to link to the source
	 * @param oTimer The RefreshTimer that is managed with the 
	 * 	refreshing MetadataProvider
	 */
	public void setProviderFor(String sSourceRef, MetadataProvider oMDP, Timer oTimer)
			throws OAException;
	
	/**
	 * Returns the MetadatProvider that was registed for sSourceRef, and
	 * releases responsibility for it
	 * @param sSourceRef
	 * @return MetadataProvider instance, or null when not found
	 */
	public MetadataProvider removeProviderFor(String sSourceRef)
			throws OAException;
	
	/**
	 * Retrieve the list of IIDP instances that are available for the provided SourceRef
	 * @param sSourceRef
	 * @return
	 */
	public List<IIDP> getIDPs(String sSourceRef);
	
	
	/**
	 * Clean up all of the the resources of MetadataProviderManager
	 */
	public void destroy();
}
