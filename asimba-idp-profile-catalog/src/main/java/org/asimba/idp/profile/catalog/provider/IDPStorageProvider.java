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
package org.asimba.idp.profile.catalog.provider;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.engine.core.idp.storage.IIDPStorage;

/**
 * Implementation that provides IDPs unfiltered
 * from a IDPStorage source
 * 
 * This IDP Provider hooks into an instantiated SAML2 IDP Storage, and
 * re-uses its configuration completely, including MetadataProvider Management
 * 
 * @author mdobrinic
 *
 */
public class IDPStorageProvider implements IIDPProvider {
	/**
	 * Configuration element names
	 */
	public static final String EL_IDPSTORAGE = "idpstorage";
	public static final String ATTR_NAME = "name";

	/**
	 * Local logger instance
	 */
	private static Log _oLogger = LogFactory.getLog(IDPStorageProvider.class); 

	/**
	 * Local copy for restart
	 */
	protected IConfigurationManager _oConfigManager;

	/**
	 * Configured IIDPStorage that is the source for this provider
	 */
	protected IIDPStorage<? extends IIDP> _oIDPStorage;
	
	/**
	 * Configured name of the IDPStorage
	 */
	protected String _sIDPStorageName;
	
	
	public void start(IConfigurationManager oConfigManager,
			Element eConfig) throws OAException 
	{
		_oIDPStorage = null;
		
		_oConfigManager = oConfigManager;
		
		Element elIDPStorage = oConfigManager.getSection(eConfig, EL_IDPSTORAGE);
		if (elIDPStorage == null) {
			_oLogger.error("No '"+EL_IDPSTORAGE+"' element was configured.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		_sIDPStorageName = oConfigManager.getParam(elIDPStorage, ATTR_NAME);
		if (_sIDPStorageName == null) {
			_oLogger.error("No idpstorage "+ATTR_NAME+"-attribute configured.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		_oLogger.info("Initialized IDPStorageProvider to use '"+_sIDPStorageName+"'");

	}

	/**
	 * {@inheritDoc}
	 */
	public void restart(Element eConfig) throws OAException {
		synchronized(this) {
			stop();
			start(_oConfigManager, eConfig);
		}

	}

	/**
	 * {@inheritDoc}
	 */
	public void stop() {
		_oIDPStorage = null;
	}

	/**
	 * {@inheritDoc}
	 */
	public List<IIDP> getIDPs() {
		if (_oIDPStorage == null) {
			_oIDPStorage = Engine.getInstance().getIDPStorageManager().getStorage(_sIDPStorageName);
		}
		
		List<IIDP> oResult = null;
		
		try {
			if (_oIDPStorage == null) {
				_oLogger.error("Unknown IDPStorage configured: "+_sIDPStorageName);
				throw new OAException(SystemErrors.ERROR_INIT);
			}

			oResult = _oIDPStorage.getAll();
		} catch (OAException e) {
			_oLogger.error("Could not retrieve IDPs from storage '"+_oIDPStorage.getID()+"'");
		}
		
		if (oResult != null) return oResult;
		
		return new ArrayList<IIDP>();
	}
	
	
	public DateTime getDateLastModified() {
		if (_oIDPStorage == null) {
			_oIDPStorage = Engine.getInstance().getIDPStorageManager().getStorage(_sIDPStorageName);
		}
		
		// The storage itself doesn't have changable properties
		// Only investigate the contained IDPs:
		
		Date dMostRecent = null;
		Date dCurrent = null;
		try {
			List<IIDP> lIDPs = _oIDPStorage.getAll();
			for (IIDP oIDP: lIDPs) {
				dCurrent = oIDP.getLastModified();
				if (dCurrent != null) {
					if (dMostRecent == null) dMostRecent = dCurrent;
					else if (dMostRecent.before(dCurrent)) dMostRecent = dCurrent;
				}
			}
			
			// Returns now() when dMostRecent==null ...
			return new DateTime(dMostRecent);
		} catch (OAException e) {
			_oLogger.error("Could not retrieve IDPs from storage '"+_oIDPStorage.getID()+"'");
		}
		return null;
	}

}
