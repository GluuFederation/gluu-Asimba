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
package org.asimba.util.saml2.metadata.provider.management;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.metadata.provider.IMetadataProviderManager;

import com.alfaariss.oa.api.IComponent;

public class MdMgrManager {

	/** Private logger instance */
	private static Log _oLogger = LogFactory.getLog(MdMgrManager.class);
	
	/** Singleton instance */
	private static MdMgrManager _oMdMgrManager = null;
	
	/** Managed MPManagers */
	private Map<String, IMetadataProviderManager> _mMPM;
	
	
	/**
	 * Get singleton instance
	 * @return MsMgrManager instance that manages the MetadataProviderManagers
	 */
	public static MdMgrManager getInstance() {
		if (_oMdMgrManager == null) {
			_oMdMgrManager = new MdMgrManager();
			_oLogger.info("MdMgrManager instance created.");
		}
		
		return _oMdMgrManager;
	}
	
	/**
	 * Private constructor
	 */
	private MdMgrManager() {
		_mMPM = new HashMap<String, IMetadataProviderManager>();
	}
	
	public IMetadataProviderManager getMetadataProviderManager(String sId) {
		return _mMPM.get(sId);
	}
	
	public void setMetadataProviderManager(String sId, IMetadataProviderManager oMPM) {
		_mMPM.put(sId, oMPM);
	}
	
	public void deleteMetadataProviderManager(String sId) {
		IMetadataProviderManager o = _mMPM.get(sId);
		if (o != null) {
			_oLogger.info("Removing MetadataProviderManager from map: "+o);

			// Stop it if appropriate
			if (o instanceof IComponent) {
				((IComponent)o).stop();
			}
			
			_mMPM.remove(o);
		}
	}

	/**
	 * Retrieve a Read-only map of the managed managers
	 * When updates are required, make them through set/delete methods of MdMgrManager
	 * @return
	 */
	public Map<String, IMetadataProviderManager> getMetadataProviderManagerMap() {
		return Collections.unmodifiableMap(_mMPM);
	}
}
