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
package com.alfaariss.oa.engine.core.idp.storage;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.Engine;

/**
 * Wrapper to put multiple IIDPStorage configurations together
 * 
 * The order of configuration is the search order.
 * 
 * Example configuration:
 * <idps id="mainIDPs" class="com.alfaariss.oa.engine.core.idp.storage.ChainedIDPStorage">
 *   <storages>
 * 	   <storage id="first_store" class="config-store" registerWithEngine="true" />
 *     <storage id="second_store" class="jdbc-store" registerWithEngine="true" />
 *     <storage id="third_store" class="confederation-store" registerWithEngine="false" />
 *   </storages>
 * </idps>
 * 
 * @author mdobrinic
 *
 */
public class ChainedIDPStorage<IDP extends IIDP> implements IIDPStorage {
	/**
	 * Configuration element names
	 */
	public static final String EL_STORAGE = "storage";
	public static final String EL_STORAGES = "storages";
	public static final String ATTR_REGISTER_SUBSTORAGE = "registerWithEngine";

	/**
	 * Local logger instance
	 */
    private final Log _oLogger = LogFactory.getLog(ChainedIDPStorage.class);

    /**
     * ID of the ChainedIDPStorage storage
     */
    protected String _sID;
    
    
    /**
     * Contains a list of sub storage elements that are
     * registered with Engine's IDPStorage manager
     * Configurable for storage with ATTR_REGISTER_SUBSTORAGE attribute
     */
    protected List<String> _lRegisteredWithEngine;
    
    
    /**
     * Ordered list of IIDPStorage id's
     */
    protected List<String> _lIDPStorageIDs;
    
    
    /**
     * Map of IIDPStorage's
     */
    protected Map<String, IIDPStorage> _mIDPStorage;

	
	public void start(IConfigurationManager oConfigManager, Element eConfig)
			throws OAException 
	{
		_lIDPStorageIDs = new ArrayList<String>();
		_mIDPStorage = new HashMap<String, IIDPStorage>();
		_lRegisteredWithEngine = new ArrayList<String>();
		
		_sID = oConfigManager.getParam(eConfig, "id");
		if (_sID == null) {
			_oLogger.error("No @id attribute configured for idp storage.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		Element elStorages = oConfigManager.getSection(eConfig, EL_STORAGES);
		if (elStorages == null) {
			_oLogger.error("No '"+EL_STORAGES+"' element defined in ChainedIDPStorage.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		Element elStorage = oConfigManager.getSection(elStorages, EL_STORAGE);
		if (elStorage == null) {
			_oLogger.error("Must configure at least one '"+EL_STORAGE+"' element in '"+EL_STORAGES+"'.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		while (elStorage != null) {
			String sClass = oConfigManager.getParam(elStorage, "class");
			if (sClass == null) {
				_oLogger.error("Must configure a @class attribute with a storage.");
				throw new OAException(SystemErrors.ERROR_CONFIG_READ);
			}
			
			String sID = oConfigManager.getParam(elStorage, "id");
			if (sID == null) {
				_oLogger.error("Must configure a @id attribute with a storage.");
				throw new OAException(SystemErrors.ERROR_CONFIG_READ);
			}
			
			// Add id to list, retain order
			_lIDPStorageIDs.add(sID);

			// Instantiate and start the IDPStorage
			IIDPStorage oIDPStorage= createStorage(sClass);
			oIDPStorage.start(oConfigManager, elStorage);
			
			// Put the IDPStorage in the map
			_mIDPStorage.put(sID, oIDPStorage);

			// Do we register this sub-storage with Engine as well?
			String sRegisterWithEngine = oConfigManager.getParam(elStorage, ATTR_REGISTER_SUBSTORAGE);
			if (sRegisterWithEngine != null) {
				if (sRegisterWithEngine.equalsIgnoreCase("TRUE")) {
					Engine.getInstance().getIDPStorageManager().addStorage(oIDPStorage);
					_lRegisteredWithEngine.add(sID);
					_oLogger.info("Registered '"+sID+"' with Engine IDPStorage manager");
				}
			}

			
			// Continue with other storages
			elStorage = oConfigManager.getNextSection(elStorage);
		}
		
		_oLogger.info("Initialized '"+_sID+"'");
	}

	
	public void stop() {
		for (String sID: _lIDPStorageIDs) {
			_mIDPStorage.get(sID).stop();
		}
		
		for (String sID: _lRegisteredWithEngine) {
			Engine.getInstance().getIDPStorageManager().removeStorage(sID);
			_oLogger.info("Unregistered '"+sID+"' from Engine IDPStorage manager");
		}
		
		// clear list and map:
		_mIDPStorage.clear();
		_lIDPStorageIDs.clear();
		
		_oLogger.info("Stopped '"+_sID+"'");
	}

	
	/**
	 * {@inheritDoc}
	 */
	public String getID() {
		return _sID;
	}

	
	/**
	 * Returns the IDP from the chained list of storages; first IDP found is
	 * returned. IDP storages are searched in the order in which they are configured.
	 * @param id id of the IDP
	 */
	public IIDP getIDP(String id) throws OAException {
		IIDP oIDP = null;
		for (String sStorageID: _lIDPStorageIDs) {
			oIDP = _mIDPStorage.get(sStorageID).getIDP(id);
			if (oIDP != null) {
				_oLogger.info("IDP '"+id+"' found in IDPStorage '"+sStorageID+"'");
				return oIDP;
			}
		}
		return null;
	}

	
	/**
	 * Returns the IDP from the chained list of storages; first IDP found is
	 * returned. IDP storages are searched in the order in which they are configured.
	 * @param id id of the IDP
	 * @param type type of the IDP, like "id", or "sourceid"
	 */
	public IIDP getIDP(Object id, String type) throws OAException {
		IIDP oIDP = null;
		for (String sStorageID: _lIDPStorageIDs) {
			oIDP = _mIDPStorage.get(sStorageID).getIDP(id, type);
			if (oIDP != null) {
				_oLogger.info("IDP '"+id+"' with type '"+type+"'found in IDPStorage '"+sStorageID+"'");
				return oIDP;
			}
		}
		return null;
	}

	
	/**
	 * Add all the IDPs of all the configured storages together and return them
	 */
	public List<IIDP> getAll() throws OAException {
		List<IIDP> lIDPs = new ArrayList<IIDP>();
		for (String sStorageID: _lIDPStorageIDs) {
			lIDPs.addAll( _mIDPStorage.get(sStorageID).getAll() );
		}
		
		return lIDPs;
	}


	/**
	 * Returns whether an IDP with provided ID exists in the configured
	 * storages
	 * @return true when exists, false when not
	 */
	public boolean exists(String id) throws OAException {
		IIDP oIDP = getIDP(id);
		return (oIDP == null);
	}

	
	/**
	 * Helper to instantiate the configured IIDMapper class
	 * @param sClass Name of class to instantiate
	 * @return Instantiated class
	 * @throws OAException when class was not found, or when class could not be instantiated
	 */
    private IIDPStorage createStorage(String sClass)
    	throws OAException
    {
    	IIDPStorage oIDPStorage = null;
    	
    	Class<?> oClass = null;
        try {
            oClass = Class.forName(sClass);
        } catch (Exception e) {
            _oLogger.error("No 'class' found with name: " + sClass, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        try {
        	oIDPStorage = (IIDPStorage) oClass.newInstance();
        } catch (Exception e) {
            _oLogger.error("Could not create an 'IIDPStorage' instance of class with name '"+
            	sClass + "'", e); 
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        return oIDPStorage;
    }
}
