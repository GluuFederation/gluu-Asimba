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
package org.asimba.util.saml2.confederation;

import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.engine.core.confederation.IConfederation;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.engine.core.idp.storage.IIDPStorage;

/**
 * Provide a layer over a IConfederation so it can operate as a IDPStorage
 * 
 * Example configuration
 * 
 * <idps id="confederation-idp-storage" class="...ConfederationIDPStorage">
 *   <confederation name="[confederationname]" />
 * </idps>
 * 
 * @author mdobrinic
 * @param <IDP>
 */
public class ConfederationIDPStorage<IDP extends IIDP> implements IIDPStorage {
	
	/** Local logger instance */
    private final Log _oLogger = LogFactory.getLog(ConfederationIDPStorage.class);
	
    /** ID of the ConfederationIDPStorage storage */
    protected String _sID;
    
    /** Name of the confederation, as configured */
    protected String _sConfederationName;
    
    /** Instance of the confederation, as */
    protected IConfederation _oConfederation;
    

    
	public void start(IConfigurationManager oConfigManager, Element eConfig)
			throws OAException 
	{
		_sID = oConfigManager.getParam(eConfig, "id");
		if (_sID == null) {
			_oLogger.error("No @id attribute configured for confederation idp storage.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		Element elConfederation = oConfigManager.getSection(eConfig, "confederation");
		if (elConfederation == null) {
			_oLogger.error("Must configure a 'confederation' in confederation idp storage.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		_sConfederationName = oConfigManager.getParam(elConfederation, "name");
		if (_sConfederationName == null) {
			_oLogger.error("Must configure a '@name' attribute for a confederation.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		_oConfederation = Engine.getInstance()
				.getConfederationFactory().getConfederations().get(_sConfederationName);
		if (_oConfederation == null) {
			_oLogger.error("Unknown confederation ("+_sConfederationName+"); must be configured with engine!");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		_oLogger.info("Initialized for confederation '"+_sConfederationName+"'");
	}
	

	public void stop() {
		_oLogger.info("Stopped for confederation "+_sConfederationName);
	}

	public String getID() {
		return _sID;
	}

	/**
	 * {@inheritDoc}
	 */
	public IIDP getIDP(String id) throws OAException {
		List<? extends IIDP> oIDPList = _oConfederation.getIDPs(
				IConfederation.UNSPECIFIED_REQUESTOR, IConfederation.NO_CONTEXT); 
		
		if (oIDPList != null) {
			for (IIDP oIDP: oIDPList) {
				if (oIDP.getID().equals(id)) {
					return oIDP;
				}
			}
		}
		
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public IIDP getIDP(Object id, String type) throws OAException {
		return getIDP((String)id);
	}

	
	/**
	 * {@inheritDoc}
	 */
	public List<? extends IIDP> getAll() throws OAException {
		List<? extends IIDP> oIDPList = _oConfederation.getIDPs(
				IConfederation.UNSPECIFIED_REQUESTOR, IConfederation.NO_CONTEXT); 

		return oIDPList;
	}

	
	/**
	 * {@inheritDoc}
	 */
	public boolean exists(String id) throws OAException {
		IIDP oIDP = getIDP(id);
		if (oIDP != null) {
			return true;
		}
		
		return false;
	}

}
