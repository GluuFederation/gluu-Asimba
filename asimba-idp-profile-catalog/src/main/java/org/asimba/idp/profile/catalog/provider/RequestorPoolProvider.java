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
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;


/**
 * Implementation that provides requestors unfiltered
 * from a RequestorPool source
 * 
 * @author mdobrinic
 *
 */
public class RequestorPoolProvider implements ISPProvider {
	/**
	 * Configuration element names
	 */
	public static final String EL_REQUESTORPOOL = "requestorpool";
	public static final String ATTR_NAME = "name";

	
	/**
	 * Local logger instance
	 */
	private static Log _oLogger = LogFactory.getLog(RequestorPoolProvider.class); 

	/**
	 * Local copy for restart
	 */
	protected IConfigurationManager _oConfigManager;
	
	
	/**
	 * Configured RequestorPool
	 */
	protected RequestorPool _oRequestorPool;
	

	/**
	 * Public constructor
	 */
	public RequestorPoolProvider() {
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public void start(IConfigurationManager oConfigManager,
			Element eConfig) throws OAException 
	{
		_oConfigManager = oConfigManager;
		
		Element elRequestorPool = oConfigManager.getSection(eConfig, EL_REQUESTORPOOL);
		if (elRequestorPool == null) {
			_oLogger.error("No '"+EL_REQUESTORPOOL+"' element was configured.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		String sRequestorPool = oConfigManager.getParam(elRequestorPool, ATTR_NAME);
		if (sRequestorPool == null) {
			_oLogger.error("No requestorpool "+ATTR_NAME+"-attribute configured.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		Collection<RequestorPool> cReqPools = Engine.getInstance().getRequestorPoolFactory().getAllEnabledRequestorPools();
		for(RequestorPool r: cReqPools) {
			if (r.getID().equals(sRequestorPool)) _oRequestorPool = r;
		}
		
		if (_oRequestorPool == null) {
			_oLogger.error("Invalid or unknown requestorpool "+ATTR_NAME+" configured: "+sRequestorPool);
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		_oLogger.info("Initialized RequestorPoolProvider for pool '"+_oRequestorPool.getID()+"'");
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
		// Nothing to clean up.
		if (_oRequestorPool != null) {
			_oLogger.info("Stopped RequestorPoolProvider ("+_oRequestorPool.getID()+")");
		}
	}

	
	/**
	 * {@inheritDoc}
	 */
	public List<IRequestor> getSPs() {
		return new ArrayList<IRequestor>(_oRequestorPool.getRequestors());
	}
	
	/**
	 * {@inheritDoc}
	 */
	public DateTime getDateLastModified() {
		Set<IRequestor> sRequestors = _oRequestorPool.getRequestors();
		
		Date dMostRecent = null;
		Date dCurrent = null;

		for(IRequestor oRequestor: sRequestors) {
			dCurrent = oRequestor.getLastModified();
			
			if (dCurrent != null) {
				if (dMostRecent == null) dMostRecent = dCurrent;
				else if (dMostRecent.before(dCurrent)) dMostRecent = dCurrent;
			}
		}
		
		// Returns now() when dMostRecent==null ...
		return new DateTime(dMostRecent);
	}
	
}
