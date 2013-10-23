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
package org.asimba.idp.profile.catalog;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.idp.profile.catalog.provider.IIDPProvider;
import org.asimba.idp.profile.catalog.provider.ISPProvider;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;

public abstract class AbstractCatalog implements ICatalog {
	/** Configuration element names */
	public static final String EL_PUBLISHMODE = "publishmode";
	public static final String EL_SP_PROVIDER = "spprovider";
	public static final String EL_IDP_PROVIDER = "idpprovider";
	public static final String ATTR_ID = "id";
	
	/** Acceptable values for publishmode */
	public static final String PUBLISHMODE_TRANSPARANT = "transparant";
	public static final String PUBLISHMODE_PROXY = "proxy";

	/** Local logger instance */
	private Log _oLogger;
	
	/** Local ConfigurationManager instance for component lifecycle */
	protected IConfigurationManager _oConfigManager;
	
	/** Configured ID of the catalog */
	protected String _sID;
	
	/** Configured SP Provider */
	protected ISPProvider _oSPProvider;
	
	/** Configured IDP Provider */
	protected IIDPProvider _oIDPProvider;
	
	/** Configured publishmode; Default: transparant */
	protected String _sPublishMode;
	

	/**
	 * Default constructor
	 */
	public AbstractCatalog() {
		_oLogger = LogFactory.getLog(AbstractCatalog.class);
	}
	
	/**
	 * {@inheritDoc}
	 */
	public void start(IConfigurationManager oConfigManager,
			Element eConfig) throws OAException 
	{
		_oConfigManager = oConfigManager;
		
		_sID = oConfigManager.getParam(eConfig, ATTR_ID);
		
		_sPublishMode = oConfigManager.getParam(eConfig, EL_PUBLISHMODE);
		if (_sPublishMode == null) {
			_oLogger.info("No publishmode configured, using default 'transparant'.");
			_sPublishMode = "transparant";
		}

		_oSPProvider = null;
		Element elSPProvider = oConfigManager.getSection(eConfig, EL_SP_PROVIDER);
		if (elSPProvider == null) {
			_oLogger.info("No '"+EL_SP_PROVIDER+"' configured.");
		} else {
			_oSPProvider = createSPProvider(oConfigManager, elSPProvider);
		}
		
		_oIDPProvider = null;
		Element elIDPProvider = oConfigManager.getSection(eConfig, EL_IDP_PROVIDER);
		if (elIDPProvider == null) {
			_oLogger.info("No '"+EL_IDP_PROVIDER+"' configured.");
		} else {
			_oIDPProvider = createIDPProvider(oConfigManager, elIDPProvider);
		}
		
		_oLogger.info("Initialized catalog properties.");
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
		if (_oIDPProvider != null) _oIDPProvider.stop();
		if (_oSPProvider != null) _oSPProvider.stop();
	}
	
	/**
	 * Helper to instantiate and start a configured SPProvider from configuration 
	 * @param oConfigManager
	 * @param elSPProviderConfig
	 * @return
	 * @throws OAException
	 */
	protected ISPProvider createSPProvider(IConfigurationManager oConfigManager, 
			Element elSPProviderConfig)
		throws OAException
	{
		String sClass = oConfigManager.getParam(elSPProviderConfig, "class");
        if (sClass == null) {
            _oLogger.error("No 'class' item found in '"+EL_SP_PROVIDER+"' section");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        Class<?> oClass = null;
        try {
            oClass = Class.forName(sClass);
        }
        catch (Exception e) {
            _oLogger.error("No 'class' found with name: " + sClass, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
		
		ISPProvider oProvider = null;
        try {
        	oProvider = (ISPProvider) oClass.newInstance();
        }
        catch (Exception e) {
            _oLogger.error("Could not create 'ISPProvider' instance of the 'class' with name: " 
                + sClass, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        // Initialize the SPProvider
        oProvider.start(oConfigManager, elSPProviderConfig);
		
		return oProvider;
	}
	
	
	/**
	 * Helper to instantiate and start a configured IDPProvider from configuration 
	 * @param oConfigManager
	 * @param elIDPProviderConfig
	 * @return
	 * @throws OAException
	 */
	protected IIDPProvider createIDPProvider(IConfigurationManager oConfigManager, 
			Element elIDPProviderConfig)
		throws OAException
	{
		String sClass = oConfigManager.getParam(elIDPProviderConfig, "class");
        if (sClass == null) {
            _oLogger.error("No 'class' item found in '"+EL_IDP_PROVIDER+"' section");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        Class<?> oClass = null;
        try {
            oClass = Class.forName(sClass);
        }
        catch (Exception e) {
            _oLogger.error("No 'class' found with name: " + sClass, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
		
		IIDPProvider oProvider = null;
        try {
        	oProvider = (IIDPProvider) oClass.newInstance();
        }
        catch (Exception e) {
            _oLogger.error("Could not create 'IIDPProvider' instance of the 'class' with name: " 
                + sClass, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        // Initialize the IDP Provider
        oProvider.start(oConfigManager, elIDPProviderConfig);
		
		return oProvider;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public String getID() {
		return _sID;
	}

	/**
	 * {@inheritDoc}
	 */
	public List<IIDP> getIDPs(HttpServletRequest oRequest) {
		if (_oIDPProvider == null) {
			return new ArrayList<IIDP>();
		}
		
		return _oIDPProvider.getIDPs();
	}

	/**
	 * {@inheritDoc}
	 */
	public List<IRequestor> getRequestors(HttpServletRequest oRequest) {
		if (_oSPProvider == null) {
			return new ArrayList<IRequestor>();
		}
		
		return _oSPProvider.getSPs();
	}

}
