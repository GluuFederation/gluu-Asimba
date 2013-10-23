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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.utility.profile.ProfileUtils;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IService;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.profile.IRequestorProfile;

public class CatalogProfile implements IRequestorProfile, IService {
	/**
	 * Configuration element names
	 */
	public static final String EL_CATALOGS = "catalogs";
	public static final String EL_CATALOG = "catalog";
	public static final String ATTR_ALIAS = "alias";
	
	
	/**
	 * Local logger instance
	 */
    private Log _oLogger;

    
    /**
     * Configurable ID of the Catalog profile
     */
    protected String _sID;
    
    
    /**
     * A map of alias->catalog instances
     */
    protected Map<String, ICatalog> _mCatalogs;
    
	
    /**
     * Default constructor
     */
    public CatalogProfile() {
    	_oLogger = LogFactory.getLog(CatalogProfile.class);
    }
    
    
	public void init(ServletContext context,
			IConfigurationManager oConfigManager, Element eConfig)
			throws OAException 
	{
		_mCatalogs = new HashMap<String, ICatalog>();
		
		_sID = oConfigManager.getParam(eConfig, "id");
        if (_sID == null)
        {
        	_oLogger.error("No 'id' item found in 'profile' section in configuration");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        Element elCatalogs = oConfigManager.getSection(eConfig, EL_CATALOGS);
        if (elCatalogs == null) {
            _oLogger.warn("No '"+EL_CATALOGS+"' item found, no catalogs will be provided!");
        } else {
        	Element elCatalog = oConfigManager.getSection(elCatalogs, EL_CATALOG);
        	while (elCatalog != null) {
        		ICatalog oCatalog = createCatalog(oConfigManager, elCatalog);
        		_mCatalogs.put(oCatalog.getID(), oCatalog); 
        		
        		elCatalog = oConfigManager.getNextSection(elCatalog);
        	}
        }
		
		_oLogger.info("Initialized CatalogProfile '"+_sID+"'");
	}

	
	public void destroy() {
		// Clean up catalog instances
		for (ICatalog c: _mCatalogs.values()) {
			c.stop();
		}
		
		_mCatalogs.clear();
		_oLogger.info("Destroyed CatalogProfile '"+_sID+"'");
	}

	
	/**
	 * {@inheritDoc}
	 */
	public String getID() {
		return _sID;
	}
	
	
	/**
	 * Configuration helper to start a new Catalog instance from provided configuration
	 * @param oConfigManager
	 * @param elCatalogConfig
	 * @return Instantiated and started Catalog instance 
	 */
	protected ICatalog createCatalog(IConfigurationManager oConfigManager, 
			Element elCatalogConfig)
		throws OAException
	{
		String sClass = oConfigManager.getParam(elCatalogConfig, "class");
        if (sClass == null) {
            _oLogger.error("No 'class' item found in '"+EL_CATALOG+"' section");
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

        ICatalog oCatalog = null;
        try {
            oCatalog = (ICatalog) oClass.newInstance();
        }
        catch (Exception e) {
            _oLogger.error("Could not create 'ICatalog' instance of the 'class' with name: " 
                + sClass, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        // Initialize the Catalog handler
        oCatalog.start(oConfigManager, elCatalogConfig);
        
        // And deliver
        return oCatalog;
	}
	
	
	/**
	 * Figure out which catalog was requested from the HttpServetRequest
	 * @param oRequest
	 * @return null if no handler could be established
	 */
	protected ICatalog establishCatalogHandler(HttpServletRequest oRequest) {
		String sHandler = ProfileUtils.endpointFromURI(oRequest.getContextPath(),
				getID(), oRequest.getRequestURI());
		if (sHandler == null) return null;
		
		return _mCatalogs.get(sHandler);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public void service(HttpServletRequest oServletRequest,
			HttpServletResponse oServletResponse) throws OAException 
	{
		ICatalog oCatalog= establishCatalogHandler(oServletRequest);
		
		if (oCatalog != null) {
			oCatalog.service(oServletRequest, oServletResponse);
		} else {
			String sErrorMessage = "Invalid catalog requested: "+oServletRequest.getRequestURI(); 
			_oLogger.warn(sErrorMessage);
			
			try {
                if (!oServletResponse.isCommitted()) {
                	oServletResponse.sendError(HttpServletResponse.SC_NOT_FOUND
                            , sErrorMessage);
                }
            } catch (IOException ioe) {
              _oLogger.warn("Could not send response", ioe);
            }
		}
		
		return;
	}


}
