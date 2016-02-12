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
package org.asimba.engine.core.confederation.configuration;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.engine.core.confederation.IConfederation;
import org.asimba.engine.core.confederation.IConfederationFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * Configure the confederations from asimba.xml configuration file
 *
 * Configuration is something like this:
 * <confederations class="...ConfederationConfigurationFactory">
 *   <confederation id="[the-id]" enabled="[true/false]" class="...IConfederationImplementation">
 *     [confederation-implementation-specific parameters]
 *   </confederation>
 *   ...
 *   <confederation id="[the-id]" enabled="[true/false]" class="...IConfederationImplementation">
 *     [confederation-implementation-specific parameters]
 *   </confederation>
 * </confederations>
 * 
 * @author mdobrinic
 *
 */
public class ConfederationConfigurationFactory implements
		IConfederationFactory, IComponent 
{
    /** Configuration elements */
    public static final String EL_CONFEDERATION = "confederation";

    /**
     * Local logger instance
     */
    private static final Log _oLogger = LogFactory.getLog(ConfederationConfigurationFactory.class);

    /**
     * Local reference to configmanager for reloading configuration
     */
    private IConfigurationManager _oConfigManager;
    
    /**
     * Map of available confederations
     */
    private Map<String, IConfederation> _mConfederations;

    
    @Override
	public void start(IConfigurationManager oConfigManager,
			Element eConfig) throws OAException 
	{
		_oConfigManager = oConfigManager;
		
		_oLogger.info("Starting Confederation configuration");
		_mConfederations = new HashMap<String, IConfederation>();
		
		
        Element elConfederation = oConfigManager.getSection(eConfig, EL_CONFEDERATION);
        if (elConfederation == null) {
            _oLogger.warn("No '"+EL_CONFEDERATION+"' item found, no confederations available!");
        } else {
        	while (elConfederation != null) {
        		IConfederation oConfederation = createConfederation(oConfigManager, elConfederation);
        		_mConfederations.put(oConfederation.getID(), oConfederation); 
        		_oLogger.info("Established confederation '"+oConfederation.getID()+"'");
        		
        		elConfederation = oConfigManager.getNextSection(elConfederation);
        	}
        }
        
		_oLogger.info("Started Confederation configuration");
	}

	@Override
	public void restart(Element eConfig) throws OAException {
		synchronized (this) {
			stop();
			start(_oConfigManager, eConfig);
		}
	}

	@Override
	public void stop() {
		if (_mConfederations != null) {
			for(Entry<String, IConfederation> e: _mConfederations.entrySet()) {
				_oLogger.info("Stopping confederation: "+e.getKey());
				((IComponent)e.getValue()).stop();
			}
		}
	}

	public Map<String, IConfederation> getConfederations() {
		return _mConfederations;
	}

	
	private IConfederation createConfederation(IConfigurationManager oConfigManager, 
			Element elConfederation)
		throws OAException
	{
		String sClass = oConfigManager.getParam(elConfederation, "class");
        if (sClass == null) {
            _oLogger.error("No 'class' item found in '"+EL_CONFEDERATION+"' section");
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

        IConfederation oConfederation = null;
        try {
            oConfederation = (IConfederation) oClass.newInstance();
        }
        catch (Exception e) {
            _oLogger.error("Could not create 'IConfederation' instance of the 'class' with name: " 
                + sClass, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        // Initialize the Catalog handler
        ((IComponent)oConfederation).start(oConfigManager, elConfederation);
        
        // And deliver
        return oConfederation;
	}
}
