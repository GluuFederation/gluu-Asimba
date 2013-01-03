/*
 * Asimba - Serious Open Source SSO
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2009 Alfa & Ariss B.V.
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
package com.alfaariss.oa.sso.web.profile.ssoquery.whitelist.config;

import java.util.List;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.sso.web.profile.ssoquery.whitelist.IWhitelist;

/**
 * Whitelist implementation that uses the configuration as storage.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class ConfigWhitelist implements IWhitelist
{
    private static Log _logger;
    private List<String> _listItems;

    /**
     * Constructor. 
     */
    public ConfigWhitelist()
    {
        _logger = LogFactory.getLog(this.getClass());
        _listItems = new Vector<String>();
    }
    
	/**
	 * @see com.alfaariss.oa.sso.web.profile.ssoquery.whitelist.IWhitelist#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
	 */
	public void start(IConfigurationManager configurationManager, Element config)
			throws OAException 
	{
	    Element eItems = configurationManager.getSection(config, "items");
	    if (eItems == null)
	    {
	        _logger.error("No 'items' section found in 'whitelist' section in configuration");
	        throw new OAException(SystemErrors.ERROR_CONFIG_READ);
	    }
	    
	    Element eItem = configurationManager.getSection(eItems, "item");
	    while (eItem != null)
	    {
	        String value = configurationManager.getParam(eItem, "value");
	        if (value == null)
	        {
	            _logger.error("No 'value' section found in 'item' section in configuration");
	            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
	        }
	        
	        if (_listItems.contains(value))
	        {
	            _logger.error("Configured 'value' in 'item' section is not unique: " + value);
                throw new OAException(SystemErrors.ERROR_INIT);
	        }
	        
	        _listItems.add(value);
	        
	        eItem = configurationManager.getNextSection(eItem);
	    }
	}

	/**
	 * @see com.alfaariss.oa.sso.web.profile.ssoquery.whitelist.IWhitelist#isWhitelisted(java.lang.String)
	 */
	public boolean isWhitelisted(String item) throws OAException 
	{
		return _listItems.contains(item);
	}

	/**
	 * @see com.alfaariss.oa.sso.web.profile.ssoquery.whitelist.IWhitelist#stop()
	 */
	public void stop() 
	{
	    if (_listItems != null)
	        _listItems.clear();
	}

}
