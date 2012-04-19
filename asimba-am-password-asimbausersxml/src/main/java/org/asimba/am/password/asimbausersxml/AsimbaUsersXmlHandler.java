/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
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
package org.asimba.am.password.asimbausersxml;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.password.AbstractPasswordHandler;
import com.alfaariss.oa.authentication.password.IResourceHandler;

public class AsimbaUsersXmlHandler extends AbstractPasswordHandler {
	
	/**
	 * Logger instance
	 */
	private Logger _oLogger;
	
	
	/**
	 * Default constructor
	 */
	public AsimbaUsersXmlHandler() {
		_oLogger = Logger.getLogger(AsimbaUsersXmlHandler.class);
	}
	
	@Override
	public void start(IConfigurationManager oCM, Element elConfig)
			throws OAException 
	{
		// Let abstract parent start first
		super.start(oCM, elConfig);
		
		// .. and continue ourselves:
		try 
        {
            Element elResourceSection;
            
            elResourceSection = oCM.getSection(elConfig, "resource");
            if (elResourceSection == null)
            {
                _oLogger.error("There must be a resource configured for AsimbaUsersXml");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            // Instantiate and add all the configured resource handlers
            while (elResourceSection != null)
            {
                IResourceHandler oAsimbaUsersXmlResource = new AsimbaUsersXmlResource();
                oAsimbaUsersXmlResource.init(oCM, elResourceSection);

                addResourceHandler(oAsimbaUsersXmlResource);

                // proceed with next ResourceHandler
                elResourceSection = oCM.getNextSection(elResourceSection);
            }

            setDefault(oCM, elConfig);

        } 
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _oLogger.fatal("Something went seriously wrong when starting AsimbaUsersXml Password handler", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
	}
}
