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
package org.asimba.util.saml2.nameid.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.util.saml2.NameIDFormatter;

/**
 * DefaultUnspecifiedFormatHandler implements the unspecified NameID format 
 * specification. As in, default behavior is the same as the 
 * DefaultPersistentFormatHandler
 * 
 * This handler must be re-implemented to provide a custom unspecified 
 * implementation for other environments
 * 
 * See the implementation of DefaultPersistentFormatHandler for more details
 * on how this can be done.
 * 
 * Example configuration:
 * <format type="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">
 *   <opaque enabled="true" salt="yah" />
 *   <attribute name="#altUID" removeAfterUse="false" />
 * </format>
 * 
 * 
 * @author mdobrinic
 */
public class DefaultUnspecifiedFormatHandler extends DefaultPersistentFormatHandler {
	
	/**
	 * Local logger instance
	 */
    private static final Log _oLogger = LogFactory.getLog(DefaultUnspecifiedFormatHandler.class);
	
    @Override
    public String format(IUser oUser, String sEntityID, String sTGTID,
			ISession oSession) throws OAException 
	{
    	_oLogger.info("Unspecified format requested for user "+oUser.getID());
    	return super.format(oUser, sEntityID, sTGTID, oSession);
	}

    @Override
	public void init(IConfigurationManager oConfigManager, Element elConfig,
			NameIDFormatter oParentFormatter) throws OAException 
	{
    	_oLogger.info("Unspecified format initializing");
		super.init(oConfigManager, elConfig, oParentFormatter);
	}

}
