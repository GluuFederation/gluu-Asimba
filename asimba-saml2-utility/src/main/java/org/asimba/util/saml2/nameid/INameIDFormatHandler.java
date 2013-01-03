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
package org.asimba.util.saml2.nameid;

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.util.saml2.NameIDFormatter;

/**
 * Interface that specifies how a NameID format can be generated
 *  
 * @author mdobrinic
 *
 */
public interface INameIDFormatHandler {

	/**
	 * Format a NameID value for the User, based on the provided context
	 * @param oUser User to format NameID for
	 * @param sEntityID EntityID of the requestor for the NameID
	 * @param sTGTID ID of the TGT with the session between the user and our IDP  
	 * @param oSession User session with context attributes 
	 * @return String with formatted value for NameID
	 * @throws OAException when something went seriously wrong
	 */
	public String format(IUser oUser, String sEntityID, String sTGTID, ISession oSession) 
	        throws OAException;
	
	
	/**
	 * Do not generate new NameID value, but do make sure that attributes
	 * are removed from the user scope as if format was called in the first place
	 * @param oUser
	 * @param sEntityID
	 * @param sTGTID
	 * @param oSession
	 * @return
	 * @throws OAException
	 */
	public void reformat(IUser oUser, String sEntityID, String sTGTID, ISession oSession) 
	        throws OAException;

	/**
	 * Initialize the INameIDFormatHandler with the provided configuration
	 * @param oConfigManager ConfigurationManager instance to use for processing elConfig
	 * @param elConfig Configuration of the handler
	 * @throws OAException when something went seriously wrong
	 */
	public void init(IConfigurationManager oConfigManager, Element elConfig, 
			NameIDFormatter oParentFormatter)
			throws OAException;
	
	
	/**
	 * Returns whether the scope of the NameIDFormat is limited to a 
	 *   (ServiceProvider-related) domain.
	 * When this is true, a NameID value must be generated for every SP and
	 * shall be cached, as regeneration might not give the same result (transient id)
	 * 
	 * Note that this does *not* imply that there can only be one TGT using the 
	 * same NameID value for the format, as there can be multiple TGT's for the same
	 * user!
	 * @return if domain-scoped, returns true
	 */
	public boolean isDomainScoped();
	
	
	/**
	 * Returns whether the NameID value for the format must be unique amongst
	 * all (active) TGT's.
	 * This is the case for a Transient Identifier, but NOT for a Persistent Identifier,
	 * as there can be multiple (active) TGT's for the same user, which result in
	 * the same NameID values for the same domain  
	 * @return
	 */
	public boolean isDomainUnique();
	
	
	/**
	 * Establish the domain value for the NameID
	 * Defaults to the EntityID, but can be overridden for each SP, so multiple SP's
	 *   can share the same domain value
	 * @return string with the EntityID or overridden domain value
	 */
	public String getDomain(IUser oUser, String sEntityID);
}
