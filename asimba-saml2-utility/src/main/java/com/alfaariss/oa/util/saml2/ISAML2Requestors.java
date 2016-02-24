/*
 * Asimba Server
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
package com.alfaariss.oa.util.saml2;

import java.util.Hashtable;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.metadata.provider.management.MdMgrManager;
import org.asimba.util.saml2.metadata.provider.management.MetadataProviderManagerUtil;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;

/**
 * SAML2 Requestors, used to manage SAML2Requestor instances.
 * 
 * @author Dmitry Ognyannikovv, 2016
 */
public interface ISAML2Requestors
{  
    /**
     * Removes the object from memory.
     */
    public void destroy();
    
    /**
     * Returns the default singing value. 
     * @return TRUE if signing is enabled.
     */
    public boolean isDefaultSigningEnabled();
    
    /**
     * Returns a SAML2 Requestor instance, with SAML2 specific config items.
     * The SAML2Requestor is either instantiated on server startup (through ConfigManager),
 or when no ISAML2Requestors were estblished on startup using ConfigManager, a new
 SAML2Requestor instance is created on the fly (typically when using a JDBC source for 
 Requestor configuration)
     *
     * @param oRequestor The OA requestor object.
     * @return SAML2Requestor or <code>null</code> if supplied IRequestor is <code>null</code>.
     * @throws OAException if requestor object could not be created.
     * @since 1.1
     */
    public SAML2Requestor getRequestor(IRequestor oRequestor) throws OAException;
}
