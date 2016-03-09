/*
 * Asimba Server
 * 
 * Copyright (c) 2015, Gluu
 * Copyright (C) 2013 Asimba
 * Copyright (C) 2007-2008 Alfa & Ariss B.V.
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
 * gluu-Asimba - Serious Open Source SSO - More information on www.gluu.org
 * 
 */
package org.gluu.asimba.engine.requestor.ldap;

import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.requestor.Requestor;
import com.alfaariss.oa.engine.core.requestor.RequestorException;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import org.gluu.asimba.util.ldap.LDAPUtility;
import org.gluu.asimba.util.ldap.sp.RequestorPoolEntry;
import org.gluu.asimba.util.ldap.sp.RequestorEntry;

/**
 * Requestor pool factory.
 *
 * Reads the information from LDAP.
 *
 * @author Dmitry Ognyannikov
 */
public class LDAPRequestorPool extends RequestorPool {

    private static final Log _logger = LogFactory.getLog(LDAPRequestorPool.class);
    
    /**
     * Creates the object.
     *
     * @param oConfigurationManager The configuration manager where the config
     * can be read from.
     * @param eConfig The configuration base section.
     * @throws RequestorException
     */
    public LDAPRequestorPool(RequestorPoolEntry entry) throws RequestorException {
        super("", "", true, false, "", "", "", new HashSet<IRequestor>(), new ArrayList<String>());
        
        try {
            _sID = entry.getId();
            if (_sID == null || "".equals(_sID)) {
                _logger.error("Empty LDAP RequestorPool's ID found in configuration");
                throw new RequestorException(SystemErrors.ERROR_CONFIG_READ);
            }
            _sFriendlyName = entry.getFriendlyName();
            
            _bEnabled = entry.isEnabled();

            if (entry.getPreAuthorizationProfileID() != null && !"".equals(entry.getPreAuthorizationProfileID())) {
                _sPreAuthorizationProfileID = entry.getPreAuthorizationProfileID();
            }

            if (entry.getPostAuthorizationProfileID() != null && !"".equals(entry.getPostAuthorizationProfileID())) {
                _sPostAuthorizationProfileID = entry.getPostAuthorizationProfileID();
            }

            if (entry.getAttributeReleasePolicyID() != null && !"".equals(entry.getAttributeReleasePolicyID())) {
                _sAttributeReleasePolicyID = entry.getAttributeReleasePolicyID();
            }
            
            _bForcedAuthenticate = entry.isForcedAuthenticate();
            
            if (entry.getAuthenticationProfileIDs() != null && !"".equals(entry.getAuthenticationProfileIDs())) {
                String profiles[] = entry.getAuthenticationProfileIDs().split(" ");
                for (String id : profiles) {
                    _listAuthenticationProfileIDs.add(id);
                }
            }

            if (entry.getProperties() == null) {
                _logger.info("No 'properties' section found, no extended properties found for LDAP requestorpool: " + _sID);
                _properties = new Properties();
            } else {
                _properties = entry.getProperties();
            }
            
            // load requestors
            List<RequestorEntry> requestors = LDAPUtility.loadRequestorsForPool(_sID);
            for (RequestorEntry rEntry : requestors) {
                try {
                    addRequestor(createRequestor(rEntry));
                    _logger.info("Requestor has been loded to LDAPRequestorPool, id: " + rEntry.getId() + 
                            ", LDAPRequestorPool id: " + _sID);
                } catch (Exception e) {
                    _logger.error("LDAPRequestorPool Internal error while reading requestor: " + entry.getId());
                }
            }
            
        } catch (RequestorException e) {
            _logger.error("Internal error during pool object update", e);
            throw e;
        } catch (Exception e) {
            _logger.fatal("Internal error during pool object update", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
        }
        
        
    }

    private Requestor createRequestor(RequestorEntry requestorEntry) throws RequestorException {
        Requestor oRequestor = null;
        try {
            if (requestorEntry.getId() == null || "".equals(requestorEntry.getId())) {
                _logger.error("No 'id' item in LDAP 'requestor' entry found in configuration");
                throw new RequestorException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            oRequestor = new Requestor(requestorEntry.getId(), requestorEntry.getFriendlyName(), requestorEntry.isEnabled(), requestorEntry.getProperties(), requestorEntry.getLastModified());
            _logger.info("Found: " + oRequestor);
        } catch (RequestorException e) {
            _logger.error("Internal error during pool object creation", e);
            throw e;
        } catch (Exception e) {
            _logger.fatal("Internal error during pool object update", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL, e);
        }

        return oRequestor;
    }

}
