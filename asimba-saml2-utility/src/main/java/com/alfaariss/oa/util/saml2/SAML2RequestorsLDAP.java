/*
 * Asimba Server
 * 
 * Copyright (c) 2016, Gluu
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
package com.alfaariss.oa.util.saml2;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.requestor.Requestor;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.gluu.asimba.util.ldap.LDAPUtility;
import org.gluu.asimba.util.ldap.sp.RequestorEntry;
import org.w3c.dom.Element;

/**
 * Replace ISAML2Requestors with LDAP entries.
 * 
 * Acts as SAML2Requestor cash map.
 * 
 * @author Dmitry Ognyannikov, 2016
 */
public class SAML2RequestorsLDAP extends SAML2Requestors {

    /** Local logger instance */
    private static final Log _logger = LogFactory.getLog(SAML2RequestorsLDAP.class);
    
    /** Cache of the instantiated ISAML2Requestors, mapping [SAML2Requestor.Id]->[SAML2Requestor-instance] */
    private Map<String, SAML2Requestor> _mapRequestors;
    
    /**
     * Constructor.
     * @param configurationManager The config manager.
     * @param config Configuration section; if null, a default initialization is performed.
     * @param sProfileID The OA Profile ID.
     * @throws OAException OAException If creation fails.
     */
    public SAML2RequestorsLDAP(IConfigurationManager configurationManager, 
        Element config, String sProfileID) throws OAException {
        super(configurationManager, config, sProfileID);
        
        // init cash - read LDAP mapRequestors
        _mapRequestors = new HashMap<>();
        List<RequestorEntry> requestors = LDAPUtility.loadRequestors();
        
        for (RequestorEntry requestorEntry : requestors) {
            try {
                Properties properties = requestorEntry.getProperties();
                if (properties == null)
                    properties = new Properties();
                Requestor oRequestor = new Requestor(requestorEntry.getId(), requestorEntry.getFriendlyName(), requestorEntry.isEnabled(), requestorEntry.getProperties(), requestorEntry.getLastModified());
                SAML2Requestor oSAML2Requestor = super.getRequestor(oRequestor);
                _mapRequestors.put(oSAML2Requestor.getID(), oSAML2Requestor);
            } catch (Exception e) {
                _logger.error("Cannot read LDAP Requestor, id: " + requestorEntry.getId(), e);
            }
        }
    }

    /**
     * Read the &lt;requestor&gt; elements from the configuration, instantiate SAML2Requestor-instances
     * and put them in a map with [requestor.id] -&gt; [SAML2Requestor-instance]
     * 
     * @param oConfigManager ConfigManager for processing configuration
     * @param elConfig requestors-configuration containing &lt;requestor$gt; elements
     * @return Map of instantiated ISAML2Requestors
     * @throws OAException
     */
    @Override
    protected Map<String, SAML2Requestor> readRequestors(IConfigurationManager 
        oConfigManager, Element elConfig) throws OAException {
        Map<String, SAML2Requestor> resultMap = new HashMap<>();
        // local requestors from LDAP
        if (_mapRequestors != null)
            for (String key : _mapRequestors.keySet()) {
                resultMap.put(key, _mapRequestors.get(key));
            }
        // parent requestors from XML
        Map<String, SAML2Requestor> mapRequestors = super.readRequestors(oConfigManager, elConfig);
        if (mapRequestors != null)
            for (String key : mapRequestors.keySet()) {
                resultMap.put(key, mapRequestors.get(key));
            }
        return mapRequestors;
    }
    
    @Override
    public void destroy() {
        if (_mapRequestors != null)
            _mapRequestors.clear();
        
        super.destroy();
    }
    
    @Override
    public SAML2Requestor getRequestor(IRequestor oRequestor) throws OAException {
        try
        {
            SAML2Requestor oSAML2Requestor = null;
            
            if (oRequestor == null)
                return null;
            
            oSAML2Requestor = _mapRequestors.get(oRequestor.getID());
            if (oSAML2Requestor == null) {
                oSAML2Requestor = super.getRequestor(oRequestor);
            } 
            
            return oSAML2Requestor;
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal(
                "Internal error resolving a SAML requestor for OA requestor: " 
                + oRequestor.getID(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
}