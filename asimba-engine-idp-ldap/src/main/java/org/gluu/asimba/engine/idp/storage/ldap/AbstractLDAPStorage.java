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
package org.gluu.asimba.engine.idp.storage.ldap;

import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.engine.core.idp.storage.IIDPStorage;
import java.util.Properties;
import org.gluu.asimba.util.ldap.LDAPConfigurationLoader;
import org.gluu.asimba.util.ldap.LdapIDPEntry;

/**
 * IDP Storage implementation using LDAP.
 * 
 * @author Dmitry Ognyannikov
 */
abstract public class AbstractLDAPStorage<IDP extends IIDP> implements IIDPStorage {
    
    /** System logger */
    private static final Log _logger = LogFactory.getLog(AbstractLDAPStorage.class);;
    /** Hashtable containing all IDP's */
    protected Hashtable<String, IDP> _htIDPs;
    /** List containing all IDP's*/
    protected List<IIDP> _listIDPs;
    
    public AbstractLDAPStorage() {
        _htIDPs = new Hashtable<String, IDP>();
        _listIDPs = new Vector<IIDP>();
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#exists(java.lang.String)
     */
    @Override
    public boolean exists(String id) {
        return _htIDPs.containsKey(id);
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getAll()
     */
    @Override
    public List<IIDP> getAll() {
        return Collections.unmodifiableList(_listIDPs);
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getIDP(java.lang.String)
     */
    @Override
    public IIDP getIDP(String id) {
        return _htIDPs.get(id);
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void start(IConfigurationManager configManager, Element config)
        throws OAException {
        Properties props = new Properties();
        props.setProperty("bindDN", "cn=directory manager");
        props.setProperty("baseDNs", "o=gluu");
        props.setProperty("bindPassword", "Ni2Bih3nCUU=");
        props.setProperty("servers", "localhost:1636");
        props.setProperty("maxconnections", "4");
        props.setProperty("useSSL", "true");
        props.setProperty("configurationEntryDN", "ou=oxauth,ou=configuration,inum=@!16BD.0CCC.B2A2.7B12!0002!5359.316B,ou=appliances,o=gluu");
        props.setProperty("binaryAttributes", "objectGUID");
        
        LDAPConfigurationLoader loader = new LDAPConfigurationLoader();
        loader.loadConfiguration(props);
        List<LdapIDPEntry> idpEntries = loader.getIdpEntries();
        
        for (LdapIDPEntry idpEntry : idpEntries) {
            IDP idp = createIDP(idpEntry);
            
            if (_htIDPs.containsKey(idp.getID())) {
                _logger.error("Configured IDP is not unique: " + idp.getID());
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            boolean bEnabled = true;
            //TODO: check enabled - where?
            
            if (!bEnabled) {
                _logger.info("IDP disabled: " + idp.getID());
            }
            else {
                _htIDPs.put(idp.getID(), idp);
                _listIDPs.add(idp);
                
                _logger.info("Found IDP with ID: " + idp.getID());
            }
        }
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#stop()
     */
    @Override
    public void stop() {
        if (_listIDPs != null)
            _listIDPs.clear();
        
        if (_htIDPs != null)
            _htIDPs.clear();
    }

    /**
     * Creates the IDP object by reading it's configuration.
     * 
     * @param configManager The configuration manager.
     * @param config The configuration of the IDP object.
     * @return The configured IDP.
     * @throws OAException if IDP could not be created.
     */
    abstract protected IDP createIDP(LdapIDPEntry idpEntry) throws OAException;
    
}
