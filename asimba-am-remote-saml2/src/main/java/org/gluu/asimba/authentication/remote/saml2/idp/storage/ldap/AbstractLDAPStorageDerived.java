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
package org.gluu.asimba.authentication.remote.saml2.idp.storage.ldap;

import java.util.Collections;
import java.util.Hashtable;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.remote.saml2.idp.storage.config.IDPConfigStorage;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import java.util.ArrayList;
import org.gluu.asimba.util.ldap.LDAPUtility;
import org.gluu.asimba.util.ldap.idp.IDPEntry;

/**
 * IDP Storage implementation using LDAP.
 * 
 * @author Dmitry Ognyannikov
 */
abstract public class AbstractLDAPStorageDerived<IDP extends IIDP> extends IDPConfigStorage {
    
    /** System logger */
    private static final Log _logger = LogFactory.getLog(AbstractLDAPStorageDerived.class);;
    /** Hashtable containing all IDP's */
    protected Hashtable<String, IDP> _htIDPsLDAP;
    /** List containing all IDP's*/
    protected List<IIDP> _listIDPsLDAP;
    
    public AbstractLDAPStorageDerived() {
        _htIDPsLDAP = new Hashtable<String, IDP>();
        _listIDPsLDAP = new ArrayList<IIDP>();
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#exists(java.lang.String)
     */
    @Override
    public boolean exists(String id) {
        return _htIDPsLDAP.containsKey(id) || super.exists(id);
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getAll()
     */
    @Override
    public List<IIDP> getAll() {
        List<IIDP> result = new ArrayList<>();
        for (IIDP idp : _listIDPsLDAP) {
            result.add(idp);
        }
        
        List<IIDP> parent = super.getAll();
        for (IIDP idp : parent) {
            result.add(idp);
        }
        return Collections.unmodifiableList(result);
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getIDP(java.lang.String)
     */
    @Override
    public IIDP getIDP(String id) {
        if (_htIDPsLDAP.containsKey(id))
            return _htIDPsLDAP.get(id);
        else
            return super.getIDP(id);
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void start(IConfigurationManager configManager, Element config)
        throws OAException {
        super.start(configManager, config);
        
        List<IDPEntry> idpEntries = LDAPUtility.loadIDPs();
        
        for (IDPEntry idpEntry : idpEntries) {
            try {
                IDP idp = createIDP(idpEntry);

                if (_htIDPsLDAP.containsKey(idp.getID())) {
                    _logger.error("Configured IDP is not unique: " + idp.getID());
                    throw new OAException(SystemErrors.ERROR_INIT);
                }

                if (idpEntry.isEnabled()) {
                    _htIDPsLDAP.put(idp.getID(), idp);
                    _listIDPsLDAP.add(idp);

                    _logger.info("Found IDP with ID: " + idp.getID());
                } else  {
                    _logger.info("IDP disabled: " + idp.getID());
                }
            } catch (Exception e) {
                _logger.error("Cannot read LDAP IDPEntry, id: " + idpEntry.getId(), e);
            }
        }
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#stop()
     */
    @Override
    public void stop() {
        super.stop();
        
        if (_listIDPsLDAP != null)
            _listIDPsLDAP.clear();
        
        if (_htIDPsLDAP != null)
            _htIDPsLDAP.clear();
    }

    /**
     * Creates the IDP object by reading it's configuration.
     * 
     * @param idpEntry The LDAP record.
     * @return The configured IDP.
     * @throws OAException if IDP could not be created.
     */
    abstract protected IDP createIDP(IDPEntry idpEntry) throws OAException;
    
}
