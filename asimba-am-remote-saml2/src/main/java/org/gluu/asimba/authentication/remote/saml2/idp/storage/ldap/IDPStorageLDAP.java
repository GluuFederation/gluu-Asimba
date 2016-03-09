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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.remote.saml2.idp.storage.config.SourceID;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;
import org.gluu.asimba.util.ldap.idp.IDPEntry;

/**
 * Uses LDAP as organization storage for SAML2IDPs
 * 
 * 
 * #signing : optional attribute to indicate whether default-signing should be enabled 
 * 		for a SAML2Requestor
 * 
 * mp_manager : optional configuration for metadataprovider manager; if the configuration is
 * 		not provided, a MetadataProviderManager is used by the name of the Profile; if it is
 * 		created, it will also be removed upon destroy() of the SAMLRequestors
 * #id : attribute that indicates the id of the MetadataProviderManager
 * 		that is responsible for managing the MetadataProvider for a SAML2Requestor; when
 * 		mpmanaged_id is not set, the profileId is used to identify the MetadataProviderManager
 * #primary : if true, and if the manager was instantiated, the manager will also be destroyed
 * 		when destroy() of the SAML2Requestors is called. Defaults to false. 
 *
 * 
 * @author Dmitry Ognyannikov
 */
public class IDPStorageLDAP extends AbstractLDAPStorageDerived 
{
    /** Configuration elements */
    public static final String EL_MPMANAGER = "mp_manager";
	
    private final static String DEFAULT_ID = "saml2";
    

    /** Local logger instance */
    private static final Log _logger = LogFactory.getLog(IDPStorageLDAP.class);
    
    private Map<SourceID, SAML2IDP> _mapIDPsOnSourceIDLDAP;
        
    /**
     * Creates the storage.
     */
    public IDPStorageLDAP()
    {
        _mapIDPsOnSourceIDLDAP = new Hashtable<SourceID, SAML2IDP>();
    }

    /**
     * @see com.alfaariss.oa.engine.idp.storage.configuration.AbstractConfigurationStorage#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void start(IConfigurationManager configManager, Element config)
        throws OAException
    {
        super.start(configManager, config);
        
        Enumeration<?> enumIDPs = _htIDPsLDAP.elements();
        while (enumIDPs.hasMoreElements())
        {
            SAML2IDP saml2IDP = (SAML2IDP)enumIDPs.nextElement();
            _mapIDPsOnSourceIDLDAP.put(new SourceID(saml2IDP.getSourceID()), saml2IDP);
        }
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getIDP(java.lang.Object, java.lang.String)
     */
    @Override
    public IIDP getIDP(Object id, String type) throws OAException
    {
        if (type.equals(SAML2IDP.TYPE_ID) && id instanceof String)
            return getIDP((String)id);
        else if (type.equals(SAML2IDP.TYPE_SOURCEID) && id instanceof byte[])
            return getIDPBySourceID((byte[])id);

        // else not supported - call paent
        return super.getIDP(id, type);
    }
    
    /**
     * @see com.alfaariss.oa.engine.idp.storage.configuration.AbstractConfigurationStorage#stop()
     */
    @Override
    public void stop()
    {
        if (_mapIDPsOnSourceIDLDAP != null)
            _mapIDPsOnSourceIDLDAP.clear();
        
        super.stop();
    }

    /**
     * @see com.alfaariss.oa.engine.idp.storage.configuration.AbstractConfigurationStorage#createIDP(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */ 
    @Override
    protected IIDP createIDP(IDPEntry idpEntry) throws OAException {
        SAML2IDP saml2IDP = null;
        
        try
        {
            String sID = idpEntry.getId();
            if (sID == null)
            {
                _logger.error(
                    "No 'id' item found in 'organization' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            byte[] baSourceID = generateSHA1(sID);
            
            saml2IDP = new SAML2IDP(idpEntry, baSourceID, _sMPMId);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error while reading organization configuration", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return saml2IDP;
    }

    /**
     * Resolves the organization specified by it's SourceID.
     *
     * @param baSourceID The SourceID of the organization
     * @return Organization The requested organization object
     */
    @Override
    protected SAML2IDP getIDPBySourceID(byte[] baSourceID)
    {
        SourceID key = new SourceID(baSourceID);
        if (_mapIDPsOnSourceIDLDAP.containsKey(key))
            return _mapIDPsOnSourceIDLDAP.get(new SourceID(baSourceID));
        else
            return super.getIDPBySourceID(baSourceID);
    }

    private byte[] generateSHA1(String id) throws OAException
    {
        try
        {
            MessageDigest dig = MessageDigest.getInstance("SHA-1");
            return dig.digest(id.getBytes("UTF-8"));
        }
        catch (NoSuchAlgorithmException e)
        {
            _logger.error("SHA-1 not supported", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch (UnsupportedEncodingException e)
        {
            _logger.error("UTF-8 not supported", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
}
