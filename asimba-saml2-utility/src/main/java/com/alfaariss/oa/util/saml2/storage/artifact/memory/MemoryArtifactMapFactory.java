/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
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
 * Asimba - Serious Open Source SSO - More information on www.asimba.org
 * 
 */
package com.alfaariss.oa.util.saml2.storage.artifact.memory;
import java.util.Hashtable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.xml.io.MarshallingException;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.storage.IStorageFactory;
import com.alfaariss.oa.util.saml2.storage.artifact.ArtifactMapEntry;
import com.alfaariss.oa.util.storage.factory.AbstractStorageFactory;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * OA style memory implementation of a <code>SAMLArtifactMap</code>.
 *
 * Uses a {@link Hashtable} as storage.
 * 
 * @author MHO
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class MemoryArtifactMapFactory extends AbstractStorageFactory 
    implements SAMLArtifactMap
{  
    //The system logger
    private Log _logger;
    //The storage
    private Map<String, SAMLArtifactMapEntry> _storage;
       
	/**
     * Create a new <code>JDBCFactory</code>.
     */
    public MemoryArtifactMapFactory()
    {
        super();        
        _logger = LogFactory.getLog(MemoryArtifactMapFactory.class);
        _storage = new HashMap<>();
    }

    /**
     * Start cleaner.
     * @see IStorageFactory#start()
     */
    @Override
    public void start() throws OAException
    {        
        if(_tCleaner != null)
            _tCleaner.start();    
    }
 
    /**
     * @see org.opensaml.common.binding.artifact.SAMLArtifactMap#contains(java.lang.String)
     */
    @Override
    public boolean contains(String artifact)
    {
        return _storage.containsKey(artifact);
    }

    /**
     * @see org.opensaml.common.binding.artifact.SAMLArtifactMap#get(java.lang.String)
     */
    @Override
    public SAMLArtifactMapEntry get(String artifact)
    {
        if (artifact == null) 
            throw new IllegalArgumentException("Given artifact is empty");
        return _storage.get(artifact);         
    }

    /**
     * @see org.opensaml.common.binding.artifact.SAMLArtifactMap#put(
     * java.lang.String, java.lang.String, java.lang.String, org.opensaml.common.SAMLObject)
     */
    @Override
    public void put(String artifact, String relyingPartyId, String issuerId,
        SAMLObject samlMessage) throws MarshallingException
    {
       _storage.put(artifact, new ArtifactMapEntry(artifact, 
           issuerId, relyingPartyId, 
           System.currentTimeMillis() + _lExpiration, samlMessage));       
    }

    /**
     * @see org.opensaml.common.binding.artifact.SAMLArtifactMap#remove(java.lang.String)
     */
    @Override
    public void remove(String artifact)
    {
        if (artifact == null) 
            throw new IllegalArgumentException("Given artifact is empty");
        _storage.remove(artifact);
        
    }

    /**
     * Remove expired artifacts.
     * @see com.alfaariss.oa.api.storage.clean.ICleanable#removeExpired()
     */
    @Override
    public void removeExpired() throws PersistenceException
    {
        Iterator<String> eArtifacts = _storage.keySet().iterator();
        while(eArtifacts.hasNext()) //Thread safe iteration
        {
            String sArtifact = eArtifacts.next();
            SAMLArtifactMapEntry entry = _storage.get(sArtifact);
            if(entry.isExpired())
            {
                _storage.remove(sArtifact);
                _logger.debug("Artifact Expired: " + sArtifact);
            }
        }                
    }
}