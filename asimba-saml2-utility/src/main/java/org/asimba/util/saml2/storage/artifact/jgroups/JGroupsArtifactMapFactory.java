/*
 * Asimba Server
 * 
 * Copyright (C) 2015 Asimba
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
package org.asimba.util.saml2.storage.artifact.jgroups;

import java.util.Map.Entry;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.engine.cluster.ClusterConfiguration;
import org.asimba.engine.core.cluster.ICluster;
import org.jgroups.JChannel;
import org.jgroups.blocks.ReplicatedHashMap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.xml.io.MarshallingException;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.util.saml2.storage.artifact.ArtifactMapEntry;
import com.alfaariss.oa.util.storage.factory.AbstractStorageFactory;
import org.w3c.dom.Element;

public class JGroupsArtifactMapFactory extends AbstractStorageFactory implements SAMLArtifactMap 
{
    public static final String EL_CONFIG_CLUSTERID = "cluster_id";
    public static final String EL_CONFIG_BLOCKING_MODE = "blocking_mode";
    public static final String EL_CONFIG_BLOCKING_TIMEOUT = "blocking_timeout";
    public static final String EL_CONFIG_STATE_TIMEOUT = "state_timeout";
    public static final long STATE_TIMEOUT_DEFAULT = 100000;

	
	private static final Log _oLogger = LogFactory.getLog(JGroupsArtifactMapFactory.class);

	private ReplicatedHashMap<String, SAMLArtifactMapEntry> _mArtifacts;

	private ICluster _oCluster;


	@Override
	public void start() throws OAException 
	{
		if (_oCluster ==  null) {
			// this._configManager and this._eConfig are initialized at this point:
			ClusterConfiguration oClusterConfiguration = new ClusterConfiguration(_configurationManager);
			_oCluster = oClusterConfiguration.getClusterFromConfigById(_eConfig, EL_CONFIG_CLUSTERID);
		}
		
		JChannel jChannel = (JChannel) _oCluster.getChannel();
		_mArtifacts = new ReplicatedHashMap<>( jChannel );
        
        String sBlockingMode = _configurationManager.getParam(_eConfig, EL_CONFIG_BLOCKING_MODE);
        if (sBlockingMode != null) {
            if (sBlockingMode.equalsIgnoreCase("true") || sBlockingMode.equalsIgnoreCase("false")) {
                Boolean bBlockingMode = Boolean.valueOf(sBlockingMode);
                _mArtifacts.setBlockingUpdates(bBlockingMode);
            }
            else{
                _oLogger.error("Invalid value in config for <" + EL_CONFIG_BLOCKING_MODE + ">, using default.");
            }
        }
        else {
            _mArtifacts.setBlockingUpdates(true);
        }
        
        String sBlockingTimeout = _configurationManager.getParam(_eConfig, EL_CONFIG_BLOCKING_TIMEOUT);
        if (sBlockingTimeout != null) {
            try {
                Long lBlockingTimeout = new Long(sBlockingTimeout);
                _mArtifacts.setTimeout(lBlockingTimeout);
            }
            catch (java.lang.NumberFormatException e) {
                _oLogger.error("Invalid value in config for <" + EL_CONFIG_BLOCKING_TIMEOUT + ">, using default.");
            }
        }
        
        Long lStateTimeout = STATE_TIMEOUT_DEFAULT;
        String sStateTimeout = _configurationManager.getParam(_eConfig, EL_CONFIG_STATE_TIMEOUT);
        if (sStateTimeout != null) {
            try {
                lStateTimeout = new Long(sStateTimeout);
            }
            catch (java.lang.NumberFormatException e) {
                _oLogger.error("Invalid value in config for <" + EL_CONFIG_STATE_TIMEOUT + ">, using default.");
            }
        }
        

		try {
			// start gets the shared state in local hashmap, it is blocking,
			// the timeout is not applied to the time needed to get the remote state
			_mArtifacts.start(lStateTimeout);
		} catch (Exception e) {
			_oLogger.error("Could not start Replicated HashMap: "+e.getMessage(), e);
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		}

		// TODO: This should move to superclass instead:
		if(_tCleaner != null)
			_tCleaner.start();
	}


	public void startForTesting(IConfigurationManager configMgr, Element clusterElement, ICluster clusterConfig, long expiration)
			throws OAException 
	{
		_configurationManager = configMgr;
		_oCluster = clusterConfig;
		_lExpiration = expiration;
        _eConfig = clusterElement;
		start();
	}

	
	@Override
	public void removeExpired() throws PersistenceException 
	{
        long lNow = System.currentTimeMillis();

        for ( Entry<String,SAMLArtifactMapEntry> entry : _mArtifacts.entrySet() )
        {
        	SAMLArtifactMapEntry session = entry.getValue();

            if( session.getExpirationTime().getMillis() <= lNow )
            {
                String id = session.getIssuerId();

                _oLogger.debug("Session Expired: " + id);

                _mArtifacts.remove(entry.getKey());
            }
        }		
	}
	

	
	@Override
	public boolean contains(String artifact) {
		return _mArtifacts.containsKey(artifact);
	}


	@Override
	public SAMLArtifactMapEntry get(String artifact) {
		if (artifact == null) 
            throw new IllegalArgumentException("Given artifact is empty");
        return _mArtifacts.get(artifact);	
	}

	
	@Override
	public void put(String artifact, String relyingPartyId, String issuerId, 
			SAMLObject samlMessage) throws MarshallingException {
		
		_mArtifacts.put(artifact, new ArtifactMapEntry(artifact, 
	               issuerId, relyingPartyId, 
	               System.currentTimeMillis() + _lExpiration, samlMessage));       
	}


	@Override
	public void remove(String artifact) {
        if (artifact == null) 
            throw new IllegalArgumentException("Given artifact is empty");
        _mArtifacts.remove(artifact);
	}
	
	
	public int size() {
		return _mArtifacts.size();
	}
    
    public boolean isBlockingUpdates() {
        return _mArtifacts.isBlockingUpdates();
    }
    
    public long getTimeout() {
        return _mArtifacts.getTimeout();
    }
}
