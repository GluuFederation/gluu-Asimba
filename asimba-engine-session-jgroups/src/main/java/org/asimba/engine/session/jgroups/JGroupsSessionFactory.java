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
package org.asimba.engine.session.jgroups;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.Map.Entry;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.engine.cluster.ClusterConfiguration;
import org.asimba.engine.core.cluster.ICluster;
import org.jgroups.JChannel;
import org.jgroups.blocks.ReplicatedHashMap;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.session.SessionException;
import com.alfaariss.oa.engine.core.session.factory.ISessionFactory;
import com.alfaariss.oa.util.ModifiedBase64;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.storage.factory.AbstractStorageFactory;

public class JGroupsSessionFactory extends AbstractStorageFactory implements
		ISessionFactory<JGroupsSession> 
{
	public static final String EL_CONFIG_CLUSTERID = "cluster_id";
	
	private static Log _oLogger = LogFactory.getLog(JGroupsSessionFactory.class);
	private static Log _oEventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);

	private ReplicatedHashMap<String, JGroupsSession> _mSessions;
	
	private ICluster _oCluster;
	
	
	@Override
	public void start() throws OAException 
	{
		// this._configManager and this._eConfig are initialized at this point:
		if (_oCluster == null) {
			ClusterConfiguration oClusterConfiguration = new ClusterConfiguration(_configurationManager);
			_oCluster = oClusterConfiguration.getClusterFromConfigById(_eConfig, EL_CONFIG_CLUSTERID);
		}
		
		JChannel jChannel = (JChannel) _oCluster.getChannel();
		_mSessions = new ReplicatedHashMap<String, JGroupsSession>( jChannel );
		try {
			// start gets the shared state in local hashmap, it is blocking,
			// the timeout is not applied to the time needed to get the remote state
			_mSessions.start(100000);
		} catch (Exception e) {
			_oLogger.error("Could not start Replicated HashMap: "+e.getMessage(), e);
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		}

		// TODO: This should move to superclass instead:
		if(_tCleaner != null)
			_tCleaner.start();
	}
	
	public void startForTesting(IConfigurationManager configurationManager, Element clusterElement,
			ICluster clusterConfig, SecureRandom secureRandom, long expiration)
			throws OAException
	{
		_configurationManager = configurationManager;
		_eConfig = clusterElement;
		_oCluster = clusterConfig;
		_random = secureRandom;
		_lMax = 100000;
		_lExpiration = expiration;
		start();
		_mSessions.setBlockingUpdates(true); // otherwise unit tests usually fail
	}
	
	@Override
	public void stop() 
	{
		// TODO: Ensure that stop/start of a JGroupsSessionFactory results in consistent state
		super.stop();
		
		if (_mSessions != null) {
			_oLogger.debug("Stopping Replicated HashMap");
			_mSessions.stop();
		}
		
		if (_oCluster != null) {
			_oLogger.debug("Closing cluster "+_oCluster.getID());
			_oCluster.close();
		}
	}

	
	@Override
	public void removeExpired() throws PersistenceException 
	{
        long lNow = System.currentTimeMillis();

        for ( Entry<String,JGroupsSession> entry : _mSessions.entrySet() )
        {
            JGroupsSession session = entry.getValue();

            if( session.getSessionExpTime().getTime() <= lNow )
            {
                String id = session.getId();

                _oLogger.debug("Session Expired: " + id);

                IUser sessionUser = session.getUser();
                
                _oLogger.info(new UserEventLogItem(session, null, 
                    UserEvent.SESSION_EXPIRED, this, "clean"));
                
                _mSessions.remove(entry.getKey());
            }
        }		
	}
	
	@Override
	public boolean exists(Object id) throws PersistenceException 
	{
		return _mSessions.containsKey(id);
	}

	
	@Override
	public void persist(JGroupsSession oSession) throws PersistenceException 
	{
		String sSessionId = oSession.getId();
		if (sSessionId == null) {	// new session
			byte[] baId = new byte[ISession.ID_BYTE_LENGTH];
			
			int iAllowedIdGenAttempts = 1000;
			do
			{                
				_random.nextBytes(baId);
				try
				{
					sSessionId = ModifiedBase64.encode(baId);
				}
				catch (UnsupportedEncodingException e)
				{
					_oLogger.error("Could not create session id for byte[]: " + baId, e);
					throw new PersistenceException(SystemErrors.ERROR_INTERNAL);
				}
				iAllowedIdGenAttempts--;
			}
			while(_mSessions.containsKey(sSessionId) && (iAllowedIdGenAttempts>0)); //Key already exists   
	
			if (_mSessions.containsKey(sSessionId)) {
				_oLogger.error("Could not persist Session because could not generate ID (which is weird!)");
				throw new PersistenceException(SystemErrors.ERROR_INTERNAL);
			}

			oSession.setId(sSessionId);
			oSession.setExpTime(System.currentTimeMillis() + _lExpiration);
			_mSessions.put(sSessionId, oSession);
			
			_oLogger.info("New session added: " + sSessionId + " for requestor '" + oSession.getRequestorId() + "'");
		}
		else if (oSession.isExpired()) {
			_oLogger.info("Session expired: " + sSessionId);
			
			_oEventLogger.info(new UserEventLogItem(oSession, null, 
	                UserEvent.SESSION_EXPIRED, this, null));
			_mSessions.remove(sSessionId);
		}
		else { // Update
			long lExpiration = System.currentTimeMillis() + _lExpiration;
            oSession.setExpTime(lExpiration);
            _mSessions.put(sSessionId, oSession);	// send updated JGroupsSession to ReplicatedHashMap
            
            _oLogger.info("Existing session(s) updated: " + sSessionId + " for requestor '" +
            		oSession .getRequestorId() + "'");
		}
	}

	
	@Override
	public void persist(JGroupsSession[] aoSession) throws PersistenceException 
	{
		for(JGroupsSession oSession : aoSession) {
            persist(oSession);
		}
	}

	
	@Override
	public long poll() throws OAException 
	{
		if (_mSessions == null) return 0;
		return _mSessions.size();
	}

	
	@Override
	public String getAuthority() 
	{
		return ISessionFactory.AUTHORITY_NAME;
	}

	
	@Override
	public ISession createSession(String sRequestorId) throws SessionException 
	{
		if(sRequestorId == null) {
            throw new IllegalArgumentException("Supplied requestor id is empty");
		}
		
		if(_lMax > 0 && _mSessions.size() >= _lMax)
        {
            _oLogger.error("Could not create session, maximum reached");
            throw new SessionException(SystemErrors.ERROR_SESSION_MAX);
        }
		
        return new JGroupsSession(this, sRequestorId);
	}

	
	@Override
	public JGroupsSession retrieve(Object oSessionId) throws PersistenceException 
	{
		JGroupsSession oSession = _mSessions.get(oSessionId);
		if (oSession != null) {
			oSession.resuscitate(this);
		}
		
		return oSession;
	}

	public Integer size() {
		return _mSessions.size();
	}

}
