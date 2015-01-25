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
package org.asimba.engine.tgt.jgroups;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Vector;

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
import com.alfaariss.oa.api.persistence.IEntity;
import com.alfaariss.oa.api.persistence.IEntityManager;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.tgt.ITGTListener;
import com.alfaariss.oa.api.tgt.TGTEventError;
import com.alfaariss.oa.api.tgt.TGTListenerEvent;
import com.alfaariss.oa.api.tgt.TGTListenerException;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.tgt.TGTException;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory;
import com.alfaariss.oa.util.ModifiedBase64;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.storage.factory.AbstractStorageFactory;

public class JGroupsTGTFactory extends AbstractStorageFactory implements ITGTFactory<JGroupsTGT>
{
	public static final String EL_CONFIG_CLUSTERID = "cluster_id";
	public static final String EL_CONFIG_ALIAS_CLUSTERID = "alias_cluster_id";

	private static Log _oLogger = LogFactory.getLog(JGroupsTGTFactory.class);
	private static Log _oEventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
	
	private ReplicatedHashMap<String, JGroupsTGT> _mTGTs;
	private ReplicatedHashMap<String, String> _mAliasMap;
	
	private ICluster _oCluster = null;
	private ICluster _oAliasCluster = null;

	private JChannel _jChannel = null;
	private JChannel _jAliasChannel = null;
	
	private JGroupsTGTAliasStore _oSPAliasStore;
	private JGroupsTGTAliasStore _oIDPAliasStore;

	private List<ITGTListener> _lListeners;


	public JGroupsTGTFactory() {
        super();
    }
	
	/**
	 * Start component instantiates the replicated hashmap, as well as 
	 * start managing the cleaner thread (should be moved to base class)
	 */
	@Override
	public void start() throws OAException 
	{
        _lListeners = new Vector<ITGTListener>();

		// this._configManager and this._eConfig are initialized at this point:
		ClusterConfiguration oClusterConfiguration = new ClusterConfiguration(_configurationManager);
		if (_oCluster == null) {
			_oCluster = oClusterConfiguration.getClusterFromConfigById(_eConfig, EL_CONFIG_CLUSTERID);
		}

		_jChannel = (JChannel) _oCluster.getChannel();
		_mTGTs = new ReplicatedHashMap<String, JGroupsTGT>( _jChannel );
		try {
			// start gets the shared state in local hashmap, it is blocking,
			// the timeout is not applied to the time needed to get the remote state
			_mTGTs.start(100000);
		} catch (Exception e) {
			_oLogger.error("Could not start Replicated HashMap: "+e.getMessage(), e);
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		}

		if (_oAliasCluster == null) {
			_oAliasCluster = 
					oClusterConfiguration.getClusterFromConfigById(_eConfig, EL_CONFIG_ALIAS_CLUSTERID);
		}
		
		_jAliasChannel = (JChannel) _oAliasCluster.getChannel();
		_mAliasMap = new ReplicatedHashMap<String, String>( _jAliasChannel );
		try {
			_mAliasMap.start(100000);
		} catch (Exception e) {
			_oLogger.error("Could not start Replicated HashMap: "+e.getMessage(), e);
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		}

		_oSPAliasStore = new JGroupsTGTAliasStore("sp", _mAliasMap, this);
		_oIDPAliasStore = new JGroupsTGTAliasStore("idp", _mAliasMap, this);


		// TODO: This should move to superclass instead:
		if(_tCleaner != null)
			_tCleaner.start();
	}


	@Override
	public void stop() {
		_mTGTs.stop();
		_mAliasMap.stop();
		_oIDPAliasStore.stop();
		_oSPAliasStore.stop();
		_oCluster.close();
		_oAliasCluster.close();
	}
	
	
	/**
	 * Convenience wrapper for start() to be used for unit testing
	 * 
	 * @param oConfigurationManager
	 * @param eConfig
	 * @param oCluster
	 * @param oAliasCluster
	 * @throws OAException
	 */
	public void startForTesting(IConfigurationManager oConfigurationManager,
						Element eConfig, ICluster oCluster, ICluster oAliasCluster,
						SecureRandom secureRandom, long expiration)
			throws OAException
	{
		_configurationManager = oConfigurationManager;
		_eConfig = eConfig;
		_oCluster = oCluster;
		_oAliasCluster = oAliasCluster;
		_random = secureRandom;
		_lExpiration = expiration;
		start();
		_mTGTs.setBlockingUpdates(true);
		_mAliasMap.setBlockingUpdates(true);
	}




	@Override
	public void removeExpired() throws PersistenceException {
		// TODO Martin.
	}

	@Override
	public boolean exists(Object id) throws PersistenceException {
		return _mTGTs.containsKey(id);
	}

	@Override
	public void persist(JGroupsTGT oEntity) throws PersistenceException {
		TGTListenerEvent performedEvent = performPersist(oEntity, true);

		StringBuffer sbDebug = new StringBuffer("Performed '");
		sbDebug.append(performedEvent);
		sbDebug.append("' event for TGT with id: ");
		sbDebug.append(oEntity.getId());
		_oLogger.debug(sbDebug.toString());
	}


	@Override
	public void persist(JGroupsTGT[] entities) throws PersistenceException 
	{
		List<TGTEventError> listTGTEventErrors = new Vector<TGTEventError>();
		int iErrorCode = -1;
		//Persist all tgts
		for(JGroupsTGT tgt : entities)
		{
			try
			{
				persist(tgt);
			}
			catch(TGTListenerException e)
			{
				listTGTEventErrors.addAll(e.getErrors());
			}
			catch(PersistenceException e)
			{
				if (iErrorCode == -1)
					iErrorCode = e.getCode();
			}
		}

		if (!listTGTEventErrors.isEmpty())
			throw new TGTListenerException(listTGTEventErrors);

		if (iErrorCode != -1)
			throw new PersistenceException(iErrorCode);
	}


	/**
	 * Persist this TGT in an <code>Hashtable</code> ignoring the TGT Listener 
	 * Event.
	 * 
	 * <dl>
	 *  <dt><code>id == null</code></dt>
	 *  <dd>Generate new unique and random id and store TGT</dd>
	 *  <dt><code>expiration time <= current time</code></dt>
	 *  <dd>Remove TGT from storage</dd>
	 * </dl>
	 * 
	 * Updating is necessary because changes need to be replicated.
	 * 
	 * Note: this code almost duplicates code from MemoryTGTFactory, JDBCTGTFactory,
	 * but it is slightly different. Also, because SessionFactory also inherits from
	 * AbstractStorageFactory, it is not possible to move this method down in
	 * the class hierarchy! 
	 * 
	 * @param tgt The TGT to persist.
	 * @return The event that was passed.
	 * @throws PersistenceException
	 * @since 1.4
	 */
	public TGTListenerEvent persistPassingListenerEvent(JGroupsTGT tgt) throws PersistenceException
	{
		TGTListenerEvent passedEvent = performPersist(tgt, false);
		_oLogger.debug("Passed '"+passedEvent+"' event for TGT with id: "+tgt.getId());

		return passedEvent;
	}


	/**
	 * Persist this TGT in the Replicated HashMap
	 * 
	 * <dl>
	 *  <dt><code>id == null</code></dt>
	 *  <dd>Generate new unique and random id and store TGT</dd>
	 *  <dt><code>expiration time <= current time</code></dt>
	 *  <dd>Remove TGT from storage</dd>
	 * </dl>
	 * 
	 * Updating is necessary because changes need to be replicated
	 * 
	 * @param oTGT The TGT to persist. 
	 * @param bProcessEvent TRUE if event must be performed
	 * @return the event that was or would be performed 
	 * @throws PersistenceException If persistence fails.
	 * @see IEntityManager#persist(IEntity)
	 */
	private synchronized TGTListenerEvent performPersist(JGroupsTGT oTGT, boolean bProcessEvent) throws PersistenceException
	{
		TGTListenerEvent listenerEvent = null;
		List<TGTEventError> listTGTEventErrors = null;
		String sTGTID = oTGT.getId();
		if (sTGTID == null) //New TGT
		{
			byte[] baId = new byte[ITGT.TGT_LENGTH];
			int iAllowedIdGenAttempts = 1000; 
			do
			{                
				_random.nextBytes(baId);
				try
				{
					sTGTID = ModifiedBase64.encode(baId);
				}
				catch (UnsupportedEncodingException e)
				{
					_oLogger.error("Could not create tgt id for byte[]: " + baId, e);
					throw new PersistenceException(SystemErrors.ERROR_INTERNAL);
				}
				iAllowedIdGenAttempts--;
			}
			while(_mTGTs.containsKey(sTGTID) && (iAllowedIdGenAttempts>0)); //Key already exists    

			if (_mTGTs.containsKey(sTGTID)) {
				_oLogger.error("Could not persist TGT because could not generate ID (which is weird!)");
				throw new PersistenceException(SystemErrors.ERROR_INTERNAL);
			}

			oTGT.setId(sTGTID);
			//Update expiration time
			oTGT.setTgtExpTime(System.currentTimeMillis() + _lExpiration);
			_mTGTs.put(sTGTID, oTGT);

			listenerEvent = TGTListenerEvent.ON_CREATE;
			if (bProcessEvent)
			{
				try
				{
					processEvent(listenerEvent, oTGT);
				}
				catch (TGTListenerException e)
				{
					listTGTEventErrors = e.getErrors();
				}
			}
		}
		else if(oTGT.isExpired()) //Expired
		{
			_oLogger.debug("TGT Expired: " + sTGTID);

			listenerEvent = TGTListenerEvent.ON_REMOVE;
			if (bProcessEvent)
			{
				try
				{
					processEvent(listenerEvent, oTGT);
				}
				catch (TGTListenerException e)
				{
					listTGTEventErrors = e.getErrors();
				}
			}

			int iCountR = _oSPAliasStore.remove(sTGTID);
			int iCountF = _oIDPAliasStore.remove(sTGTID);

			if ((iCountR + iCountF) > 0) {
				_oLogger.debug("Cleaned '"+iCountR+"' (requestor based) aliasses and '"+iCountF+
						"' (remote enitity based) aliasses for TGT with id: "+sTGTID);
			}

			IUser tgtUser = oTGT.getUser();
			_oEventLogger.info(
					new UserEventLogItem(null, sTGTID, null, UserEvent.TGT_EXPIRED, 
							tgtUser.getID(), tgtUser.getOrganization(), null, null, 
							this, null));

			_mTGTs.remove(sTGTID);
		}
		else //Update
		{
			//Update expiration time
			oTGT.setTgtExpTime(System.currentTimeMillis() + _lExpiration);
			_mTGTs.replace(sTGTID, oTGT);

			listenerEvent = TGTListenerEvent.ON_UPDATE;
			if (bProcessEvent)
			{
				try
				{
					processEvent(listenerEvent, oTGT);
				}
				catch (TGTListenerException e)
				{
					listTGTEventErrors = e.getErrors();
				}
			}
		}

		if (listTGTEventErrors != null)
		{//TGT Event processing failed, error has been logged already
			throw new TGTListenerException(listTGTEventErrors);
		}

		return listenerEvent;
	}


	public void clean(JGroupsTGT oJGroupsTGT) throws PersistenceException
	{
		List<TGTEventError> listTGTEventErrors = null;
		String sTGTID = oJGroupsTGT.getId();

		_oLogger.debug("Clean TGT: " + sTGTID);

		try
		{
			processEvent(TGTListenerEvent.ON_REMOVE, oJGroupsTGT);
		}
		catch (TGTListenerException e)
		{
			listTGTEventErrors = e.getErrors();
		}

		int iCountR = _oSPAliasStore.remove(sTGTID);
		int iCountF = _oIDPAliasStore.remove(sTGTID);

		if ((iCountR + iCountF) > 0) {
			_oLogger.debug("Cleaned '"+iCountR+"' (requestor based) aliasses and '"+iCountF+
					"' (remote enitity based) aliasses for TGT with id: "+sTGTID);
		}

		IUser tgtUser = oJGroupsTGT.getUser();
		_oEventLogger.info(
				new UserEventLogItem(null, sTGTID, null, UserEvent.TGT_EXPIRED, 
						tgtUser.getID(), tgtUser.getOrganization(), null, null, 
						this, null));

		_mTGTs.remove(sTGTID);

		if (listTGTEventErrors != null)
		{//TGT Event processing failed, error has been logged already
			throw new TGTListenerException(listTGTEventErrors);
		}
	}

	/**
	 * Return the number of TGT's that are stored in the underlying storage
	 */
	@Override
	public long poll() throws OAException 
	{
		if (_mTGTs == null) return 0;
		return _mTGTs.size();
	}


	@Override
	public String getAuthority() 
	{
		return ITGTFactory.AUTHORITY_NAME;
	}

	@Override
	public ITGT createTGT(IUser user) throws TGTException 
	{
		if(_lMax > 0 && _mTGTs.size() >= _lMax)
		{
			_oLogger.error("Could not create TGT, maximum reached");
			throw new TGTException(SystemErrors.ERROR_TGT_MAX);
		}
		return new JGroupsTGT(this, user);
	}


	@Override
	public JGroupsTGT retrieve(Object id) throws PersistenceException 
	{
		String sId = id.toString();
		JGroupsTGT oJGroupTGT = _mTGTs.get(sId);
		if (oJGroupTGT != null) {
			oJGroupTGT.resuscitate(this);
		}

		return oJGroupTGT;
	}

	
	@Override
	public void addListener(ITGTListener listener) 
	{
		_lListeners.add(listener);
	}

	@Override
	public void removeListener(ITGTListener listener) 
	{
		_lListeners.remove(listener);
	}

	@Override
	public List<ITGTListener> getListeners() 
	{
		return Collections.unmodifiableList(_lListeners);
	}

	@Override
	public void putAlias(String sType, String sRequestorID, String sTGTID, String sAlias) throws OAException 
	{
		_oLogger.error("method not supported: deprecated");
		throw new OAException(SystemErrors.ERROR_INTERNAL);
	}

	
	@Override
	public String getAlias(String sType, String sRequestorID, String sTGTID) throws OAException 
	{
		_oLogger.error("method not supported: deprecated");
		throw new OAException(SystemErrors.ERROR_INTERNAL);
	}

	
	@Override
	public String getTGTID(String sType, String sRequestorID, String sAlias) throws OAException 
	{
		_oLogger.error("method not supported: deprecated");
		throw new OAException(SystemErrors.ERROR_INTERNAL);
	}

	
	@Override
	public boolean isAlias(String sType, String sRequestorID, String sAlias) throws OAException 
	{
		_oLogger.error("method not supported: deprecated");
		throw new OAException(SystemErrors.ERROR_INTERNAL);
	}
	

	@Override
	public boolean hasAliasSupport() 
	{
		_oLogger.error("method not supported: deprecated");
		return _oSPAliasStore != null;
	}

	
	@Override
	public ITGTAliasStore getAliasStoreSP() 
	{
		return _oSPAliasStore;
	}

	
	@Override
	public ITGTAliasStore getAliasStoreIDP() 
	{
		return _oIDPAliasStore;
	}


	public int size() {
		return _mTGTs.size();
	}


	public Set<Entry<String, JGroupsTGT>> entrySet() {
		return _mTGTs.entrySet();
	}


	private void processEvent(TGTListenerEvent event, ITGT tgt) throws TGTListenerException
	{
		List<TGTEventError> listErrors = new Vector<TGTEventError>();
		for (int i = 0; i < _lListeners.size(); i++)
		{
			ITGTListener listener = _lListeners.get(i);
			try
			{
				listener.processTGTEvent(event, tgt);
			}
			catch (TGTListenerException e)
			{
				StringBuffer sbDebug = new StringBuffer("Could not process '");
				sbDebug.append(event);
				sbDebug.append("' event for TGT with id '");
				sbDebug.append(tgt.getId());
				sbDebug.append("': ");
				sbDebug.append(e);
				_oLogger.debug(sbDebug.toString(), e);

				listErrors.addAll(e.getErrors());
			}
		} 

		if (!listErrors.isEmpty())
			throw new TGTListenerException(listErrors);
	}

}
