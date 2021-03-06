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
import com.alfaariss.oa.api.configuration.ConfigurationException;
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
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.BooleanUtils;

public class JGroupsTGTFactory extends AbstractStorageFactory implements ITGTFactory<JGroupsTGT>
{
	public static final String EL_CONFIG_CLUSTERID = "cluster_id";
	public static final String EL_CONFIG_ALIAS_CLUSTERID = "alias_cluster_id";
    public static final String EL_CONFIG_BLOCKING_MODE = "blocking_mode";
    public static final String EL_CONFIG_BLOCKING_TIMEOUT = "blocking_timeout";
    public static final String EL_CONFIG_STATE_TIMEOUT = "state_timeout";
    public static final String EL_CONFIG_ALIASMAP_RETRIES = "aliasmap_retries";
    public static final String EL_CONFIG_ALIASMAP_TIMEOUT = "aliasmap_timeout";
    public static final String EL_CONFIG_ALIASMAP_LOGGING = "aliasmap_logging";
    public static final Boolean BLOCKING_MODE_DEFAULT = true;
    public static final Long BLOCKING_TIMEOUT_DEFAULT = 5000l;
    public static final Long STATE_TIMEOUT_DEFAULT = 100000l;
    public static final Integer ALIASMAP_RETRIES_DEFAULT = 0;
    public static final Long ALIASMAP_TIMEOUT_DEFAULT = 10l;
    public static final Boolean ALIASMAP_LOGGING_DEFAULT = false;

	private static final Log _oLogger = LogFactory.getLog(JGroupsTGTFactory.class);
	private static final Log _oEventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
	
	private ReplicatedHashMap<String, JGroupsTGT> _mTGTs;
	private ReplicatedHashMap<String, String> _mAliasMap;
	
	private ICluster _oCluster = null;
	private ICluster _oAliasCluster = null;

	private JChannel _jChannel = null;
	private JChannel _jAliasChannel = null;
	
	private JGroupsTGTAliasStore _oSPAliasStore;
	private JGroupsTGTAliasStore _oIDPAliasStore;

	private List<ITGTListener> _lListeners;
    

    private int _iAliasMapRetries;

    private long _lAliasMapTimeout;
    
    
	public JGroupsTGTFactory() {
        super();
    }
	
	/**
	 * Start component instantiates the replicated hashmap, as well as 
	 * start managing the cleaner thread (should be moved to base class)
     * @throws com.alfaariss.oa.OAException
	 */
	@Override
	public void start() throws OAException 
	{
        _lListeners = new Vector<>();

		// this._configManager and this._eConfig are initialized at this point:
		ClusterConfiguration oClusterConfiguration = new ClusterConfiguration(_configurationManager);
		if (_oCluster == null) {
			_oCluster = oClusterConfiguration.getClusterFromConfigById(_eConfig, EL_CONFIG_CLUSTERID);
		}

		_jChannel = (JChannel) _oCluster.getChannel();
		_mTGTs = new ReplicatedHashMap<>( _jChannel );

        _iAliasMapRetries = (new ConfigParser<Integer>()).parse(EL_CONFIG_ALIASMAP_RETRIES, _eConfig, ALIASMAP_RETRIES_DEFAULT);
        _lAliasMapTimeout = (new ConfigParser<Long>()).parse(EL_CONFIG_ALIASMAP_TIMEOUT, _eConfig, ALIASMAP_TIMEOUT_DEFAULT);
        Long lStateTimeout = (new ConfigParser<Long>()).parse(EL_CONFIG_STATE_TIMEOUT, _eConfig, STATE_TIMEOUT_DEFAULT);
        Boolean bBlockingMode = (new ConfigParser<Boolean>().parse(EL_CONFIG_BLOCKING_MODE, _eConfig, BLOCKING_MODE_DEFAULT));
        Long lBlockingTimeout = (new ConfigParser<Long>().parse(EL_CONFIG_BLOCKING_TIMEOUT, _eConfig, BLOCKING_TIMEOUT_DEFAULT));        
        Boolean bAliasMapLogging = (new ConfigParser<Boolean>().parse(EL_CONFIG_ALIASMAP_LOGGING, _eConfig, ALIASMAP_LOGGING_DEFAULT));
        
        try {
			// start gets the shared state in local hashmap, it is blocking,
			// the timeout is not applied to the time needed to get the remote state
			_mTGTs.start(lStateTimeout);
		} catch (Exception e) {
			_oLogger.error("Could not start Replicated HashMap: "+e.getMessage(), e);
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		}

		if (_oAliasCluster == null) {
			_oAliasCluster = 
					oClusterConfiguration.getClusterFromConfigById(_eConfig, EL_CONFIG_ALIAS_CLUSTERID);
		}
		
		_jAliasChannel = (JChannel) _oAliasCluster.getChannel();
		_mAliasMap = new ReplicatedHashMap<>( _jAliasChannel );
		try {
			_mAliasMap.start(lStateTimeout);
		} catch (Exception e) {
			_oLogger.error("Could not start Replicated HashMap: "+e.getMessage(), e);
			throw new OAException(SystemErrors.ERROR_INTERNAL);
		}

        _mTGTs.setBlockingUpdates(bBlockingMode);
        _mAliasMap.setBlockingUpdates(bBlockingMode);
     
        _mTGTs.setTimeout(lBlockingTimeout);
        _mAliasMap.setTimeout(lBlockingTimeout);
        
		_oSPAliasStore = new JGroupsTGTAliasStore("sp", _mAliasMap, this);
		_oIDPAliasStore = new JGroupsTGTAliasStore("idp", _mAliasMap, this);

        _oSPAliasStore.setFailureLogging(bAliasMapLogging, JGroupsTGTFactory.class.getName());
        _oIDPAliasStore.setFailureLogging(bAliasMapLogging, JGroupsTGTFactory.class.getName());

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
     * @param secureRandom
     * @param expiration
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
	}

    
    public boolean isBlockingUpdates() {
        return _mTGTs.isBlockingUpdates() && _mAliasMap.isBlockingUpdates();
    }
    
    
    public void setBlockingUpdates(boolean b) {
		_mTGTs.setBlockingUpdates(b);
		_mAliasMap.setBlockingUpdates(b);        
    }
    
    
    public long getTimeout() {
        return _mTGTs.getTimeout();
    }

    
    public void setTimout(long timeout) {
        _mTGTs.setTimeout(timeout);
        _mAliasMap.setTimeout(timeout);
    }
    
    
	@Override
    public void removeExpired() throws PersistenceException
    {
        long lNow = System.currentTimeMillis();

        for ( Entry<String,JGroupsTGT> entry : _mTGTs.entrySet() )
        {
            JGroupsTGT tgt = entry.getValue();

            if( tgt.getTgtExpTime().getTime() <= lNow )
            {
                String id = tgt.getId();

                _oLogger.debug("TGT Expired: " + id);

                try
                {
                    processEvent(TGTListenerEvent.ON_EXPIRE, tgt);
                }
                catch (TGTListenerException e)
                {//do nothing; just remove and try the next tgt
                    _oLogger.debug("Could not process events for TGT with id: " + id, e);
                }

                int iCountR = _oSPAliasStore.remove(id);
                int iCountF = _oIDPAliasStore.remove(id);

                if (_oLogger.isDebugEnabled() && iCountR + iCountF > 0)
                {
                    StringBuilder sbDebug = new StringBuilder("Cleaned '");
                    sbDebug.append(iCountR);
                    sbDebug.append("' (requestor based) aliases and '");
                    sbDebug.append(iCountF);
                    sbDebug.append("' (remote entity based) aliases for TGT with id: ");
                    sbDebug.append(id);
                    _oLogger.debug(sbDebug.toString());
                }

                IUser tgtUser = tgt.getUser();
                _oEventLogger.info(
                    new UserEventLogItem(null, id, null, UserEvent.TGT_EXPIRED,
                        tgtUser.getID(), tgtUser.getOrganization(), null, null,
                        this, "clean"));

                _mTGTs.remove(entry.getKey());
            }
        }
    }
	

	@Override
	public boolean exists(Object id) throws PersistenceException {
		return _mTGTs.containsKey((String)id);
	}
	

	@Override
	public void persist(JGroupsTGT oEntity) throws PersistenceException {
        TGTListenerEvent performedEvent = performPersist(oEntity, true);

		StringBuilder sbDebug = new StringBuilder("Performed '");
		sbDebug.append(performedEvent);
		sbDebug.append("' event for TGT with id: ");
		sbDebug.append(oEntity.getId());
		_oLogger.debug(sbDebug.toString());
	}


	@Override
	public void persist(JGroupsTGT[] entities) throws PersistenceException 
	{
		List<TGTEventError> listTGTEventErrors = new Vector<>();
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
					_oLogger.error("Could not create tgt id for byte[]: " + Arrays.toString(baId), e);
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
     * @throws com.alfaariss.oa.OAException
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

    
    public int getAliasMapRetries() {
        return _iAliasMapRetries;
    }

    
    public long getAliasMapTimeout() {
        return _lAliasMapTimeout;
    }

    
    public void setAliasMapFailureLogging(boolean doLog, String label) {
        _oIDPAliasStore.setFailureLogging(doLog, label);
        _oSPAliasStore.setFailureLogging(doLog, label);
    }
    
    
    public boolean isAliasMapFailureLogging() {
        return _oIDPAliasStore.isFailureLogging() && _oSPAliasStore.isFailureLogging();
    }
    
    
	private void processEvent(TGTListenerEvent event, ITGT tgt) throws TGTListenerException
	{
		List<TGTEventError> listErrors = new Vector<>();
        for (ITGTListener listener : _lListeners) {
            try
            {
                listener.processTGTEvent(event, tgt);
            }
            catch (TGTListenerException e)
            {
                StringBuilder sbDebug = new StringBuilder("Could not process '");
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

    private class ConfigParser<T> {
        public T parse(String name, Element configElement, T defaultValue) throws OAException {
            T value = defaultValue;
            Class type = defaultValue.getClass();
            HashSet<Type> supportedTypes = new HashSet<Type>(Arrays.asList(Long.class, Integer.class, Boolean.class));
            
            if (!supportedTypes.contains(type)) {
                _oLogger.error("Internal error: type '" + type + "' is not supported");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }

            String sParameterValue = null;
            try {
                sParameterValue = _configurationManager.getParam(configElement, name);
            }
            catch (ConfigurationException ex) {
                Logger.getLogger(JGroupsTGTFactory.class.getName()).log(Level.SEVERE, null, ex);
            }
            
            try {
                Constructor constructor = type.getConstructor(String.class);
                if (sParameterValue != null) {
                    if (defaultValue.getClass() == Boolean.class) {
                        if (!sParameterValue.equalsIgnoreCase("true") && !sParameterValue.equalsIgnoreCase("false")) {
                            throw new IllegalArgumentException("Bad boolean value: '" + sParameterValue + "'");
                        }
                        value = (T) (Boolean) BooleanUtils.toBoolean(sParameterValue);
                    }
                    else {
                        value = (T)constructor.newInstance(sParameterValue);
                    }
                }
            }
            catch (java.lang.NumberFormatException e) {
                _oLogger.error("Invalid numeric value '" + sParameterValue + "' in config for <" + name + ">, using default: " + defaultValue);
            }
            catch (java.lang.IllegalArgumentException iae) {
                _oLogger.error("Invalid boolean value '" + sParameterValue + "' in config for <" + name + ">, using default: " + defaultValue);
            }
            catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
                _oLogger.error("Unexpceted exception '" + e.getClass().getName() + "' while parsing value '" + sParameterValue + "' in config for '" + name + "', using default value");
            }

            return value;
        }
    }
}

