/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2009 Alfa & Ariss B.V.
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
package com.alfaariss.oa.engine.tgt.memory;
import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.persistence.IEntity;
import com.alfaariss.oa.api.persistence.IEntityManager;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.storage.IStorageFactory;
import com.alfaariss.oa.api.storage.clean.ICleanable;
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

/**
 * Simple {@link ITGTFactory} which stores TGT in a {@link Hashtable}.
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class MemoryTGTFactory extends AbstractStorageFactory
    implements ITGTFactory<MemoryTGT>
{
    private Hashtable<String, MemoryTGT> _htTGT;
    private List<ITGTListener> _lListeners;
    //The system logger
    private Log _logger;
    private Log _eventLogger;
    
    private MemoryTGTAliasStore _aliasStoreSP;
    private MemoryTGTAliasStore _aliasStoreIDP;

	/**
     * Create a new <code>MemoryFactory</code>.
     */
    public MemoryTGTFactory()
    {
        super();
        _logger = LogFactory.getLog(MemoryTGTFactory.class);
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
        _htTGT = new Hashtable<String, MemoryTGT>();     
        _lListeners = new Vector<ITGTListener>();
        
        _aliasStoreSP = new MemoryTGTAliasStore();
        _aliasStoreIDP = new MemoryTGTAliasStore();
    }

    /**
	 * Create a new <code>AbstractTGT</code>.
	 * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#createTGT(com.alfaariss.oa.api.user.IUser)
	 */
	public ITGT createTGT(IUser user) throws TGTException
    {       
        if(_lMax > 0 && _htTGT.size() >= _lMax)
        {
            _logger.error("Could not create TGT, maximum reached");
            throw new TGTException(SystemErrors.ERROR_TGT_MAX);
        }
        return new MemoryTGT(this, user);
	}

    /**
     * Check if a TGT with the given id exists.
     * @see IEntityManager#exists(java.lang.Object)
     */
    public boolean exists(Object id)
    {
        return _htTGT.containsKey(id);
    }

    /**
     * Restore an existing TGT from the storage.
     *
     * Try to find a existing TGT in the storage and return the stored TGT. 
     * @see IEntityManager#retrieve(java.lang.Object)
     */
    public MemoryTGT retrieve(Object id) throws PersistenceException
    {
        return _htTGT.get(id);
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
     * Updating is not neccesary when using an <code>Hashtable</code>.
     * 
     * @param tgt The TGT to persist.
     * @return The event that was passed.
     * @throws PersistenceException
     * @since 1.4
     */
    public TGTListenerEvent persistPassingListenerEvent(MemoryTGT tgt) 
        throws PersistenceException
    {
        TGTListenerEvent passedEvent = performPersist(tgt, false);
        
        StringBuffer sbDebug = new StringBuffer("Passed '");
        sbDebug.append(passedEvent);
        sbDebug.append("' event for TGT with id: ");
        sbDebug.append(tgt.getId());
        _logger.debug(sbDebug.toString());
        
        return passedEvent;
    }
    
    /**
     * Cleans the TGT by removing it and triggering the TGT expire event.
     * <br>
     * This will trigger the expire tgt event after removing the TGT.
     * @param tgt The TGT to persist.
     * @throws PersistenceException If cleaning fails.
     * @since 1.4
     */
    public void clean(MemoryTGT tgt) throws PersistenceException
    {
        List<TGTEventError> listTGTEventErrors = null;
        String id = tgt.getId();
        
        _logger.debug("Clean TGT: " + id);
        
        try
        {
            processEvent(TGTListenerEvent.ON_EXPIRE, tgt);
        }
        catch (TGTListenerException e)
        {
            listTGTEventErrors = e.getErrors();
        }
        
        int iCountR = _aliasStoreSP.remove(id);
        int iCountF = _aliasStoreIDP.remove(id);
        
        if (_logger.isDebugEnabled() && iCountR + iCountF > 0)
        {
            StringBuffer sbDebug = new StringBuffer("Cleaned '");
            sbDebug.append(iCountR);
            sbDebug.append("' (requestor based) aliasses and '");
            sbDebug.append(iCountF);
            sbDebug.append("' (remote enitity based) aliasses for TGT with id: ");
            sbDebug.append(id);
            _logger.debug(sbDebug.toString());
        }
        
        IUser tgtUser = tgt.getUser();
        _eventLogger.info(
            new UserEventLogItem(null, id, null, UserEvent.TGT_EXPIRED, 
                tgtUser.getID(), tgtUser.getOrganization(), null, null, 
                this, null));
        
        _htTGT.remove(id);
        
        if (listTGTEventErrors != null)
        {//TGT Event processing failed, error has been logged already
            throw new TGTListenerException(listTGTEventErrors);
        }
    }

    /**
     * Persist this TGT in an <code>Hashtable</code>.
     * 
     * <dl>
     *  <dt><code>id == null</code></dt>
     *  <dd>Generate new unique and random id and store TGT</dd>
     *  <dt><code>expiration time <= current time</code></dt>
     *  <dd>Remove TGT from storage</dd>
     * </dl>
     * 
     * Updating is not neccesary when using an <code>Hashtable</code>.
     * 
     * @param tgt The TGT to persist.
     * @throws PersistenceException If persistance.
     * @see IEntityManager#persist(IEntity)
     */
    public void persist(MemoryTGT tgt) throws PersistenceException
    {
        TGTListenerEvent performedEvent = performPersist(tgt, true);
        
        StringBuffer sbDebug = new StringBuffer("Performed '");
        sbDebug.append(performedEvent);
        sbDebug.append("' event for TGT with id: ");
        sbDebug.append(tgt.getId());
        _logger.debug(sbDebug.toString());
    }

    /**
     * Persist all TGTs in an <code>Hashtable</code>.
     * @param oaTgt The TGTs to persist.
     * @throws PersistenceException If persistance fails.
     * @see IEntityManager#persist(IEntity[])
     * @see IEntityManager#persist(IEntity)
     */
    public void persist(MemoryTGT[] oaTgt) throws PersistenceException
    {
        List<TGTEventError> listTGTEventErrors = new Vector<TGTEventError>();
        int iErrorCode = -1;
        //Persist all tgts
        for(MemoryTGT tgt : oaTgt)
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
     * Remove all expired TGTs.
     * @see ICleanable#removeExpired()
     */
    public void removeExpired() throws PersistenceException
    {
        long lNow = System.currentTimeMillis();
        Enumeration<MemoryTGT> eTGTs = _htTGT.elements();
        while(eTGTs.hasMoreElements()) //Threadsafe iteration
        {          
            MemoryTGT tgt = eTGTs.nextElement(); 
            if(tgt.getTgtExpTime().getTime() <= lNow)
            {
                String id = tgt.getId();
                
                _logger.debug("TGT Expired: " + id);
                
                try
                {
                    processEvent(TGTListenerEvent.ON_EXPIRE, tgt);
                }
                catch (TGTListenerException e)
                {//do nothing; just remove and try the next tgt
                    _logger.debug("Could not process events for TGT with id: " + id, e);
                }
                
                int iCountR = _aliasStoreSP.remove(id);
                int iCountF = _aliasStoreIDP.remove(id);
                
                if (_logger.isDebugEnabled() && iCountR + iCountF > 0)
                {
                    StringBuffer sbDebug = new StringBuffer("Cleaned '");
                    sbDebug.append(iCountR);
                    sbDebug.append("' (requestor based) aliasses and '");
                    sbDebug.append(iCountF);
                    sbDebug.append("' (remote enitity based) aliasses for TGT with id: ");
                    sbDebug.append(id);
                    _logger.debug(sbDebug.toString());
                }
                
                IUser tgtUser = tgt.getUser();
                _eventLogger.info(
                    new UserEventLogItem(null, id, null, UserEvent.TGT_EXPIRED, 
                        tgtUser.getID(), tgtUser.getOrganization(), null, null, 
                        this, "clean"));
                
                _htTGT.remove(id);
            }
        }
    }

    /**
     * Start cleaner
     * @see IStorageFactory#start()
     */
    public void start() throws OAException
    {
        if(_tCleaner != null)
            _tCleaner.start();         
    }

    /**
     * @see com.alfaariss.oa.api.poll.IPollable#poll()
     */
    public long poll() throws OAException
    {
        if (_htTGT!=null) 
            return _htTGT.size();
        
        return Long.MIN_VALUE;
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#addListener(com.alfaariss.oa.api.tgt.ITGTListener)
     */
    public void addListener(ITGTListener listener)
    {
        _lListeners.add(listener);
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#removeListener(com.alfaariss.oa.api.tgt.ITGTListener)
     */
    public void removeListener(ITGTListener listener)
    {
        _lListeners.remove(listener);
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#getListeners()
     */
    public List<ITGTListener> getListeners()
    {
        return Collections.unmodifiableList(_lListeners);
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#putAlias(java.lang.String, java.lang.String, java.lang.String, java.lang.String)
     * @deprecated please use getRequestorAliasStore().putAlias() instead.
     */
    public void putAlias(String type, String requestorID, String tgtID,
        String alias) throws OAException
    {
        _aliasStoreSP.putAlias(type, requestorID, tgtID, alias);
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#getAlias(java.lang.String, java.lang.String, java.lang.String)
     * @deprecated please use getRequestorAliasStore().getAlias() instead.
     */
    public String getAlias(String type, String requestorID, String tgtID)
        throws OAException
    {
        return _aliasStoreSP.getAlias(type, requestorID, tgtID);
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#getTGTID(java.lang.String, java.lang.String, java.lang.String)
     * @deprecated please use getRequestorAliasStore().getTGTID() instead.
     */
    public String getTGTID(String type, String requestorID, String alias)
        throws OAException
    {
        return _aliasStoreSP.getTGTID(type, requestorID, alias);
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#isAlias(java.lang.String, java.lang.String, java.lang.String)
     * @deprecated please use getRequestorAliasStore().isAlias() instead.
     */
    public boolean isAlias(String type, String requestorID, String alias)
        throws OAException
    {
        return _aliasStoreSP.isAlias(type, requestorID, alias);
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#hasAliasSupport()
     * @deprecated please use getRequestorAliasStore() != null instead.
     */
    public boolean hasAliasSupport()
    {
        return _aliasStoreSP != null;
    }
    
    /**
     * @see com.alfaariss.oa.api.logging.IAuthority#getAuthority()
     * @since 1.3
     */
    public String getAuthority()
    {
        return ITGTFactory.AUTHORITY_NAME;
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#getAliasStoreIDP()
     */
    public ITGTAliasStore getAliasStoreIDP()
    {
        return _aliasStoreIDP;
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#getAliasStoreSP()
     */
    public ITGTAliasStore getAliasStoreSP()
    {
        return _aliasStoreSP;
    }

    /**
     * Persist this TGT in an <code>Hashtable</code>.
     * 
     * <dl>
     *  <dt><code>id == null</code></dt>
     *  <dd>Generate new unique and random id and store TGT</dd>
     *  <dt><code>expiration time <= current time</code></dt>
     *  <dd>Remove TGT from storage</dd>
     * </dl>
     * 
     * Updating is not neccesary when using an <code>Hashtable</code>.
     * 
     * @param tgt The TGT to persist. 
     * @param bProcessEvent TRUE if event must be performed
     * @return the event that was or would be performed 
     * @throws PersistenceException If persistance fails.
     * @see IEntityManager#persist(IEntity)
     */
    private synchronized TGTListenerEvent performPersist(MemoryTGT tgt, boolean bProcessEvent) throws PersistenceException
    {
        TGTListenerEvent listenerEvent = null;
        List<TGTEventError> listTGTEventErrors = null;
        String id = tgt.getId();
        if(id == null) //New TGT
        {
            byte[] baId = new byte[ITGT.TGT_LENGTH];     
            do
            {                
                _random.nextBytes(baId);
               try
               {
                   id = ModifiedBase64.encode(baId);
               }
               catch (UnsupportedEncodingException e)
               {
                   _logger.error("Could not create tgt id for byte[]: " + baId, e);
                   throw new PersistenceException(SystemErrors.ERROR_INTERNAL);
               }
            }
            while(_htTGT.containsKey(id)); //Key allready exists    
            
            tgt.setId(id);
            //Update expiration time
            tgt.setTgtExpTime(System.currentTimeMillis() + _lExpiration);
            _htTGT.put(id, tgt);      
            
            listenerEvent = TGTListenerEvent.ON_CREATE;
            if (bProcessEvent)
            {
                try
                {
                    processEvent(listenerEvent, tgt);
                }
                catch (TGTListenerException e)
                {
                    listTGTEventErrors = e.getErrors();
                }
            }
        }
        else if(tgt.isExpired()) //Expired
        {
            _logger.debug("TGT Expired: " + id);
            
            listenerEvent = TGTListenerEvent.ON_REMOVE;
            if (bProcessEvent)
            {
                try
                {
                    processEvent(listenerEvent, tgt);
                }
                catch (TGTListenerException e)
                {
                    listTGTEventErrors = e.getErrors();
                }
            }
            
            int iCountR = _aliasStoreSP.remove(id);
            int iCountF = _aliasStoreIDP.remove(id);
            
            if (_logger.isDebugEnabled() && iCountR + iCountF > 0)
            {
                StringBuffer sbDebug = new StringBuffer("Cleaned '");
                sbDebug.append(iCountR);
                sbDebug.append("' (requestor based) aliasses and '");
                sbDebug.append(iCountF);
                sbDebug.append("' (remote enitity based) aliasses for TGT with id: ");
                sbDebug.append(id);
                _logger.debug(sbDebug.toString());
            }
            
            IUser tgtUser = tgt.getUser();
            _eventLogger.info(
                new UserEventLogItem(null, id, null, UserEvent.TGT_EXPIRED, 
                    tgtUser.getID(), tgtUser.getOrganization(), null, null, 
                    this, null));
            
            _htTGT.remove(id);
        }    
        else //Update
        {
            //Update expiration time
            tgt.setTgtExpTime(System.currentTimeMillis() + _lExpiration);
            //Storing can be omitted when using Hashtable
            
            listenerEvent = TGTListenerEvent.ON_UPDATE;
            if (bProcessEvent)
            {
                try
                {
                    processEvent(listenerEvent, tgt);
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

    private void processEvent(TGTListenerEvent event, ITGT tgt) 
        throws TGTListenerException
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
                _logger.debug(sbDebug.toString(), e);
                
                listErrors.addAll(e.getErrors());
            }
        } 
        
        if (!listErrors.isEmpty())
            throw new TGTListenerException(listErrors);
    }
}