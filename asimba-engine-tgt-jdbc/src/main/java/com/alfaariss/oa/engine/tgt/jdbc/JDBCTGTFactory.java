/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.engine.tgt.jdbc;
import java.io.UnsupportedEncodingException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Collections;
import java.util.List;
import java.util.Vector;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.datastorage.IDataStorageFactory;
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
import com.alfaariss.oa.engine.core.attribute.TGTAttributes;
import com.alfaariss.oa.engine.core.authentication.AuthenticationProfile;
import com.alfaariss.oa.engine.core.tgt.TGTException;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory;
import com.alfaariss.oa.util.ModifiedBase64;
import com.alfaariss.oa.util.Serialize;
import com.alfaariss.oa.util.database.DatabaseException;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.storage.factory.AbstractStorageFactory;

/**
 * <code>ITGTFactory</code> which uses a JDBC source for storage.
 * 
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class JDBCTGTFactory extends AbstractStorageFactory implements ITGTFactory<JDBCTGT>
{
    private final static String TABLE_NAME = "tgt";
    private final static String COLUMN_ID = "id";
    private final static String COLUMN_EXPIRATION = "expiration";
    private final static String COLUMN_USER = "tgtuser";
    private final static String COLUMN_AUTHN_PROFILE = "authn_profile";
    private final static String COLUMN_AUTHN_PROFILES = "authn_profile_ids";
    private final static String COLUMN_REQUESTOR_IDS = "requestor_ids";
    private final static String COLUMN_ATTRIBUTES = "attributes";
    
    private String _sTableName;
    private String _sColumnID;
    private String _sColumnEXPIRATION;
    private String _sColumnUSER;
    private String _sColumnAUTHN_PROFILE;
    private String _sColumnAUTHN_PROFILES;
    private String _sColumnREQUESTOR_IDS;
    private String _sColumnATTRIBUTES;
        
    //Queries
    private String _sSearchQuery = null;
    private String _sCountQuery = null; 
    private String _sInsertQuery = null; 
    private String _sUpdateQuery = null; 
    private String _sRemoveQuery = null;
    private String _sRemoveExpiredQuery = null; 
    private String _sSelectExpiredQuery = null;
       
    private List<ITGTListener> _lListeners;
    //The JDBC manager 
    private DataSource _oDataSource;
    //The system logger
    private Log _logger;
    private Log _eventLogger;
    
    private JDBCTGTAliasStore _aliasStoreSP;
    private JDBCTGTAliasStore _aliasStoreIDP;
       
	/**
     * Create a new <code>JDBCFactory</code>.
     */
    public JDBCTGTFactory()
    {
        super();        
        _logger = LogFactory.getLog(JDBCTGTFactory.class);
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
        _lListeners = new Vector<ITGTListener>();
    }

    /**
     * Call super class and start cleaner.
     * @see IStorageFactory#start()
     */
    public void start() throws OAException
    {        
        //Read resource configuration 
        Element eResource = _configurationManager.getSection(_eConfig, "resource");
        if (eResource != null)
        {
            _oDataSource = DataSourceFactory.createDataSource(_configurationManager, eResource);
            _logger.info("Using datasource specified in 'resource' section in configuration");
        }
        else
        {
            IDataStorageFactory databaseFactory = Engine.getInstance().getStorageFactory();
            if (databaseFactory != null && databaseFactory.isEnabled())
            {
                _oDataSource = databaseFactory.createSystemDatasource();
                if (_oDataSource == null)
                {
                    _logger.error("Could not create a valid datasource");
                    throw new DatabaseException(SystemErrors.ERROR_INIT);
                }
                _logger.info("Using datasource specified in engine");
            }
            else
            {
                _logger.error("Could not create a valid datasource");
                throw new DatabaseException(SystemErrors.ERROR_INIT);
            }
        }
        
        //Read query configuration
        createQueries(_eConfig);
        verifyTableConfig(_eConfig);
         
        Element eAliasStoreSP = _configurationManager.getSection(_eConfig, 
            "alias_store", "id=sp");
        if (eAliasStoreSP == null)
        {
            _logger.info("No optional 'alias_store' section with id='sp' found in configuration, disabling alias storage support for Requestors");
            _aliasStoreSP = null;
        }
        else
        {
            _aliasStoreSP = new JDBCTGTAliasStore(_configurationManager, 
                eAliasStoreSP, _oDataSource, _sTableName, _sColumnID);
        }
        
        Element eAliasStoreIDP = _configurationManager.getSection(_eConfig, 
            "alias_store", "id=idp");
        if (eAliasStoreIDP == null)
        {
            _logger.info("No optional 'alias_store' section with id='idp' found in configuration, disabling alias storage support for IdP's");
            _aliasStoreIDP = null;
        }
        else
        {
            _aliasStoreIDP = new JDBCTGTAliasStore(_configurationManager, 
                eAliasStoreIDP, _oDataSource, _sTableName, _sColumnID);
        }
        
        //Start cleaner
        if(_tCleaner != null)
            _tCleaner.start(); 
    }
     
	/**
	 * Create a new TGT if max is not reached yet.
	 * @throws TGTException if TGT maximum is reached.
	 * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#createTGT(com.alfaariss.oa.api.user.IUser)
	 */
	public ITGT createTGT(IUser user) throws TGTException
    {
        if(_lMax > 0)          
        {
            if(getTGTCount() >= _lMax)
            {
                _logger.error("Could not create TGT, maximum reached");
                throw new TGTException(SystemErrors.ERROR_TGT_MAX);
            }
        }
        return new JDBCTGT(this, user);
	}
    
    /**
	 * Check if a TGT with the given ID exists.	
	 * @see IEntityManager#exists(java.lang.Object)
	 */
	public boolean exists(Object id) throws PersistenceException
    {
        if(id == null || !(id instanceof String))
            throw new IllegalArgumentException("Suplied id is empty or invalid");
        
        boolean bRet = false;
        Connection oConnection = null;
        PreparedStatement ps = null;
        ResultSet rs = null;

        try
        {
            oConnection = _oDataSource.getConnection();
            ps = oConnection.prepareStatement(_sSearchQuery);
            ps.setString(1, (String)id);
            rs = ps.executeQuery();
            if(rs.next())
               bRet = true;
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute search query: " + _sSearchQuery, e);
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (Exception e)
        {
            _logger.error("Internal error during exists check for tgt with id: " 
                + id, e);
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }       
        finally
        {    
            try
            {
                if (rs != null)
                    rs.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close resultset", e);
            } 
            try
            {
                if (ps != null)
                    ps.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close statement", e);
            } 
            try
            {
                if (oConnection != null)
                    oConnection.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close connection", e);
            }          
        }
        return bRet;
	}
    
	/**
	 * Retrieve the TGT with the given id.
	 * @param id The TGT id.
	 * @return The TGT, or null if a TGT with the given id does not exist.
	 * @throws PersistenceException If retrieving fails.
	 */
	@SuppressWarnings("unchecked") //Serialize value can not be checked
    public JDBCTGT retrieve(Object id) throws PersistenceException
    {
        if(id == null || !(id instanceof String))
            throw new IllegalArgumentException("Suplied id is empty or invalid");
        
        JDBCTGT tgt = null;
        Connection oConnection = null;
        PreparedStatement ps = null;
        ResultSet rs = null;

        try
        {
            oConnection = _oDataSource.getConnection();
            ps = oConnection.prepareStatement(_sSearchQuery);
            ps.setString(1, (String)id);
            rs = ps.executeQuery();
            if(rs.next())
            { 
               byte[] baUser = rs.getBytes(_sColumnUSER);
               tgt = new JDBCTGT(this, (IUser)Serialize.decode(baUser));
               tgt.setId((String)id);
               tgt.setTgtExpTime(rs.getTimestamp(_sColumnEXPIRATION).getTime());          
               tgt.setAuthenticationProfile(
                   (AuthenticationProfile)Serialize.decode(rs.getBytes(_sColumnAUTHN_PROFILE)));
               tgt.setAuthNProfileIDs(
                   (List)Serialize.decode(rs.getBytes(_sColumnAUTHN_PROFILES)));
               tgt.setRequestorIDs(
                   (List)Serialize.decode(rs.getBytes(_sColumnREQUESTOR_IDS)));
               
               TGTAttributes oAttributes = 
                   (TGTAttributes)Serialize.decode(rs.getBytes(_sColumnATTRIBUTES));
               if (oAttributes != null)
                   tgt.setAttributes(oAttributes);
            }      
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute search query", e);
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (ClassCastException e)
        {
            _logger.error("Could not decode, invalid class type", e);
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (Exception e)
        {
            _logger.error("Internal error during retrieval of tgt with id: " 
                + id, e);
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }   
        finally
        {
            try
            {
                if(rs != null)
                    rs.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close resultset", e);
            }
            try
            {
                if(ps != null)
                    ps.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close statement", e);
            }
            try
            {
                if(oConnection != null)
                    oConnection.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close connection", e);
            }
        }
        return tgt;
	}
	
	/**
	 * Persist the TGT in the JDBC storage ignoring the TGT Listener Event.
	 * 
	 * @param tgt The TGT to persist.
	 * @return The event that was passed.
	 * @throws PersistenceException
	 * @since 1.4
	 */
	public TGTListenerEvent persistPassingListenerEvent(JDBCTGT tgt) throws PersistenceException
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
	 * 
	 * @param tgt The TGT to persist.
	 * @throws PersistenceException If cleaning fails.
	 * @since 1.4
	 */
	public void clean(JDBCTGT tgt) throws PersistenceException
    {
	    if (tgt == null)
            throw new IllegalArgumentException(
                "Suplied tgt is empty or invalid");
        
        Connection oConnection = null;
        PreparedStatement ps = null;
        List<TGTEventError> listTGTEventErrors = null;
        
        String id = tgt.getId();
        try
        {
            oConnection = _oDataSource.getConnection();
            
    	    _logger.debug("Clean TGT: " + id);
            
            IUser tgtUser = tgt.getUser();
            _eventLogger.info(
                new UserEventLogItem(null, tgt.getId(), null, 
                    UserEvent.TGT_EXPIRED, tgtUser.getID(), 
                    tgtUser.getOrganization(), null, null, this, "clean"));
            
            try
            {
                processEvent(TGTListenerEvent.ON_EXPIRE, tgt);
            }
            catch (TGTListenerException e)
            {
                listTGTEventErrors = e.getErrors();
            }
            
            try
            {
                ps = oConnection.prepareStatement(_sRemoveQuery);
                ps.setString(1, id);
                int i = ps.executeUpdate();
                _logger.debug(i + " TGT cleaned: " + id);
            }
            catch (SQLException e)
            {                    
                _logger.error("Could not execute delete query: " + 
                    _sRemoveQuery, e);
                throw new PersistenceException(SystemErrors.ERROR_RESOURCE_REMOVE);
            }
            
            int iCountR = 0;
            if (_aliasStoreSP != null)
                iCountR = _aliasStoreSP.remove(oConnection, id);
            int iCountF = 0;
            if (_aliasStoreIDP != null)
                iCountF = _aliasStoreIDP.remove(oConnection, id);
            
            if (_logger.isDebugEnabled() && iCountR + iCountF > 0)
            {
                StringBuffer sbDebug = new StringBuffer("Cleaned '");
                sbDebug.append(iCountR);
                sbDebug.append("' (requestor based) aliasses and '");
                sbDebug.append(iCountF);
                sbDebug.append("' (remote enitity based) aliasses");
                _logger.debug(sbDebug.toString());
            }
            
            if (listTGTEventErrors != null)
            {//TGT Event processing failed, error has been logged already
                throw new TGTListenerException(listTGTEventErrors);
            }
        }
        catch (PersistenceException e)
        {
            throw e;
        }  
        catch (Exception e)
        {
            _logger.error("Internal error during cleaning of tgt with id: " + id, e);
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_REMOVE);
        }  
        finally
        {
            try
            {
                if (ps != null)
                    ps.close();
            }
            catch (SQLException e)
            {                    
                _logger.error("Could not close statement", e);
            }
            try
            {
                if (oConnection != null)
                    oConnection.close();
            }
            catch (SQLException e)
            {                    
                _logger.error("Could not close connection", e);
            }
        }
    }

    /**
     * Persist the TGT in the JDBC storage.
     * @param tgt The TGT to persist.
     * @throws PersistenceException If persistance.
     * @see IEntityManager#persist(IEntity)
     */
	public void persist(JDBCTGT tgt) throws PersistenceException
	{
	    TGTListenerEvent performedEvent = performPersist(tgt, true);
	    
	    StringBuffer sbDebug = new StringBuffer("Performed '");
	    sbDebug.append(performedEvent);
	    sbDebug.append("' event for TGT with id: ");
	    sbDebug.append(tgt.getId());
	    _logger.debug(sbDebug.toString());
	}
	
    /**
     * Uses a batch update to persist all supplied tgts.
     * @param tgts The TGTs to persist.
     * @throws PersistenceException If persistance fails.
     * 
     * @see IEntityManager#persist(IEntity[])
     * @see PreparedStatement#addBatch()
     */
    public void persist(JDBCTGT[] tgts) throws PersistenceException
    {
        if(tgts == null)
            throw new IllegalArgumentException(
                "Suplied tgt array is empty or invalid");  
        
        List<TGTEventError> listTGTEventErrors = new Vector<TGTEventError>();
        
        Connection connection = null;
        PreparedStatement psInsert = null;
        PreparedStatement psDelete = null;
        PreparedStatement psDeleteAliasR = null;
        PreparedStatement psDeleteAliasF = null;
        PreparedStatement psUpdate = null;
        try
        {
            connection = _oDataSource.getConnection(); //Manage connection
            connection.setAutoCommit(false);

            if (_aliasStoreSP != null)
                psDeleteAliasR = connection.prepareStatement(
                    _aliasStoreSP.getQueryAliasRemove());
            
            if (_aliasStoreIDP != null)
                psDeleteAliasF = connection.prepareStatement(
                    _aliasStoreIDP.getQueryAliasRemove());
            
            psInsert = connection.prepareStatement(_sInsertQuery);
            psDelete = connection.prepareStatement(_sRemoveQuery);
            psUpdate = connection.prepareStatement(_sUpdateQuery);            
                        
            Vector<ITGT> vCreate = new Vector<ITGT>();
            Vector<ITGT> vUpdate = new Vector<ITGT>();
            Vector<ITGT> vRemove = new Vector<ITGT>();
            
            for(JDBCTGT tgt : tgts) //For all tgts
            {
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
                    while(exists(id)); //Key allready exists   
                    
                    tgt.setId(id);
                    //Update expiration time
                    long expiration = System.currentTimeMillis() + _lExpiration;
                    tgt.setTgtExpTime(expiration);                    
                    psInsert.setString(1, id);
                    psInsert.setTimestamp(2, new Timestamp(expiration));
                    psInsert.setBytes(3, Serialize.encode(tgt.getUser()));
                    psInsert.setBytes(4, Serialize.encode(tgt.getAuthenticationProfile()));   
                    psInsert.setBytes(5, Serialize.encode(tgt.getModifiableAuthNProfileIDs()));
                    psInsert.setBytes(6, Serialize.encode(tgt.getModifiableRequestorIDs()));
                    psInsert.setBytes(7, Serialize.encode(tgt.getAttributes()));
                    psInsert.addBatch();     
                    
                    vCreate.add(tgt);
                }
                else if(tgt.isExpired()) //Expired
                {                   
                    _logger.debug("TGT Expired: " + id);    
                    
                    if (psDeleteAliasR != null)
                    {
                        psDeleteAliasR.setString(1, id);           
                        psDeleteAliasR.addBatch();
                    }
                    
                    if (psDeleteAliasF != null)
                    {
                        psDeleteAliasF.setString(1, id);           
                        psDeleteAliasF.addBatch();
                    }
                    
                    vRemove.add(tgt);
                }    
                else //Update
                {
                    //Update expiration time
                    long expiration = System.currentTimeMillis() + _lExpiration;
                    tgt.setTgtExpTime(expiration);
                    //Update tgt
                    psUpdate.setTimestamp(1, new Timestamp(expiration));
                    psUpdate.setBytes(2, Serialize.encode(tgt.getUser()));           
                    psUpdate.setBytes(3, Serialize.encode(tgt.getAuthenticationProfile()));
                    psUpdate.setBytes(4, Serialize.encode(tgt.getModifiableAuthNProfileIDs()));
                    psUpdate.setBytes(5, Serialize.encode(tgt.getModifiableRequestorIDs()));
                    psUpdate.setBytes(6, Serialize.encode(tgt.getAttributes()));
                    psUpdate.setString(7, id);
                    psUpdate.addBatch();    
                    
                    vUpdate.add(tgt);
                } 
            }
            
            try
            {
                int iTotalAdded = 0;
                for(int i : psInsert.executeBatch())
                {
                    iTotalAdded += i;
                }      
                _logger.debug(iTotalAdded + " new TGT(s) added by batch");
                
                for (ITGT tgt: vCreate)
                {
                    try
                    {
                        processEvent(TGTListenerEvent.ON_CREATE, tgt);
                    }
                    catch (TGTListenerException e)
                    {
                        listTGTEventErrors.addAll(e.getErrors());
                    }
                }
            }
            catch (SQLException e)
            {
                _logger.error("Could not execute insert batch", e);          
                throw new PersistenceException(SystemErrors.ERROR_RESOURCE_INSERT);
            } 
            
            try
            {
                for (ITGT tgt: vRemove)
                {
                    IUser tgtUser = tgt.getUser();
                    _eventLogger.info(
                        new UserEventLogItem(null, tgt.getId(), null, 
                            UserEvent.TGT_EXPIRED, tgtUser.getID(), 
                            tgtUser.getOrganization(), null, null, this, null));
                    
                    try
                    {
                        processEvent(TGTListenerEvent.ON_REMOVE, tgt);
                    }
                    catch (TGTListenerException e)
                    {
                        listTGTEventErrors.addAll(e.getErrors());
                    }
                }
                
                int iTotalDeleted = 0;
                for(int i : psDelete.executeBatch())
                {
                    iTotalDeleted += i;
                }  
                _logger.debug(iTotalDeleted + " TGT(s) deleted by batch");
            }
            catch (SQLException e)
            {
                _logger.error("Could not execute delete batch", e);          
                throw new PersistenceException(SystemErrors.ERROR_RESOURCE_REMOVE);
            } 
            
            if (psDeleteAliasR != null)
            {
                try
                {
                    int iTotalAliasDeleted = 0;
                    for(int i : psDeleteAliasR.executeBatch())
                    {
                        iTotalAliasDeleted += i;
                    }  
                    _logger.debug(iTotalAliasDeleted + " (requestor based) alias(es) deleted by batch");
                }
                catch (SQLException e)
                {
                    _logger.error("Could not execute delete (requestor based) alias batch", e);          
                    throw new PersistenceException(SystemErrors.ERROR_RESOURCE_REMOVE);
                } 
            }
            
            if (psDeleteAliasF != null)
            {
                try
                {
                    int iTotalAliasDeleted = 0;
                    for(int i : psDeleteAliasF.executeBatch())
                    {
                        iTotalAliasDeleted += i;
                    }  
                    _logger.debug(iTotalAliasDeleted + " (remote enitity based) alias(es) deleted by batch");
                }
                catch (SQLException e)
                {
                    _logger.error("Could not execute delete (remote enitity based) alias batch", e);          
                    throw new PersistenceException(SystemErrors.ERROR_RESOURCE_REMOVE);
                } 
            }
                        
            try
            {
                int iTotalUpdated = 0;
                for(int i : psUpdate.executeBatch())
                {
                    iTotalUpdated += i;
                }  
                _logger.debug(iTotalUpdated + " TGT(s) updated by batch");
                
                for (ITGT tgt: vUpdate)
                {
                    try
                    {
                        processEvent(TGTListenerEvent.ON_UPDATE, tgt);
                    }
                    catch (TGTListenerException e)
                    {
                        listTGTEventErrors.addAll(e.getErrors());
                    }
                }
            }
            catch (SQLException e)
            {
                _logger.error("Could not execute update batch", e);          
                throw new PersistenceException(SystemErrors.ERROR_RESOURCE_UPDATE);
            } 
            
            connection.commit(); 
            
            if (listTGTEventErrors != null)
            {//TGT Event processing failed, error has been logged already
                throw new TGTListenerException(listTGTEventErrors);
            }
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute Batch", e); 
            try
            {
                if(connection != null)
                    connection.rollback();
            }
            catch (SQLException e1)
            {
                _logger.warn("Could not rollback batch", e);
            }
                    
            throw new PersistenceException(SystemErrors.ERROR_INTERNAL);
        }
        catch (PersistenceException e)
        {         
            try
            {
                if(connection != null)
                    connection.rollback();
            }
            catch (SQLException e1)
            {
                _logger.warn("Could not rollback batch", e);
            }            
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Could not connect to JDBC resource", e);
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_CONNECT);
        }     
        finally
        {
            try
            {
                if(psInsert != null )
                    psInsert.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close insert statement", e);
            }
            
            try
            {
                if(psDelete != null )
                    psDelete.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close delete statement", e);
            }
            
            try
            {
                if(psDeleteAliasR != null )
                    psDeleteAliasR.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close delete (requestor based) alias statement", e);
            }
            
            try
            {
                if(psDeleteAliasF != null )
                    psDeleteAliasF.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close delete (remote entity based) alias statement", e);
            }
            
            try
            {
                if(psUpdate != null )
                    psUpdate.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close update statement", e);
            }
            
            try
            {
                if(connection != null)
                    connection.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close connection", e);
            }
        }
    }

    /**
     * Remove all expired tgts.
     * 
     * e.g. <code>DELETE FROM tgt WHERE expiration <= NOW()</code>
     * @see ICleanable#removeExpired()
     */
    public void removeExpired() throws PersistenceException
    {
        Connection oConnection = null;
        PreparedStatement psSelect = null;
        PreparedStatement psDelete = null;
        ResultSet rsSelect = null;
        try
        {
            oConnection = _oDataSource.getConnection();
            
            psSelect = oConnection.prepareStatement(_sSelectExpiredQuery);
            psSelect.setTimestamp(1, new Timestamp(System.currentTimeMillis())); 
            rsSelect = psSelect.executeQuery();
            while(rsSelect.next())
            {
                String sId = rsSelect.getString(_sColumnID);
                if (sId != null)
                {
                    try
                    {
                        ITGT tgt = retrieve(sId);
                        if (tgt != null)
                        {
                            String sTGTUserID = null;
                            String sTGTUserOrganization = null;
                            IUser tgtUser = tgt.getUser();
                            if (tgtUser != null)
                            {
                                sTGTUserID = tgtUser.getID();
                                sTGTUserOrganization = tgtUser.getOrganization();
                            }
                            else
                                _logger.debug("No user available for TGT with ID: " + sId);
                            
                            _eventLogger.info(
                                new UserEventLogItem(null, sId, null, UserEvent.TGT_EXPIRED, 
                                    sTGTUserID, sTGTUserOrganization, null, null, 
                                    this, "clean"));
                            
                            processEvent(TGTListenerEvent.ON_EXPIRE, tgt);
                        }
                        else
                            _logger.debug("No TGT available with ID: " + sId);
                    }
                    catch (PersistenceException e)
                    {
                        _logger.debug("Invalid TGT will be removed: " + sId, e);
                    }
                }
            }
            
            psDelete = oConnection.prepareStatement(_sRemoveExpiredQuery);
            psDelete.setTimestamp(1, new Timestamp(System.currentTimeMillis()));           
            int i = psDelete.executeUpdate();
            if(i > 0)
                _logger.debug(i + " TGT(s) expired");
            
            int iCountR = 0;
            if (_aliasStoreSP != null)
                iCountR = _aliasStoreSP.clean(oConnection);
            
            int iCountF = 0;
            if (_aliasStoreIDP != null)
                iCountF = _aliasStoreIDP.clean(oConnection);
            
            if (_logger.isDebugEnabled() && iCountR + iCountF > 0)
            {
                StringBuffer sbDebug = new StringBuffer("Cleaned '");
                sbDebug.append(iCountR);
                sbDebug.append("' (requestor based) aliasses and '");
                sbDebug.append(iCountF);
                sbDebug.append("' (remote enitity based) aliasses");
                _logger.debug(sbDebug.toString());
            }
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute delete expired", e);          
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_REMOVE);
        }
        catch (Exception e)
        {
            _logger.error("Internal error during removal of expired tgt", e);          
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_REMOVE);
        }       
        finally
        {
            try
            {
                if (rsSelect != null)
                    rsSelect.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close resultset", e);
            }
            try
            {
                if (psSelect != null)
                    psSelect.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close select statement", e);
            }
            try
            {
                if (psDelete != null)
                    psDelete.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close delete statement", e);
            }
            try
            {
                if (oConnection != null)
                    oConnection.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close connection", e);
            }
        }        
    }
    
    /**
     * @see com.alfaariss.oa.api.poll.IPollable#poll()
     */
    public long poll() throws OAException
    {
        return getTGTCount();
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
        if (_aliasStoreSP == null)
        {
            _logger.debug("SP role alias store not available");
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        _aliasStoreSP.putAlias(type, requestorID, tgtID, alias);
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#getAlias(java.lang.String, java.lang.String, java.lang.String)
     * @deprecated please use getRequestorAliasStore().getAlias() instead.
     */
    public String getAlias(String type, String requestorID, String tgtID)
        throws OAException
    {
        if (_aliasStoreSP == null)
        {
            _logger.debug("SP role alias store not available");
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return _aliasStoreSP.getAlias(type, requestorID, tgtID);
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#getTGTID(java.lang.String, java.lang.String, java.lang.String)
     * @deprecated please use getRequestorAliasStore().getTGTID() instead.
     */
    public String getTGTID(String type, String requestorID, String alias)
        throws OAException
    {
        if (_aliasStoreSP == null)
        {
            _logger.debug("SP role alias store not available");
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return _aliasStoreSP.getTGTID(type, requestorID, alias);
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#isAlias(java.lang.String, java.lang.String, java.lang.String)
     * @deprecated please use getRequestorAliasStore().isAlias() instead.
     */
    public boolean isAlias(String type, String requestorID, String alias)
        throws OAException
    {
        if (_aliasStoreSP == null)
        {
            _logger.debug("SP role alias store not available");
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return _aliasStoreSP.isAlias(type, requestorID, alias);
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory#hasAliasSupport()
     * @deprecated please use getAliasStoreSP() != null instead.
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

    /*
     * Read the entity storage configuration.
     * 
     * If no configuration section is present the default queries are used.
     */
     private void createQueries(
         Element eConfig) throws TGTException, ConfigurationException
     {
         Element eEntity = _configurationManager.getSection(eConfig, "entity");
         if (eEntity == null)
         {
             _logger.info("No optional 'entity' section found in configuration, using default table and column names");
         }
         else
         {
             _sTableName = _configurationManager.getParam(eEntity, "table");
             _sColumnID = getIdColumnName(eEntity);    
             _sColumnEXPIRATION = getColumnName(eEntity, "tgtExpTime");
             _sColumnUSER = getColumnName(eEntity, "user");
             _sColumnAUTHN_PROFILE = getColumnName(eEntity, "authenticationProfile");
             _sColumnAUTHN_PROFILES = getColumnName(eEntity, "authenticationProfileIDs");
             _sColumnREQUESTOR_IDS = getColumnName(eEntity, "requestorIDs");
             _sColumnATTRIBUTES = getColumnName(eEntity, "attributes");
         }
         
         if (_sTableName == null)
             _sTableName = TABLE_NAME;
          
         if (_sColumnID == null)
             _sColumnID = COLUMN_ID;
         
         if (_sColumnEXPIRATION == null)
             _sColumnEXPIRATION = COLUMN_EXPIRATION;
         
         if (_sColumnUSER == null)
             _sColumnUSER = COLUMN_USER;
         
         if (_sColumnAUTHN_PROFILE == null)
             _sColumnAUTHN_PROFILE = COLUMN_AUTHN_PROFILE;
         
         if (_sColumnAUTHN_PROFILES == null)
             _sColumnAUTHN_PROFILES = COLUMN_AUTHN_PROFILES;
         
         if (_sColumnREQUESTOR_IDS == null)
             _sColumnREQUESTOR_IDS = COLUMN_REQUESTOR_IDS;

         if (_sColumnATTRIBUTES == null)
             _sColumnATTRIBUTES = COLUMN_ATTRIBUTES;  
         
         //SearchQuery
         StringBuffer sb = new StringBuffer("SELECT ");
         sb.append(_sColumnEXPIRATION).append(", ");
         sb.append(_sColumnUSER).append(", ");
         sb.append(_sColumnAUTHN_PROFILE).append(", ");
         sb.append(_sColumnAUTHN_PROFILES).append(", ");
         sb.append(_sColumnREQUESTOR_IDS).append(", ");
         sb.append(_sColumnATTRIBUTES);
         sb.append(" FROM ").append(_sTableName);
         sb.append(" WHERE ").append(_sColumnID).append("=?");
         _sSearchQuery = sb.toString();
         _logger.debug("Using SearchQuery: " + _sSearchQuery);
         
         //CountQuery 
         sb = new StringBuffer("SELECT COUNT(");
         sb.append(_sColumnID);
         sb.append(") FROM ");
         sb.append(_sTableName);
         _sCountQuery = sb.toString();
         _logger.debug("Using CountQuery: " + _sCountQuery);

         //InsertQuery
         sb = new StringBuffer("INSERT INTO ");
         sb.append(_sTableName).append("(");
         sb.append(_sColumnID).append(", ");
         sb.append(_sColumnEXPIRATION).append(", ");
         sb.append(_sColumnUSER).append(", ");
         sb.append(_sColumnAUTHN_PROFILE).append(", ");
         sb.append(_sColumnAUTHN_PROFILES).append(", ");
         sb.append(_sColumnREQUESTOR_IDS).append(",");
         sb.append(_sColumnATTRIBUTES);
         sb.append(") VALUES(? , ?, ?, ?, ?, ?, ?)");             
         _sInsertQuery = sb.toString();
         _logger.debug("Using InsertQuery: " + _sInsertQuery);
         
         //UpdateQuery
         sb = new StringBuffer("UPDATE ");
         sb.append(_sTableName).append(" SET ");
         sb.append(_sColumnEXPIRATION).append("=?, ");
         sb.append(_sColumnUSER).append("=?, ");
         sb.append(_sColumnAUTHN_PROFILE).append("=?, ");
         sb.append(_sColumnAUTHN_PROFILES).append("=?, ");
         sb.append(_sColumnREQUESTOR_IDS).append("=?, ");
         sb.append(_sColumnATTRIBUTES).append("=? WHERE  ");
         sb.append(_sColumnID).append("=?");
         _sUpdateQuery = sb.toString();
         _logger.debug("Using UpdateQuery: " + _sUpdateQuery);
         
         //RemoveQuery
         sb = new StringBuffer("DELETE FROM ");
         sb.append(_sTableName).append(" WHERE ");
         sb.append(_sColumnID).append("=?");
         _sRemoveQuery = sb.toString();
         _logger.debug("Using RemoveQuery: " + _sRemoveQuery);
         
         //RemoveExpiredQuery 
         sb = new StringBuffer("DELETE FROM ");
         sb.append(_sTableName).append(" WHERE ");
         sb.append(_sColumnEXPIRATION).append("<=?");
         _sRemoveExpiredQuery = sb.toString();
         _logger.debug("Using RemoveExpiredQuery: " + _sRemoveExpiredQuery);
         
         //SelectExpiredQuery 
         sb = new StringBuffer("SELECT ");
         sb.append(_sColumnID);
         sb.append(" FROM ");
         sb.append(_sTableName).append(" WHERE ");
         sb.append(_sColumnEXPIRATION).append("<=?");
         _sSelectExpiredQuery = sb.toString();
         _logger.debug("Using SelectExpiredQuery: " + _sSelectExpiredQuery);
     }
     
     private void verifyTableConfig(Element eConfig) throws OAException
     {
         Connection oConnection = null;
         PreparedStatement pVerify = null;
         try
         {   
             try
             {
                 oConnection = _oDataSource.getConnection();
             }
             catch (SQLException e)
             {
                 _logger.error("Could not connect to resource", e);
                 throw new DatabaseException(SystemErrors.ERROR_INIT);
             }
             
             String sVerificationQuery = null;
             try
             {
                 //<validation query=""/>    
                 Element eValidation = _configurationManager.getSection(eConfig, "validation");
                 if(eValidation != null)
                 {
                     sVerificationQuery = _configurationManager.getParam(eValidation, "query");
                     if(sVerificationQuery == null || sVerificationQuery.length() == 0)
                     {
                         //DD Do not verify the table if empty query configured
                         _logger.warn("Empty validation query found, table structure is not validated");
                         //finally is executed before return
                         return;
                     }
                 }
                 
                 if(sVerificationQuery == null)
                 {
                     //DD Use default query if no validation.query parameter configured                     
                     StringBuffer sbVerificationQuery = new StringBuffer("SELECT ");
                     sbVerificationQuery.append(_sColumnID).append(",");
                     sbVerificationQuery.append(_sColumnEXPIRATION).append(",");
                     sbVerificationQuery.append(_sColumnUSER).append(",");
                     sbVerificationQuery.append(_sColumnAUTHN_PROFILE).append(",");
                     sbVerificationQuery.append(_sColumnAUTHN_PROFILES).append(",");
                     sbVerificationQuery.append(_sColumnREQUESTOR_IDS).append(",");
                     sbVerificationQuery.append(_sColumnATTRIBUTES);
                     sbVerificationQuery.append(" FROM ");
                     sbVerificationQuery.append(_sTableName);
                     sbVerificationQuery.append(" LIMIT 1"); 
                     sVerificationQuery = sbVerificationQuery.toString();
                     _logger.info("No validation query found, using default: " + sVerificationQuery);
                 }
             }
             catch(ConfigurationException e)
             {
                 
                 _logger.error("Invalid validation query found", e);
                 throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
             }
             
             pVerify = oConnection.prepareStatement(sVerificationQuery);
             try
             {
                 pVerify.executeQuery();
             }
             catch(Exception e)
             {
                 StringBuffer sbError = new StringBuffer("Invalid table configured '");
                 sbError.append(_sTableName);
                 sbError.append("' verified with query: ");
                 sbError.append(sVerificationQuery);
                 _logger.error(sbError.toString(), e);
                 throw new DatabaseException(SystemErrors.ERROR_INIT);
             }  
         }
         catch (OAException e)
         {
             throw e;
         }
         catch (Exception e)
         {
             _logger.error("Internal error during verification of configured table", e);          
             throw new OAException(SystemErrors.ERROR_INIT);
         }       
         finally
         {
             try
             {
                 if (pVerify != null)
                     pVerify.close();
             }
             catch (SQLException e)
             {
                 _logger.debug("Could not close statement", e);
             }
             try
             {
                 if (oConnection != null)
                     oConnection.close();
             }
             catch (SQLException e)
             {
                 _logger.debug("Could not close connection", e);
             }
         }  
     }
     
     //Retrieve id column name
     private String getIdColumnName(Element eConfig) 
         throws TGTException, ConfigurationException
     {
         String sIdColumn = null;
         if (eConfig != null)
         {
             Element eIdColumn = _configurationManager.getSection(eConfig, "id");
             if(eIdColumn == null)
             {
                 _logger.error("Could not find 'id' section");
                 throw new TGTException(SystemErrors.ERROR_CONFIG_READ);
             }
             
             sIdColumn = _configurationManager.getParam(eIdColumn, "column"); 
             if(sIdColumn == null)
             {
                 _logger.error("Could not find column name for id");
                 throw new TGTException(SystemErrors.ERROR_CONFIG_READ);
             }
         }
         
         return sIdColumn;
     }

     //Retrieve property column name
     private String getColumnName(Element eConfig, 
         String sName) throws TGTException, ConfigurationException
     {
         String sColumn = null;
         if (eConfig != null || sName != null)
         {
             Element eColumn = _configurationManager.getSection(eConfig, 
                 "property", "name=" + sName);
             if(eColumn == null)
                 _logger.warn("No optional 'property' section found for property with name: " + sName);
             else
             {
                 sColumn = _configurationManager.getParam(eColumn, "column"); 
                 if(sColumn == null)
                 {
                     _logger.error("Could not find column name for property " + sName);
                     throw new TGTException(SystemErrors.ERROR_CONFIG_READ);
                 }
             }
         }
         return sColumn;
     }
     
    //Retrieve the current number of tgt's
    private int getTGTCount() throws TGTException
    {
        Connection oConnection =null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        int iRet = 0;
        try
        {
            oConnection = _oDataSource.getConnection();
            ps = oConnection.prepareStatement(_sCountQuery);
            rs = ps.executeQuery();
            if(rs.next())
               iRet = rs.getInt(1);
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute count query", e);
            throw new TGTException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (Exception e)
        {
            _logger.error("Internal error during TGT counting", e);
            throw new TGTException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }       
        finally
        {
            try
            {
                if(rs != null)
                   rs.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close resultset", e);
            }
            try
            {
                if(ps != null)
                   ps.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close statement", e);
            }
            try
            {
                if(oConnection != null)
                   oConnection.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close connection", e);
            }
        }
        return iRet;
    }    
    
    /**
     * Persist the TGT in the JDBC storage.
     * @param tgt The TGT to persist.
     * @param bProcessEvent TRUE if event must be performed
     * @return the event that was or would be performed 
     * @throws PersistenceException If persistance.
     * @see IEntityManager#persist(IEntity)
     */
    private TGTListenerEvent performPersist(JDBCTGT tgt, boolean bProcessEvent) throws PersistenceException
    {
        if (tgt == null)
            throw new IllegalArgumentException(
                "Suplied tgt is empty or invalid");
        
        TGTListenerEvent listenerEvent = null;
        List<TGTEventError> listTGTEventErrors = null;
        
        Connection oConnection = null;
        PreparedStatement ps = null;
        
        String id = tgt.getId();
        try
        {
            oConnection = _oDataSource.getConnection();
            if (id == null) // New TGT
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
                while(exists(id)); //Key allready exists 
                
                //Update expiration time and id
                tgt.setId(id);
                long expiration = System.currentTimeMillis() + _lExpiration;
                tgt.setTgtExpTime(expiration);
                
                try
                {
                    //Create statement
                    ps = oConnection.prepareStatement(_sInsertQuery);                    
                    ps.setString(1, id);            
                    ps.setTimestamp(2, new Timestamp(expiration));  
                    ps.setBytes(3, Serialize.encode(tgt.getUser()));
                    ps.setBytes(4, Serialize.encode(tgt.getAuthenticationProfile()));
                    ps.setBytes(5, Serialize.encode(tgt.getModifiableAuthNProfileIDs()));
                    ps.setBytes(6, Serialize.encode(tgt.getModifiableRequestorIDs()));
                    ps.setBytes(7, Serialize.encode(tgt.getAttributes()));
                    int i = ps.executeUpdate();
                    _logger.debug(i + " New TGT(s) added:" + id);        
                    
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
                catch (SQLException e)
                {                    
                    _logger.error("Could not execute insert query: " + 
                        _sInsertQuery, e);
                    throw new PersistenceException(SystemErrors.ERROR_RESOURCE_INSERT);
                }
            }
            else if (tgt.isExpired()) // Expired
            {
                _logger.debug("TGT Expired: " + id);
                
                IUser tgtUser = tgt.getUser();
                _eventLogger.info(
                    new UserEventLogItem(null, tgt.getId(), null, 
                        UserEvent.TGT_EXPIRED, tgtUser.getID(), 
                        tgtUser.getOrganization(), null, null, this, null));
                
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
                
                try
                {
                    ps = oConnection.prepareStatement(_sRemoveQuery);
                    ps.setString(1, id);
                    int i = ps.executeUpdate();
                    _logger.debug(i + " TGT removed: " + id);
                }
                catch (SQLException e)
                {                    
                    _logger.error("Could not execute delete query: " + 
                        _sRemoveQuery, e);
                    throw new PersistenceException(SystemErrors.ERROR_RESOURCE_REMOVE);
                }
                
                int iCountR = 0;
                if (_aliasStoreSP != null)
                    iCountR = _aliasStoreSP.remove(oConnection, id);
                int iCountF = 0;
                if (_aliasStoreIDP != null)
                    iCountF = _aliasStoreIDP.remove(oConnection, id);
                
                if (_logger.isDebugEnabled() && iCountR + iCountF > 0)
                {
                    StringBuffer sbDebug = new StringBuffer("Removed '");
                    sbDebug.append(iCountR);
                    sbDebug.append("' (requestor based) aliasses and '");
                    sbDebug.append(iCountF);
                    sbDebug.append("' (remote enitity based) aliasses");
                    _logger.debug(sbDebug.toString());
                }
            }
            else // Update
            {
                try
                {
                    // Update expiration time
                    long expiration = System.currentTimeMillis() + _lExpiration;
                    tgt.setTgtExpTime(expiration);
                    // Update tgt
                    ps = oConnection.prepareStatement(_sUpdateQuery);
                    ps.setTimestamp(1, new Timestamp(expiration));           
                    ps.setBytes(2, Serialize.encode(tgt.getUser()));              
                    ps.setBytes(3, Serialize.encode(tgt.getAuthenticationProfile()));
                    ps.setBytes(4, Serialize.encode(tgt.getModifiableAuthNProfileIDs()));
                    ps.setBytes(5, Serialize.encode(tgt.getModifiableRequestorIDs()));
                    ps.setBytes(6, Serialize.encode(tgt.getAttributes()));
                    ps.setString(7, id);
                    int i = ps.executeUpdate();
                    _logger.debug(i + " TGT updated:" + id);
                    
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
                catch (SQLException e)
                {                    
                    _logger.error("Could not execute update query: " + _sUpdateQuery, e);
                    throw new PersistenceException(SystemErrors.ERROR_RESOURCE_UPDATE);
                }
            }
            
            if (listTGTEventErrors != null)
            {//TGT Event processing failed, error has been logged already
                throw new TGTListenerException(listTGTEventErrors);
            }
        }
        catch (PersistenceException e)
        {
            throw e;
        }  
        catch (Exception e)
        {
            _logger.error("Internal error during persist of tgt with id: " + id, e);
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_UPDATE);
        }  
        finally
        {
            try
            {
                if (ps != null)
                    ps.close();
            }
            catch (SQLException e)
            {                    
                _logger.error("Could not close statement", e);
            }
            try
            {
                if (oConnection != null)
                    oConnection.close();
            }
            catch (SQLException e)
            {                    
                _logger.error("Could not close connection", e);
            }
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
                if (tgt != null)
                    listener.processTGTEvent(event, tgt);
                else
                    _logger.debug("No TGT available; event not processed: " + event);
            }
            catch (TGTListenerException e)
            {
                StringBuffer sbDebug = new StringBuffer("Could not process '");
                sbDebug.append(event);
                sbDebug.append("' event for TGT with id '");
                sbDebug.append(tgt == null ? "NULL" : tgt.getId());
                sbDebug.append("': ");
                sbDebug.append(e);
                _logger.debug(sbDebug.toString(), e);
                
                listErrors.addAll(e.getErrors());
            }
            catch (Exception e)
            {
                StringBuffer sbDebug = new StringBuffer("Internal error while processing '");
                sbDebug.append(event);
                sbDebug.append("' event for TGT with id: ");
                sbDebug.append(tgt == null ? "NULL" : tgt.getId());
                _logger.debug(sbDebug.toString(), e);
                
                listErrors.add(new TGTEventError(UserEvent.INTERNAL_ERROR));
            }
        } 
        if (!listErrors.isEmpty())
            throw new TGTListenerException(listErrors);
    }

}