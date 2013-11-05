/*
 * * Asimba - Serious Open Source SSO
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
 * * Asimba - Serious Open Source SSO - More information on www.asimba.org
 * 
 */
package com.alfaariss.oa.engine.session.jdbc;
import java.io.UnsupportedEncodingException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;
import java.util.Locale;

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
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.api.storage.IStorageFactory;
import com.alfaariss.oa.api.storage.clean.ICleanable;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.attribute.SessionAttributes;
import com.alfaariss.oa.engine.core.authentication.AuthenticationProfile;
import com.alfaariss.oa.engine.core.session.SessionException;
import com.alfaariss.oa.engine.core.session.factory.ISessionFactory;
import com.alfaariss.oa.util.ModifiedBase64;
import com.alfaariss.oa.util.Serialize;
import com.alfaariss.oa.util.database.DatabaseException;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;
import com.alfaariss.oa.util.logging.UserEventLogItem;
import com.alfaariss.oa.util.storage.factory.AbstractStorageFactory;

/**
 * <code>ISessionFactory</code> which uses a JDBC source for storage.
 * 
 * @author MHO
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class JDBCSessionFactory extends AbstractStorageFactory 
    implements ISessionFactory<JDBCSession>
{  
    private final static String TABLE_NAME = "session";
    private final static String COLUMN_ID = "id";
    private final static String COLUMN_TGT_ID = "tgt_id";
    private final static String COLUMN_STATE = "state";
    private final static String COLUMN_REQUESTOR = "requestor_id";
    private final static String COLUMN_URL = "url";
    private final static String COLUMN_EXPIRATION = "expiration";
    private final static String COLUMN_FORCED_AUTHENTICATE = "forced_authenticate";
    private final static String COLUMN_OWNER = "sessionuser";
    private final static String COLUMN_ATTRIBUTES = "attributes";
    private final static String COLUMN_FORCED_USERID = "forced_userid";
    private final static String COLUMN_LOCALE = "locale";
    private final static String COLUMN_SELECTED_AUTHN_PROFILE = "selected_authn_profile";
    private final static String COLUMN_AUTHN_PROFILES = "authn_profiles";
    private final static String COLUMN_PASSIVE = "passive";
    
    private String _sTableName;
    private String _sColumnID;
    private String _sColumnTGT_ID;
    private String _sColumnSTATE;
    private String _sColumnREQUESTOR;
    private String _sColumnURL;
    private String _sColumnEXPIRATION;
    private String _sColumnFORCED_AUTHENTICATE;
    private String _sColumnOWNER;
    private String _sColumnATTRIBUTES;
    private String _sColumnFORCED_USERID;
    private String _sColumnLOCALE;
    private String _sColumnSELECTED_AUTHN_PROFILE;
    private String _sColumnAUTHN_PROFILES;
    private String _sColumnPASSIVE;
    
    //Queries
    private String _sSearchQuery = null;
    private String _sCountQuery = null; 
    private String _sInsertQuery = null; 
    private String _sUpdateQuery = null; 
    private String _sRemoveQuery = null; 
    private String _sRemoveExpiredQuery = null; 
    
    //The JDBC manager 
    private DataSource _oDataSource;
    //The system logger
    private Log _logger;
    private Log _eventLogger;
       
	/**
     * Create a new <code>JDBCFactory</code>.
     */
    public JDBCSessionFactory()
    {
        super();        
        _logger = LogFactory.getLog(JDBCSessionFactory.class);
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
    }

    /**
     * Call super class and start cleaner.
     * @see IStorageFactory#start()
     */
    public void start() throws OAException
    {

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
        
        if(_tCleaner != null)
            _tCleaner.start();    
    }

	/**
	 * Create a new session if max is not reached yet.
	 * @throws SessionException if maximum is reached.
	 * @see com.alfaariss.oa.engine.core.session.factory.ISessionFactory#createSession(java.lang.String)
	 */
	public ISession createSession(String sRequestorId) throws SessionException
    {
        if(sRequestorId == null)
            throw new IllegalArgumentException("Suplied requestor id is empty");
        if(_lMax > 0)          
        {
            if(getSessionCount() >= _lMax)
            {
                _logger.error("Could not create session, maximum reached");
                throw new SessionException(SystemErrors.ERROR_SESSION_MAX);
            }
        }
        return new JDBCSession(this, sRequestorId);
	}
    
    /**
	 * Check if a Session with the given ID exists.	
	 * @see IEntityManager#exists(java.lang.Object)
	 */
	public boolean exists(Object id) throws PersistenceException
    {
        if(id == null || !(id instanceof String))
            throw new IllegalArgumentException("Suplied id is empty or invalid");
        
        boolean bRet = false;
        Connection oConnection = null;
        PreparedStatement psSelect = null;
        ResultSet rsSelect = null;

        try
        {
            oConnection = _oDataSource.getConnection();
            psSelect = oConnection.prepareStatement(_sSearchQuery);
            psSelect.setString(1, (String)id);
            rsSelect = psSelect.executeQuery();
            if(rsSelect.next())
               bRet = true;
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute search query", e);
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (Exception e)
        {
            _logger.error("Internal error during exists check for session with id: " + id, e);
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
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
	 * Retrieve the Session with the given id.
	 * @param id The Session id.
	 * @return The Session, or null if a Session with the given id does not exist.
	 * @throws PersistenceException If retrieving fails.
	 */
    @SuppressWarnings("unchecked") //Serialize value can not be checked
	public JDBCSession retrieve(Object id)
	  throws PersistenceException
    {
        if(id == null || !(id instanceof String))
            throw new IllegalArgumentException("Suplied id is empty or invalid");
        
        Connection oConnection = null;
        JDBCSession session = null;
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
               session = new JDBCSession(this, rs.getString(_sColumnREQUESTOR));
               session.setId((String)id);
               
               String sTGTID = rs.getString(_sColumnTGT_ID);
               if (sTGTID != null)
                   session.setTGTId(sTGTID);
               
               session.setState(SessionState.values()[rs.getInt(_sColumnSTATE)]);              
                            
               String sUrl = rs.getString(_sColumnURL);
               if (sUrl != null)
                   session.setProfileURL(sUrl);
               
               IUser oUser = (IUser)Serialize.decode(rs.getBytes(_sColumnOWNER));
               if (oUser != null)
                   session.setUser(oUser);
               
               session.setExpTime(rs.getTimestamp(_sColumnEXPIRATION).getTime());
               session.setForcedAuthentication(rs.getBoolean(_sColumnFORCED_AUTHENTICATE));
               session.setPassive(rs.getBoolean(_sColumnPASSIVE));
               
               SessionAttributes oAttributes = 
                   (SessionAttributes)Serialize.decode(rs.getBytes(_sColumnATTRIBUTES));
               if (oAttributes != null)
                   session.setAttributes(oAttributes);
               
               String sForcedUid = rs.getString(_sColumnFORCED_USERID);
               if (sForcedUid != null)
                   session.setForcedUserID(sForcedUid);
               
               Locale oLocale = (Locale)Serialize.decode(rs.getBytes(_sColumnLOCALE));
               if (oLocale != null)
                   session.setLocale(oLocale);
               
               List listProfiles = (List)Serialize.decode(rs.getBytes(_sColumnAUTHN_PROFILES));
               if (listProfiles != null)
                   session.setAuthNProfiles(listProfiles);
               
               AuthenticationProfile oProfile = (AuthenticationProfile)Serialize.decode(rs.getBytes(_sColumnSELECTED_AUTHN_PROFILE));
               if (oProfile != null)
                   session.setSelectedAuthNProfile(oProfile);
            }      
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute search query: " + _sSearchQuery, e);
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch(ClassCastException e)
        {
            _logger.error("Could not decode, invalid class type", e);
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (Exception e)
        {
            _logger.error("Internal error during retrieve of session id: " + id, e);
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
        return session;
	}

    /**
     * Persist the session in the JDBC storage.
     * 
     * The sessionstate is saved with its name.
     * @param session The session to persist.
     * @throws PersistenceException If persistance fails.
     * @see IEntityManager#persist(IEntity)
     */
    public void persist(JDBCSession session) throws PersistenceException
    {
        if (session == null)
            throw new IllegalArgumentException(
                "Suplied session is empty or invalid");
        
        Connection oConnection = null;
        PreparedStatement psInsert = null;
        PreparedStatement psDelete = null;
        PreparedStatement psUpdate = null;
        
        String id = session.getId();
        try
        {
            oConnection = _oDataSource.getConnection();
            if (id == null) // New Session
            {
                try
                {     
                    byte[] baId = new byte[ISession.ID_BYTE_LENGTH];
                    do
                    {                
                        _random.nextBytes(baId);
                        try
                        {
                            id = ModifiedBase64.encode(baId);
                        }
                        catch (UnsupportedEncodingException e)
                        {
                            _logger.error("Could not create id for byte[]: " + baId, e);
                            throw new PersistenceException(SystemErrors.ERROR_INTERNAL);
                        }
                    }
                    while(exists(id)); //Key allready exists  
                                        
                    // Update expiration time and id
                    long expiration = System.currentTimeMillis() + _lExpiration;
                    session.setTgtExpTime(expiration);
                    session.setId(id);
                   
                    //Create statement                  
                    psInsert = oConnection.prepareStatement(_sInsertQuery);
                    psInsert.setString(1, id);                   
                    psInsert.setString(2, session.getTGTId());
                    psInsert.setInt(3, session.getState().ordinal());                   
                    psInsert.setString(4, session.getRequestorId());
                    psInsert.setString(5, session.getProfileURL());
                    psInsert.setBytes(6, Serialize.encode(session.getUser())); 
                    psInsert.setTimestamp(7, new Timestamp(expiration));
                    psInsert.setBoolean(8, session.isForcedAuthentication());
                    psInsert.setBoolean(9, session.isPassive());
                    psInsert.setBytes(10, Serialize.encode(session.getAttributes()));
                    psInsert.setString(11, session.getForcedUserID());
                    psInsert.setBytes(12, Serialize.encode(session.getLocale()));
                    psInsert.setBytes(13, Serialize.encode(session.getSelectedAuthNProfile()));
                    psInsert.setBytes(14, Serialize.encode(session.getAuthNProfiles()));
                    
                    int i = psInsert.executeUpdate();
                    _logger.info(i + " new session(s) added: " + id + " for requestor '"+session.getRequestorId() + "'");
                }
                catch (SQLException e)
                {                    
                    _logger.error("Could not execute insert query: " + _sInsertQuery, e);
                    throw new PersistenceException(SystemErrors.ERROR_RESOURCE_INSERT);
                }

            }
            else if (session.isExpired()) // Expired
            {
                try
                {
                    _logger.info("Session Expired: " + id);
                    
                    _eventLogger.info(new UserEventLogItem(session, null, 
                        UserEvent.SESSION_EXPIRED, this, null));
                    
                    psDelete = oConnection.prepareStatement(_sRemoveQuery);
                    psDelete.setString(1, id);
                    int i = psDelete.executeUpdate();
                    _logger.debug(i + " session(s) removed: " + id);
                }
                catch (SQLException e)
                {                    
                    _logger.error("Could not execute delete query: " + _sRemoveQuery, e);
                    throw new PersistenceException(SystemErrors.ERROR_RESOURCE_REMOVE);
                }
            }
            else // Update
            {  
                try
                {
                    // Update expiration time
                    long expiration = System.currentTimeMillis() + _lExpiration;
                    session.setExpTime(expiration);
                    psUpdate = oConnection.prepareStatement(_sUpdateQuery);
                    psUpdate.setString(1, session.getTGTId());
                    psUpdate.setInt(2, session.getState().ordinal());                  
                    psUpdate.setString(3, session.getRequestorId());
                    psUpdate.setString(4, session.getProfileURL());
                    psUpdate.setBytes(5, Serialize.encode(session.getUser()));                                    
                    psUpdate.setTimestamp(6, new Timestamp(expiration));
                    psUpdate.setBoolean(7, session.isForcedAuthentication());
                    psUpdate.setBoolean(8, session.isPassive());
                    psUpdate.setBytes(9, Serialize.encode(session.getAttributes()));
                    psUpdate.setString(10, session.getForcedUserID());
                    psUpdate.setBytes(11, Serialize.encode(session.getLocale()));
                    psUpdate.setBytes(12, Serialize.encode(session.getSelectedAuthNProfile()));
                    psUpdate.setBytes(13, Serialize.encode(session.getAuthNProfiles()));
                    psUpdate.setString(14, id);
                   
                    int i = psUpdate.executeUpdate();
                    _logger.info(i + " session(s) updated: " + id + " for requestor '"+session.getRequestorId() + "'");
                }
                catch (SQLException e)
                {                    
                    _logger.error("Could not execute update query: " + _sUpdateQuery, e);
                    throw new PersistenceException(SystemErrors.ERROR_RESOURCE_UPDATE);
                }
            }
        }
        catch (PersistenceException e)
        {
            throw e;
        }    
        catch (Exception e)
        {
            _logger.error("Internal error during persist of session with id: " + id, e);
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_UPDATE);
        }  
        finally
        {
            try
            {
                if (psInsert != null)
                    psInsert.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close insert statement", e);
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
                if (psUpdate != null)
                    psUpdate.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close update statement", e);
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
     * Uses a batch update to persist all supplied sessions.
     * @param sessions The sessions to persist.
     * @throws PersistenceException If persistance fails.
     * 
     * @see IEntityManager#persist(IEntity[])
     * @see PreparedStatement#addBatch()
     */
    public void persist(JDBCSession[] sessions) throws PersistenceException
    {
        if(sessions == null)
            throw new IllegalArgumentException(
                "Suplied session array is empty or invalid");  
        
        Connection connection = null;
        PreparedStatement psInsert = null;
        PreparedStatement psDelete = null;
        PreparedStatement psUpdate = null;
        try
        {
            connection = _oDataSource.getConnection(); //Manage connection
            connection.setAutoCommit(false);

            psInsert = connection.prepareStatement(_sInsertQuery);
            psDelete = connection.prepareStatement(_sRemoveQuery);
            psUpdate = connection.prepareStatement(_sUpdateQuery);            
                        
            for(JDBCSession session : sessions)
            {
                String id = session.getId();
                if(id == null) 
                {      
                    byte[] baId = new byte[ISession.ID_BYTE_LENGTH];     
                    do
                    {                
                        _random.nextBytes(baId);
                        try
                        {
                            id = ModifiedBase64.encode(baId);
                        }
                        catch (UnsupportedEncodingException e)
                        {
                            _logger.error("Could not create id for byte[]: " + baId, e);
                            throw new PersistenceException(SystemErrors.ERROR_INTERNAL);
                        }
                    }
                    while(exists(id)); //Key allready exists   
                    
                    session.setId(id);
                    //Update expiration time
                    long expiration = System.currentTimeMillis() + _lExpiration;
                    session.setTgtExpTime(expiration); 
                    psInsert.setString(1, id);
                    psInsert.setString(2, session.getTGTId());
                    psInsert.setInt(3, session.getState().ordinal());                   
                    psInsert.setString(4, session.getRequestorId());
                    psInsert.setString(5, session.getProfileURL());
                    psInsert.setBytes(6, Serialize.encode(session.getUser()));  
                    psInsert.setTimestamp(7, new Timestamp(expiration));
                    psInsert.setBoolean(8, session.isForcedAuthentication());
                    psInsert.setBoolean(9, session.isPassive());
                    psInsert.setBytes(10, Serialize.encode(session.getAttributes()));
                    psInsert.setString(11, session.getForcedUserID());
                    psInsert.setBytes(12, Serialize.encode(session.getLocale()));
                    psInsert.setBytes(13, Serialize.encode(session.getSelectedAuthNProfile()));
                    psInsert.setBytes(14, Serialize.encode(session.getAuthNProfiles()));
                    psInsert.addBatch();      
                }
                else if(session.isExpired()) //Expired
                {                   
                    _logger.info("Session Expired: " + id);   
                    
                    _eventLogger.info(new UserEventLogItem(session, null, 
                        UserEvent.SESSION_EXPIRED, this, null));
                    
                    psDelete.setString(1, id);           
                    psDelete.addBatch();                                    
                }    
                else //Update
                {
                    //Update expiration time
                    long expiration = System.currentTimeMillis() + _lExpiration;                       
                    session.setTgtExpTime(expiration);
                    psUpdate.setString(1, session.getTGTId());
                    psUpdate.setInt(2, session.getState().ordinal());                   
                    psUpdate.setString(3, session.getRequestorId());
                    psUpdate.setString(4, session.getProfileURL());
                    psUpdate.setBytes(5, Serialize.encode(session.getUser()));                                    
                    psUpdate.setTimestamp(6, new Timestamp(expiration));
                    psUpdate.setBoolean(7, session.isForcedAuthentication());
                    psInsert.setBoolean(8, session.isPassive());
                    psUpdate.setBytes(9, Serialize.encode(session.getAttributes()));
                    psUpdate.setString(10, session.getForcedUserID());
                    psUpdate.setBytes(11, Serialize.encode(session.getLocale()));
                    psUpdate.setBytes(12, Serialize.encode(session.getSelectedAuthNProfile()));
                    psUpdate.setBytes(13, Serialize.encode(session.getAuthNProfiles()));
                    psUpdate.setString(14, id);
                    psUpdate.addBatch();        
                } 
            }
            try
            {
                int[] iResult = psInsert.executeBatch();
                if (_logger.isDebugEnabled())
                {
                    int iTotalAdded = 0;
                    for(int i : iResult)
                        iTotalAdded += i;
                    
                    _logger.info(iTotalAdded + " new session(s) added by batch");
                }
            }
            catch (SQLException e)
            {
                _logger.error("Could not execute insert batch", e);          
                throw new PersistenceException(SystemErrors.ERROR_RESOURCE_INSERT);
            } 
            try
            {
                int[] iResult = psDelete.executeBatch();
                if (_logger.isDebugEnabled())
                {
                    int iTotalDeleted = 0;
                    for(int i : iResult)
                        iTotalDeleted += i;
                    
                    _logger.info(iTotalDeleted + " session(s) deleted by batch");
                }
                
            }
            catch (SQLException e)
            {
                _logger.error("Could not execute delete batch", e);          
                throw new PersistenceException(SystemErrors.ERROR_RESOURCE_REMOVE);
            } 
            try
            {
                int[] iResult = psUpdate.executeBatch();
                if (_logger.isDebugEnabled())
                {
                    int iTotalUpdated = 0;
                    for(int i : iResult)
                        iTotalUpdated += i;

                    _logger.info(iTotalUpdated + " session(s) updated by batch");
                }
            }
            catch (SQLException e)
            {
                _logger.error("Could not execute update batch", e);          
                throw new PersistenceException(SystemErrors.ERROR_RESOURCE_UPDATE);
            } 
            
            connection.commit(); 
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute batch", e); 
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
            _logger.error("Internal error during session persist", e);
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
     * Remove all expired sessions.
     * 
     * e.g. <code>DELETE FROM session WHERE expiration <= NOW()</code>
     * @see ICleanable#removeExpired()
     */
    public void removeExpired() throws PersistenceException
    {
        //DD does not log a user event when session is expired, because this will cost an unnecesary select (eventlogging should be done with DB trigger)
        Connection oConnection = null;
        PreparedStatement ps = null;
        try
        {
            oConnection = _oDataSource.getConnection();
            ps = oConnection.prepareStatement(_sRemoveExpiredQuery);
            ps.setTimestamp(1, new Timestamp(System.currentTimeMillis()));           
            int i = ps.executeUpdate();
            if(i > 0)
                _logger.info(i + " session(s) expired");
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute delete expired", e);          
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_REMOVE);
        }
        catch (Exception e)
        {
            _logger.error("Internal error while delete expired sessions", e);          
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
    
    /**
     * @see com.alfaariss.oa.api.poll.IPollable#poll()
     */
    public long poll() throws OAException
    {
        return getSessionCount();
    }
    
    /**
     * @see com.alfaariss.oa.api.logging.IAuthority#getAuthority()
     * @since 1.3
     */
    public String getAuthority()
    {
        return ISessionFactory.AUTHORITY_NAME;
    }

    /*
     * Read the entity storage configuration. 
     * 
     * If no configuration section is present the default queries are used.
     */
     private void createQueries(
         Element eConfig) throws SessionException, ConfigurationException
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
             _sColumnTGT_ID = getColumnName(eEntity, "tgtId");
             _sColumnSTATE = getColumnName(eEntity, "state");  
             _sColumnREQUESTOR = getColumnName(eEntity, "requestorId");
             _sColumnURL = getColumnName(eEntity, "profileURL");
             _sColumnEXPIRATION = getColumnName(eEntity, "expTime");
             _sColumnFORCED_AUTHENTICATE = getColumnName(eEntity, "forcedAuthentication");
             _sColumnOWNER = getColumnName(eEntity, "user");
             _sColumnATTRIBUTES = getColumnName(eEntity, "attributes");
             _sColumnFORCED_USERID = getColumnName(eEntity, "forcedUserId");
             _sColumnLOCALE = getColumnName(eEntity, "locale");
             _sColumnSELECTED_AUTHN_PROFILE = getColumnName(eEntity, "selectedAuthNProfile");
             _sColumnAUTHN_PROFILES = getColumnName(eEntity, "authenticationProfiles");
             _sColumnPASSIVE = getColumnName(eEntity, "passive");
         }
         
         if(_sTableName == null)
             _sTableName = TABLE_NAME;
         
         if (_sColumnID == null)
             _sColumnID = COLUMN_ID;    
          
         if (_sColumnTGT_ID == null)
             _sColumnTGT_ID = COLUMN_TGT_ID;
          
         if (_sColumnSTATE == null)
             _sColumnSTATE = COLUMN_STATE;   
         
         if (_sColumnREQUESTOR == null)
             _sColumnREQUESTOR = COLUMN_REQUESTOR;  
         
         if (_sColumnURL == null)
             _sColumnURL = COLUMN_URL; 
         
         if (_sColumnEXPIRATION == null)
             _sColumnEXPIRATION = COLUMN_EXPIRATION;  
         
         if (_sColumnFORCED_AUTHENTICATE == null)
             _sColumnFORCED_AUTHENTICATE = COLUMN_FORCED_AUTHENTICATE;   
         
         if (_sColumnPASSIVE == null)
             _sColumnPASSIVE = COLUMN_PASSIVE;
         
         if (_sColumnOWNER == null)
             _sColumnOWNER = COLUMN_OWNER;  
         
         if (_sColumnATTRIBUTES == null)
             _sColumnATTRIBUTES = COLUMN_ATTRIBUTES;  
         
         if (_sColumnFORCED_USERID == null)
             _sColumnFORCED_USERID = COLUMN_FORCED_USERID;  
         
         if (_sColumnLOCALE == null)
             _sColumnLOCALE = COLUMN_LOCALE;
         
         if (_sColumnSELECTED_AUTHN_PROFILE == null)
             _sColumnSELECTED_AUTHN_PROFILE = COLUMN_SELECTED_AUTHN_PROFILE;
         
         if (_sColumnAUTHN_PROFILES == null)
             _sColumnAUTHN_PROFILES = COLUMN_AUTHN_PROFILES;
           
         //SearchQuery
         StringBuffer sb = new StringBuffer("SELECT ");
         sb.append(_sColumnTGT_ID).append(", ");
         sb.append(_sColumnSTATE).append(", ");
         sb.append(_sColumnREQUESTOR).append(", ");
         sb.append(_sColumnURL).append(", ");
         sb.append(_sColumnOWNER).append(", ");
         sb.append(_sColumnEXPIRATION).append(", ");
         sb.append(_sColumnFORCED_AUTHENTICATE).append(", ");
         sb.append(_sColumnPASSIVE).append(", ");
         sb.append(_sColumnATTRIBUTES).append(", ");
         sb.append(_sColumnFORCED_USERID).append(", ");
         sb.append(_sColumnLOCALE).append(", ");
         sb.append(_sColumnSELECTED_AUTHN_PROFILE).append(", ");
         sb.append(_sColumnAUTHN_PROFILES);
         sb.append(" FROM ").append(_sTableName);
         sb.append(" WHERE ").append(_sColumnID).append("=?");
         _sSearchQuery = sb.toString();
         _logger.debug("Using SearchQuery: " + _sSearchQuery);
         
         //CountQuery 
         sb = new StringBuffer("SELECT COUNT(");
         sb.append(_sColumnID).append(") FROM ").append(_sTableName);
         _sCountQuery = sb.toString();
         _logger.debug("Using CountQuery: " + _sCountQuery);

         //InsertQuery
         sb = new StringBuffer("INSERT INTO ");
         sb.append(_sTableName).append("(");
         sb.append(_sColumnID).append(",");
         sb.append(_sColumnTGT_ID).append(",");
         sb.append(_sColumnSTATE).append(",");
         sb.append(_sColumnREQUESTOR).append(",");
         sb.append(_sColumnURL).append(",");
         sb.append(_sColumnOWNER).append(",");
         sb.append(_sColumnEXPIRATION).append(",");
         sb.append(_sColumnFORCED_AUTHENTICATE).append(",");
         sb.append(_sColumnPASSIVE).append(",");
         sb.append(_sColumnATTRIBUTES).append(",");
         sb.append(_sColumnFORCED_USERID).append(",");
         sb.append(_sColumnLOCALE).append(",");
         sb.append(_sColumnSELECTED_AUTHN_PROFILE).append(",");
         sb.append(_sColumnAUTHN_PROFILES);
         sb.append(") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)");             
         _sInsertQuery = sb.toString();
         _logger.debug("Using InsertQuery: " + _sInsertQuery);
         
         //UpdateQuery
         sb = new StringBuffer("UPDATE ");
         sb.append(_sTableName).append(" SET ");
         sb.append(_sColumnTGT_ID).append("=?, ");
         sb.append(_sColumnSTATE).append("=?, ");
         sb.append(_sColumnREQUESTOR).append("=?, ");
         sb.append(_sColumnURL).append("=?, ");
         sb.append(_sColumnOWNER).append("=?, ");
         sb.append(_sColumnEXPIRATION).append("=?, ");
         sb.append(_sColumnFORCED_AUTHENTICATE).append("=?, ");
         sb.append(_sColumnPASSIVE).append("=?, ");
         sb.append(_sColumnATTRIBUTES).append("=?, ");
         sb.append(_sColumnFORCED_USERID).append("=?, ");
         sb.append(_sColumnLOCALE).append("=?, ");
         sb.append(_sColumnSELECTED_AUTHN_PROFILE).append("=?, ");
         sb.append(_sColumnAUTHN_PROFILES).append("=? WHERE  ");
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
                     sbVerificationQuery.append(_sColumnTGT_ID).append(",");
                     sbVerificationQuery.append(_sColumnSTATE).append(",");
                     sbVerificationQuery.append(_sColumnREQUESTOR).append(",");
                     sbVerificationQuery.append(_sColumnURL).append(",");
                     sbVerificationQuery.append(_sColumnEXPIRATION).append(",");
                     sbVerificationQuery.append(_sColumnFORCED_AUTHENTICATE).append(",");
                     sbVerificationQuery.append(_sColumnPASSIVE).append(",");
                     sbVerificationQuery.append(_sColumnOWNER).append(",");
                     sbVerificationQuery.append(_sColumnATTRIBUTES).append(",");
                     sbVerificationQuery.append(_sColumnFORCED_USERID).append(",");
                     sbVerificationQuery.append(_sColumnLOCALE).append(",");
                     sbVerificationQuery.append(_sColumnSELECTED_AUTHN_PROFILE).append(",");
                     sbVerificationQuery.append(_sColumnAUTHN_PROFILES);
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
  
              //Verify the table             
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
     private String getIdColumnName(
         Element eConfig) throws SessionException, ConfigurationException
     {
         String sIdColumn = null;
         if (eConfig != null)
         {
             Element eIdColumn = _configurationManager.getSection(eConfig, "id");
             if(eIdColumn == null)
                 _logger.error("No optional 'id' section found");
             else
             {
                 sIdColumn = _configurationManager.getParam(eIdColumn, "column"); 
                 if(sIdColumn == null)
                 {
                     _logger.error("Could not find column name for id");
                     throw new SessionException(SystemErrors.ERROR_CONFIG_READ);
                 }
             }
         }
         return sIdColumn;
     }

     //Retrieve property column name
     private String getColumnName(Element eConfig, 
         String sName) throws SessionException, ConfigurationException
     {
         String sColumn = null;
         if (eConfig != null || sName != null)
         {
             Element eColumn = _configurationManager.getSection(
                 eConfig, "property", "name=" + sName);
             if(eColumn == null)
                 _logger.warn("No optional 'property' section found for property with name: " + sName);
             else
             {
                 sColumn = _configurationManager.getParam(eColumn, "column"); 
                 if(sColumn == null)
                 {
                     _logger.error("Could not find column name for property " + sName);
                     throw new SessionException(SystemErrors.ERROR_CONFIG_READ);
                 }
             }
         }
         return sColumn;
     }

    //Retrieve the current number of sessions
    private int getSessionCount() throws SessionException
    {
        Connection oConnection = null;
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
            throw new SessionException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (Exception e)
        {
            _logger.error("Internal error during session count retrieval", e);
            throw new SessionException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
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
}