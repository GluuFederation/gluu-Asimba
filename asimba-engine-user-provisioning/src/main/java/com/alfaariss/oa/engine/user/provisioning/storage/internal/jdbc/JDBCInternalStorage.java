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
package com.alfaariss.oa.engine.user.provisioning.storage.internal.jdbc;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Set;
import java.util.Vector;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.engine.user.provisioning.ProvisioningUser;
import com.alfaariss.oa.engine.user.provisioning.storage.IStorage;
import com.alfaariss.oa.engine.user.provisioning.storage.internal.IInternalStorage;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;

/**
 * JDBC internal storage object.
 * <br>
 * Uses the configured JDBC storage as internal storage.
 * @author MHO
 * @author Alfa & Ariss
 * 
 * DD All queries use uppercase() in comparing user id's to make user id's case insensitive in the internal database
 */
public class JDBCInternalStorage implements IInternalStorage 
{
    private final static String TABLE_ACCOUNT = "account";
    private final static String COLUMN_ACCOUNT_ID = "id";
    private final static String COLUMN_ACCOUNT_ENABLED = "enabled";
    
    private final static String TABLE_PROFILE = "accountprofile";
    private final static String COLUMN_PROFILE_ID = "id";
    private final static String COLUMN_PROFILE_AUTHSPID = "method_id";
    private final static String COLUMN_PROFILE_REGISTERED = "registered";
       
    private Log _logger;
    private DataSource _oDataSource;
    
    private String _sTableAccount;
    private String _sTableProfile;
    private String _sAccountExistsSelect;
    private String _sAccountEnabledSelect;
    private String _sAccountInsert;
    private String _sAccountDelete;
    private String _sProfileRegisteredSelect;
    private String _sProfileSelect;
    private String _sProfileInsert;
    private String _sProfileDelete;
    
	/**
     * Creates the object.
	 */
	public JDBCInternalStorage()
    {
        _logger = LogFactory.getLog(JDBCInternalStorage.class);
	}

    /**
     * Starts the object.
     * <br>
     * Reads the configuration and checks the connection.
     * @see IStorage#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws UserException
    {
	    try
        {
            Element eResource = oConfigurationManager.getSection(
                eConfig, "resource");
            if (eResource == null)
            {
                _logger.error(
                    "No 'resource' section found in 'internalstorage' section");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _oDataSource = DataSourceFactory.createDataSource(
                oConfigurationManager, eResource);
            
            Element eAccount = oConfigurationManager.getSection(eResource, "account");
            if (eAccount == null)
            {
                _sTableAccount = TABLE_ACCOUNT;
                _logger.warn("No 'account' section found in configuration, using default table: " + _sTableAccount);
            }
            else
            {
                _sTableAccount = oConfigurationManager.getParam(eAccount, "table");
                if (_sTableAccount == null)
                {
                    _sTableAccount = TABLE_ACCOUNT;
                    _logger.warn("No 'table' item in 'account' section found in configuration, using default: " + _sTableAccount);
                }
            }
            
            Element eProfile = oConfigurationManager.getSection(eResource, "profile");
            if (eProfile == null)
            {
                _sTableProfile = TABLE_PROFILE;
                _logger.warn("No 'profile' section found in configuration, using default table: " + _sTableProfile);
            }
            else
            {
                _sTableProfile = oConfigurationManager.getParam(eProfile, "table");
                if (_sTableProfile == null)
                {
                    _sTableProfile = TABLE_PROFILE;
                    _logger.warn("No 'table' item in 'profile' section found in configuration, using default: " + _sTableProfile);
                }
            }
                        
            StringBuffer sbAccountExistsQuery = new StringBuffer("SELECT ");
            sbAccountExistsQuery.append(COLUMN_ACCOUNT_ID).append(" FROM ");
            sbAccountExistsQuery.append(_sTableAccount);
            sbAccountExistsQuery.append(" WHERE UPPER(");
            sbAccountExistsQuery.append(COLUMN_ACCOUNT_ID);
            sbAccountExistsQuery.append(")=UPPER(?)");
            _sAccountExistsSelect = sbAccountExistsQuery.toString();
            
            StringBuffer sbAccountEnabledQuery = new StringBuffer("SELECT ");
            sbAccountEnabledQuery.append(COLUMN_ACCOUNT_ENABLED);
            sbAccountEnabledQuery.append(" FROM ");
            sbAccountEnabledQuery.append(_sTableAccount);
            sbAccountEnabledQuery.append(" WHERE UPPER(");
            sbAccountEnabledQuery.append(COLUMN_ACCOUNT_ID);
            sbAccountEnabledQuery.append(")=UPPER(?)");
            _sAccountEnabledSelect = sbAccountEnabledQuery.toString();
            
            StringBuffer sbProfileRegisteredQuery = new StringBuffer("SELECT ");
            sbProfileRegisteredQuery.append(COLUMN_PROFILE_AUTHSPID);
            sbProfileRegisteredQuery.append(",");
            sbProfileRegisteredQuery.append(COLUMN_PROFILE_REGISTERED);
            sbProfileRegisteredQuery.append(" FROM ");
            sbProfileRegisteredQuery.append(_sTableProfile);
            sbProfileRegisteredQuery.append(" WHERE UPPER(");
            sbProfileRegisteredQuery.append(COLUMN_PROFILE_ID);
            sbProfileRegisteredQuery.append(")=UPPER(?)");
            _sProfileRegisteredSelect = sbProfileRegisteredQuery.toString();
                        
            StringBuffer sbAccountInsertQuery = new StringBuffer("INSERT INTO ");
            sbAccountInsertQuery.append(_sTableAccount);
            sbAccountInsertQuery.append(" (");
            sbAccountInsertQuery.append(COLUMN_ACCOUNT_ID);
            sbAccountInsertQuery.append(",");
            sbAccountInsertQuery.append(COLUMN_ACCOUNT_ENABLED);
            sbAccountInsertQuery.append(") VALUES (?,?)");
            _sAccountInsert = sbAccountInsertQuery.toString();
            
            StringBuffer sbProfileInsertQuery = new StringBuffer("INSERT INTO ");
            sbProfileInsertQuery.append(_sTableProfile);
            sbProfileInsertQuery.append(" (");
            sbProfileInsertQuery.append(COLUMN_PROFILE_ID);
            sbProfileInsertQuery.append(",");
            sbProfileInsertQuery.append(COLUMN_PROFILE_AUTHSPID);
            sbProfileInsertQuery.append(",");
            sbProfileInsertQuery.append(COLUMN_PROFILE_REGISTERED);
            sbProfileInsertQuery.append(") VALUES (?,?,?)");
            _sProfileInsert = sbProfileInsertQuery.toString();
            
            StringBuffer sbProfileSelectQuery = new StringBuffer("SELECT ");
            sbProfileSelectQuery.append(COLUMN_PROFILE_ID);
            sbProfileSelectQuery.append(",");
            sbProfileSelectQuery.append(COLUMN_PROFILE_AUTHSPID);
            sbProfileSelectQuery.append(" FROM ");
            sbProfileSelectQuery.append(_sTableProfile);
            sbProfileSelectQuery.append(" WHERE UPPER(");
            sbProfileSelectQuery.append(COLUMN_PROFILE_ID);
            sbProfileSelectQuery.append(")=UPPER(?)");
            _sProfileSelect = sbProfileSelectQuery.toString();
            
            StringBuffer sbAccountDeleteQuery = new StringBuffer("DELETE FROM ");
            sbAccountDeleteQuery.append(_sTableAccount);
            sbAccountDeleteQuery.append(" WHERE UPPER(");
            sbAccountDeleteQuery.append(COLUMN_ACCOUNT_ID);
            sbAccountDeleteQuery.append(")=UPPER(?)");
            _sAccountDelete = sbAccountDeleteQuery.toString();
            
            StringBuffer sbProfileDeleteQuery = new StringBuffer("DELETE FROM ");
            sbProfileDeleteQuery.append(_sTableProfile);
            sbProfileDeleteQuery.append(" WHERE UPPER(");
            sbProfileDeleteQuery.append(COLUMN_PROFILE_ID);
            sbProfileDeleteQuery.append(")=UPPER(?)");
            _sProfileDelete = sbProfileDeleteQuery.toString();
            
        }
        catch (UserException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not initialize object", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
	}
    
    /**
     * Verifies whether the supplied id exists in the internal storage.
     * <br>
     * Returns <code>true</code> if the id exists in the account table of 
     *  the internal storage.
     * @see IStorage#exists(java.lang.String)
     */
    public boolean exists(String id) throws UserException
    {
        boolean bReturn = false;
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        
        try
        {
            oConnection = _oDataSource.getConnection();
            oPreparedStatement = oConnection.prepareStatement(
                _sAccountExistsSelect);
            oPreparedStatement.setString(1, id);
            oResultSet = oPreparedStatement.executeQuery();
            if (oResultSet.next())
                bReturn = true;
        }
        catch (SQLException e)
        {
            _logger.error("Could not verify account exists for user with id: " 
                + id, e);
            throw new UserException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (Exception e)
        {
            _logger.error("Could not run query: " + _sAccountExistsSelect, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (oResultSet != null)
                    oResultSet.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close resultset", e);
            }
            
            try
            {
                if (oPreparedStatement != null)
                    oPreparedStatement.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close statement", e);
            }
            
            try
            {
                if (oConnection != null)
                    oConnection.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close connection", e);
            }
        }
        
        return bReturn;
    }

    /**
     * Returns the user object specified by the supplied id.
     * @see IInternalStorage#getUser(java.lang.String, java.lang.String)
     */
    public ProvisioningUser getUser(
        String sOrganization, String id) throws UserException
    {
        ProvisioningUser oProvisioningUser = null;
        try
        {
            Boolean boolEnabled = isAccountEnabled(id);
            if (boolEnabled == null)
                return null;
            
            oProvisioningUser = new ProvisioningUser(
                sOrganization, id, boolEnabled);
            
            Hashtable<String, Boolean> htRegistered = getRegistered(id);
            Enumeration enumAuthSPIDs = htRegistered.keys();
            while (enumAuthSPIDs.hasMoreElements())
            {
                String sID = (String)enumAuthSPIDs.nextElement();
                oProvisioningUser.putRegistered(sID, htRegistered.get(sID));
            }
        }
        catch (UserException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not get user with id: " + id, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        return oProvisioningUser;
    }

    /**
     * Adds the supplied user to the internal storage.
     * @see IInternalStorage#add(ProvisioningUser)
     */
    public void add(ProvisioningUser user) throws UserException
    {
        Connection oConnection = null;
        try
        {
            oConnection = _oDataSource.getConnection();
            oConnection.setAutoCommit(false);
            
            insertAccount(oConnection, user);
            
            Set<String> setMethods = user.getAuthenticationMethods();
            for (String sMethod: setMethods)
                insertProfile(oConnection, user, sMethod);
            
            oConnection.commit();
        }
        catch (UserException e)
        {
            rollback(oConnection);
            throw e;
        }
        catch(Exception e)
        {
            rollback(oConnection);
            _logger.fatal("Could not store", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (oConnection != null)
                    oConnection.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close connection", e);
            }
        }
    }
    
    /**
     * Updates the user in the internal storage 
     * @see IInternalStorage#update(ProvisioningUser)
     */
    public void update(ProvisioningUser user) throws UserException
    {
        Connection oConnection = null;
        try
        {
            oConnection = _oDataSource.getConnection();
            oConnection.setAutoCommit(false);
            
            updateProfile(oConnection, user);
            
            oConnection.commit();
        }
        catch (UserException e)
        {
            rollback(oConnection);
            throw e;
        }
        catch(Exception e)
        {
            rollback(oConnection);
            _logger.fatal("Could not update user", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (oConnection != null)
                    oConnection.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close connection", e);
            }
        }
    }
       
    /**
     * Removes a user with the supplied id.
     * @see com.alfaariss.oa.engine.user.provisioning.storage.internal.IInternalStorage#remove(java.lang.String)
     */
    public void remove(String id) throws UserException
    {
        Connection oConnection = null;
        try
        {
            oConnection = _oDataSource.getConnection();
            oConnection.setAutoCommit(false);
            
            remove(oConnection, id);
            
            oConnection.commit();
        }
        catch (UserException e)
        {
            rollback(oConnection);
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not store user with id: " + id, e);
            rollback(oConnection);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (oConnection != null)
                    oConnection.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close connection", e);
            }
        }
    }

    /**
     * Does nothing.
     * @see com.alfaariss.oa.engine.user.provisioning.storage.IStorage#stop()
     */
    public void stop()
    {
        //do nothing yet
    }
    
    /**
     * Returns a boolean object with the value of the account enabled field.
     * @param id the user id
     * @return TRUE if account enabled or null if no account found
     * @throws UserException if retrieval failed
     */
    private Boolean isAccountEnabled(String id) throws UserException
    {
        Boolean boolReturn = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        Connection oConnection = null;
        try
        {
            oConnection = _oDataSource.getConnection();
            oPreparedStatement = oConnection.prepareStatement(
                _sAccountEnabledSelect);
            oPreparedStatement.setString(1, id);
            oResultSet = oPreparedStatement.executeQuery();
            if (!oResultSet.next())
                return null; // user unknown
            
            boolReturn = oResultSet.getBoolean(COLUMN_ACCOUNT_ENABLED);
        }
        catch (SQLException e)
        {
            _logger.error(
                "Could not retrieve account enabled for user with id: " 
                + id, e);
            throw new UserException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (Exception e)
        {
            _logger.error(
                "Could not retrieve account information for account with id: " 
                + id, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (oResultSet != null)
                    oResultSet.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close resultset", e);
            }
            
            try
            {
                if (oPreparedStatement != null)
                    oPreparedStatement.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close statement", e);
            }
            
            try
            {
                if (oConnection != null)
                    oConnection.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close connection", e);
            }
        }
        
        return boolReturn;
    }
    
    /**
     * Retrieve the registered fields for all methods in the user profile.
     * @param sUserId the user id
     * @return a <code>Hashtable</code> with method id (key) and registered 
     * <code>Boolean</code> (value)
     * @throws UserException if selection fails
     */
    private Hashtable<String, Boolean> getRegistered(
        String sUserId) throws UserException
    {
        Hashtable<String, Boolean> htRegistered = new Hashtable<String, Boolean>();
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        Connection oConnection = null;
        try
        {
            oConnection = _oDataSource.getConnection();
            oPreparedStatement = oConnection.prepareStatement(
                _sProfileRegisteredSelect);
            oPreparedStatement.setString(1, sUserId);
            oResultSet = oPreparedStatement.executeQuery();
            while (oResultSet.next())
            {
                String sID = oResultSet.getString(COLUMN_PROFILE_AUTHSPID);
                boolean bRegistered = oResultSet.getBoolean(
                    COLUMN_PROFILE_REGISTERED);
                
                htRegistered.put(sID, bRegistered);
            }
        }
        catch (SQLException e)
        {
            _logger.error(
                "Could not retrieve profile registered for user with id: " 
                + sUserId, e);
            throw new UserException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (Exception e)
        {
            _logger.error(
                "Could not retrieve profile for user with id: " 
                + sUserId, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (oResultSet != null)
                    oResultSet.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close resultset", e);
            }
            
            try
            {
                if (oPreparedStatement != null)
                    oPreparedStatement.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close statement", e);
            }
            
            try
            {
                if (oConnection != null)
                    oConnection.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close connection", e);
            }
        }
        
        return htRegistered;
    }    


    /**
     * Insert the supplied user in the account table.
     * @param oConnection the connection
     * @param user the user that must be inserted
     * @throws UserException if insertion fails
     */
    private void insertAccount(Connection oConnection, ProvisioningUser user) 
        throws UserException
    {
        PreparedStatement oPreparedStatement = null;
        try
        {
            oPreparedStatement = oConnection.prepareStatement(_sAccountInsert);
            oPreparedStatement.setString(1, user.getID());
            oPreparedStatement.setBoolean(2, user.isEnabled());
            
            if (oPreparedStatement.executeUpdate() != 1)
            {
                _logger.error("Could not insert account for user with id: " 
                    + user.getID());
                throw new UserException(SystemErrors.ERROR_RESOURCE_INSERT);
            }
        }
        catch (UserException e)
        {
            throw e;
        }
        catch (SQLException e)
        {
            _logger.error("Could not insert account for user with id: " 
                + user.getID(), e);
            throw new UserException(SystemErrors.ERROR_RESOURCE_INSERT);
        }
        catch(Exception e)
        {
            _logger.fatal("Could not insert account", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (oPreparedStatement != null)
                    oPreparedStatement.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close statement", e);
            }
        }
    }     
    
    /**
     * Insert the supplied user profile in the profile table.
     * @param oConnection the connection
     * @param user the user that must be inserted
     * @throws UserException if insertion fails
     */
    private void insertProfile(Connection oConnection, ProvisioningUser user, 
        String sMethod) throws UserException 
    {
        PreparedStatement oPreparedStatement = null;
        try
        {
            oPreparedStatement = oConnection.prepareStatement(_sProfileInsert);
            oPreparedStatement.setString(1, user.getID());
            oPreparedStatement.setString(2, sMethod);
            oPreparedStatement.setBoolean(3, user.isAuthenticationRegistered(sMethod));
            
            if (oPreparedStatement.executeUpdate() != 1)
            {
                StringBuffer sbError = new StringBuffer("Could not insert profile (");
                sbError.append(sMethod);
                sbError.append(") for user with id: ");
                sbError.append(user.getID());
                _logger.error(sbError.toString());
                throw new UserException(SystemErrors.ERROR_RESOURCE_INSERT);
            }
        }
        catch(UserException e)
        {
            throw e;
        }
        catch(SQLException e)
        {
            StringBuffer sbError = new StringBuffer("Could not insert profile for user with id '");
            sbError.append(user.getID());
            sbError.append("'; authentication method '");
            sbError.append(sMethod);
            sbError.append("'; registered: ");
            sbError.append(user.isAuthenticationRegistered(sMethod));
            _logger.error(sbError.toString(), e);
            throw new UserException(SystemErrors.ERROR_RESOURCE_INSERT);
        }
        catch(Exception e)
        {
            _logger.fatal("Could not insert profile", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (oPreparedStatement != null)
                    oPreparedStatement.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close statement", e);
            }
        }
    }      
    
    /**
     * Update the supplied user profile in the profile table.
     * @param oConnection the connection
     * @param user the user that must be updated
     * @throws UserException if update fails
     */
    private void updateProfile(Connection oConnection, ProvisioningUser user) 
        throws UserException
    {
        ResultSet oResultSet = null;
        PreparedStatement psRetrieve = null;
        PreparedStatement psInsert = null;
        
        try
        {
            Vector<String> vExistingMethodIDs = new Vector<String>();
            psRetrieve = oConnection.prepareStatement(_sProfileSelect);
            psRetrieve.setString(1, user.getID());
            oResultSet = psRetrieve.executeQuery();
            
            String sUserID = user.getID();
            while (oResultSet.next())
            {
                sUserID = oResultSet.getString(COLUMN_PROFILE_ID);
                String sMethodID = oResultSet.getString(COLUMN_PROFILE_AUTHSPID);
                vExistingMethodIDs.add(sMethodID);
            }
            
            psInsert = oConnection.prepareStatement(_sProfileInsert);
            psInsert.setString(1, sUserID);
            for (String sMethod: user.getAuthenticationMethods())
            {
                if (!vExistingMethodIDs.contains(sMethod))
                {
                    psInsert.setString(2, sMethod);
                    psInsert.setBoolean(3, user.isAuthenticationRegistered(sMethod));
                    psInsert.addBatch();
                }
            }
            int[] iInserts = psInsert.executeBatch();
           
            _logger.debug("Total number of update queries performed in batch: " 
                + iInserts.length);
        }
        catch (SQLException e)
        {
            _logger.error("Could not update profile for user with id: " + user.getID(), e);
            throw new UserException(SystemErrors.ERROR_RESOURCE_UPDATE);
        }        
        catch (Exception e)
        {
            _logger.fatal("Could not update profile", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (psRetrieve != null)
                    psRetrieve.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close retrieve statement", e);
            }
            try
            {
                if (psInsert != null)
                    psInsert.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close insert statement", e);
            }
        }
    }
    
    /**
     * Removes a user from the account table and profile table. 
     * @param oConnection the database connection
     * @param id the user id
     * @throws UserException if removal fails
     */
    private void remove(Connection oConnection, String id) throws UserException
    {
        PreparedStatement psAccount = null;
        PreparedStatement psProfile = null;
        try
        {
            psAccount = oConnection.prepareStatement(_sAccountDelete);
            psAccount.setString(1, id);
            psAccount.executeUpdate();
            
            psProfile = oConnection.prepareStatement(_sProfileDelete);
            psProfile.setString(1, id);
            psProfile.executeUpdate();
        }
        catch(SQLException e)
        {
            _logger.error(
                "Could not remove account for user with id: " + id, e);
            throw new UserException(SystemErrors.ERROR_RESOURCE_REMOVE);
        }
        catch(Exception e)
        {
            _logger.fatal("Could not store", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (psAccount != null)
                    psAccount.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close account statement", e);
            }
            
            try
            {
                if (psProfile != null)
                    psProfile.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close profile statement", e);
            }
        }
    }
       
    //rollback the connection
    private void rollback(Connection oConnection)
    {
        if (oConnection != null)
        {
            try
            {
                oConnection.rollback();
            }
            catch (Exception e)
            {
                _logger.error("Could not rollback", e);
            }
        }
    }

}