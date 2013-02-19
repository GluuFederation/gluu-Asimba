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
package com.alfaariss.oa.engine.requestor.jdbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.engine.core.requestor.RequestorException;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;

/**
 * Creates the requestor pool from a JDBC resource.
 * <br>
 * This requestor pool is read at runtime from a database table, 
 * specified by the resource configuration.               
 * 
 * @author MHO
 * @author Alfa & Ariss
 */
public class JDBCRequestorPool extends RequestorPool
{
    /** id */
    public static final String COLUMN_ID = "id";
    /** friendlyname */
    public static final String COLUMN_FRIENDLYNAME = "friendlyname";
    /** enabled */
    public static final String COLUMN_ENABLED = "enabled";
    /** preauthorization */
    public static final String COLUMN_PREAUTHORIZATION = "preauthz_profile_id";
    /** postauthorization */
    public static final String COLUMN_POSTAUTHORIZATIE = "postauthz_profile_id";
    /** forced */
    public static final String COLUMN_FORCED = "forced";
    /** releasepolicy */
    public static final String COLUMN_RELEASEPOLICY = "releasepolicy";
    
    /** id */
    public static final String COLUMN_AUTHENTICATION_ID = "authn_profile_id";
    /** pool_id */
    public static final String COLUMN_AUTHENTICATION_POOLID = "pool_id";
    
    /** Requestorpool ID */
    public static final String COLUMN_PROPERTY_POOL_ID = "pool_id";
    /** Requestorpool property Name */
    public static final String COLUMN_PROPERTY_NAME = "name";
    /** Requestorpool property Value */
    public static final String COLUMN_PROPERTY_VALUE = "value";
    
    /** Order by id column */
    public static final String COLUMN_ORDER_ID = "order_id";
    
    private static Log _logger;
    
    /**
     * Creates the object by reading information from JDBC.
     * <br>
     * @param oDataSource JDBC resource
     * @param oResultSet containing a row from the pool table
     * @param sPoolsTable the pool table name
     * @param sRequestorsTable the requestors table name
     * @param sRequestorPropertiesTable the requestor properties table name
     * @param sAuthenticationTable the authentication table name
     * @param sPoolPropertiesTable the requestor pool properties table name
     * @throws RequestorException when creation fails
     */
    public JDBCRequestorPool(ResultSet oResultSet, 
        DataSource oDataSource, 
        String sPoolsTable, 
        String sRequestorsTable, 
        String sRequestorPropertiesTable, 
        String sAuthenticationTable,
        String sPoolPropertiesTable) throws RequestorException
    {
        try
        {
            _logger = LogFactory.getLog(JDBCRequestorPool.class);
            
            _sID = oResultSet.getString(COLUMN_ID);
            _sFriendlyName = oResultSet.getString(COLUMN_FRIENDLYNAME);
            if (_sFriendlyName == null)
            {
                StringBuffer sbWarn = new StringBuffer("No '");
                sbWarn.append(COLUMN_FRIENDLYNAME);
                sbWarn.append("' available for requestorpool with id: ");
                sbWarn.append(_sID);
                _logger.error(sbWarn.toString());
                throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }
            
            _bEnabled = oResultSet.getBoolean(COLUMN_ENABLED);
            _bForced = oResultSet.getBoolean(COLUMN_FORCED);
            _sAttributeReleasePolicyID = oResultSet.getString(COLUMN_RELEASEPOLICY);
            _sPreAuthorizationProfileID = oResultSet.getString(COLUMN_PREAUTHORIZATION);
            _sPostAuthorizationProfileID = oResultSet.getString(COLUMN_POSTAUTHORIZATIE);
            
            addAuthenticationProfiles(oDataSource, sAuthenticationTable);
            
            addRequestors(oDataSource, sPoolsTable, sRequestorsTable, 
                sRequestorPropertiesTable);
            
            addProperties(oDataSource, sPoolPropertiesTable);
        }
        catch (SQLException e)
        {
            _logger.error("Can not read pool from database", e);
            throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (RequestorException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during pool object creation", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private void addAuthenticationProfiles(DataSource oDataSource, 
        String sAuthenticationTable) throws RequestorException
    {
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        try
        {
            oConnection = oDataSource.getConnection();
        
            StringBuffer sbSelect = new StringBuffer("SELECT ");
            sbSelect.append(COLUMN_AUTHENTICATION_ID);
            sbSelect.append(" FROM ");
            sbSelect.append(sAuthenticationTable);
            sbSelect.append(" WHERE ");
            sbSelect.append(COLUMN_AUTHENTICATION_POOLID);
            sbSelect.append("=? ORDER BY ");
            sbSelect.append(COLUMN_ORDER_ID);
            sbSelect.append(" ASC");
            
            oPreparedStatement = oConnection.prepareStatement(sbSelect.toString());
            oPreparedStatement.setString(1, _sID);
            oResultSet = oPreparedStatement.executeQuery();
            while (oResultSet.next())
            {
                String sAuthenticationProfileID = oResultSet.getString(COLUMN_AUTHENTICATION_ID);
                super.addAuthenticationProfileID(sAuthenticationProfileID);
            }
        }
        catch (SQLException e)
        {
            _logger.error("Can not read from database", e);
            throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during retrieval of requestors", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
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
    }

    private void addRequestors(DataSource oDataSource, String sPoolsTable, 
        String sRequestorsTable, String sRequestorPropertiesTable) throws RequestorException
    {
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet rsRequestor = null;
        ResultSet rsProperties = null;
        try
        {
            oConnection = oDataSource.getConnection();
        
            StringBuffer sbSelect = new StringBuffer("SELECT ");
            sbSelect.append(sRequestorsTable).append(".*");
            sbSelect.append(" FROM ");
            sbSelect.append(sRequestorsTable);
            sbSelect.append(",");
            sbSelect.append(sPoolsTable);
            sbSelect.append(" WHERE ");
            sbSelect.append(sRequestorsTable);
            sbSelect.append(".");
            sbSelect.append(JDBCRequestor.COLUMN_POOLID);
            sbSelect.append("=? AND ");
            sbSelect.append(sRequestorsTable);
            sbSelect.append(".");
            sbSelect.append(JDBCRequestor.COLUMN_POOLID);
            sbSelect.append("=");
            sbSelect.append(sPoolsTable);
            sbSelect.append(".");
            sbSelect.append(JDBCRequestorPool.COLUMN_ID);
            
            oPreparedStatement = oConnection.prepareStatement(sbSelect.toString());
            oPreparedStatement.setString(1, _sID);
            rsRequestor = oPreparedStatement.executeQuery();
            
            while (rsRequestor.next())
            {
                String sID = rsRequestor.getString(COLUMN_ID);
                StringBuffer sbSelectProperties = new StringBuffer("SELECT ");
                sbSelectProperties.append(sRequestorPropertiesTable).append(".*");
                sbSelectProperties.append(" FROM ");
                sbSelectProperties.append(sRequestorPropertiesTable);            
                sbSelectProperties.append(" WHERE ");
                sbSelectProperties.append(sRequestorPropertiesTable);
                sbSelectProperties.append(".");
                sbSelectProperties.append(JDBCRequestor.COLUMN_PROPERTY_REQUESTOR_ID);
                sbSelectProperties.append("=?");
                
                oPreparedStatement = oConnection.prepareStatement(
                    sbSelectProperties.toString());
                oPreparedStatement.setString(1, sID);
                rsProperties = oPreparedStatement.executeQuery();
                
                JDBCRequestor oJDBCRequestor = new JDBCRequestor(
                    rsRequestor, rsProperties);
                super.addRequestor(oJDBCRequestor.getRequestor());
                rsProperties.close();
               
            }
        }
        catch (RequestorException e)
        {
            throw e;
        }
        catch (SQLException e)
        {
            _logger.error("Can not read from database", e);
            throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during retrieval of requestors", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (rsProperties != null)
                    rsProperties.close();
                if (rsRequestor != null)
                    rsRequestor.close();
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
    }
    
    
    private void addProperties(DataSource oDataSource, 
        String sPoolPropertiesTable) throws RequestorException
    {
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet rsProperties = null;
        
        try
        {
            oConnection = oDataSource.getConnection();
            
            StringBuffer sbSelectProperties = new StringBuffer("SELECT ");
            sbSelectProperties.append(sPoolPropertiesTable).append(".*");
            sbSelectProperties.append(" FROM ");
            sbSelectProperties.append(sPoolPropertiesTable);            
            sbSelectProperties.append(" WHERE ");
            sbSelectProperties.append(sPoolPropertiesTable);
            sbSelectProperties.append(".");
            sbSelectProperties.append(JDBCRequestorPool.COLUMN_PROPERTY_POOL_ID);
            sbSelectProperties.append("=?");
            
            oPreparedStatement = oConnection.prepareStatement(
                sbSelectProperties.toString());
            oPreparedStatement.setString(1, _sID);
            rsProperties = oPreparedStatement.executeQuery();
                        
            _properties = new Properties();
            
            while (rsProperties.next())
            {
                String sName = rsProperties.getString(JDBCRequestorPool.COLUMN_PROPERTY_NAME);
                Object value = rsProperties.getString(JDBCRequestorPool.COLUMN_PROPERTY_VALUE);
                _properties.put(sName, value);
            }
            _logger.debug("Retrieved properties: " + _properties);
        }
        catch (SQLException e)
        {
            _logger.error("Can not read from database", e);
            throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during create of a requestorpool", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (rsProperties != null)
                    rsProperties.close();
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
    }
}
