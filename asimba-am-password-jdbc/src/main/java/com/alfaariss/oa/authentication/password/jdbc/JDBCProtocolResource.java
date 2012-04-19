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

package com.alfaariss.oa.authentication.password.jdbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.password.AbstractDigestorResourceHandler;
import com.alfaariss.oa.authentication.password.AbstractResourceHandler;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;

/**
 * A JDBC protocol resource.
 * 
 * For every JDBC resource configured in the Password Authentication Handler
 * section a JDBCProtocolResource will be initialized.
 * 
 * @author JVG
 * @author Alfa & Ariss
 * 
 */
public class JDBCProtocolResource extends AbstractDigestorResourceHandler
{
    /** The system logger */
    private final Log _logger;
    /** The data source */
    protected DataSource _oDataSource;
    /** The Database query. */
    protected String _query;

    /**
     * Constructor.
     */
    public JDBCProtocolResource ()
    {
        super();
        _logger = LogFactory.getLog(this.getClass());
    }

    /**
     * @see AbstractResourceHandler#init(IConfigurationManager, 
     *  org.w3c.dom.Element)
     */
    @Override
    public void init(IConfigurationManager cmm, Element eResourceSection)
    throws OAException
    {
        super.init(cmm, eResourceSection);

        // Create data source
        _oDataSource = DataSourceFactory.createDataSource(cmm, eResourceSection);

        //Get query configuration
        _query = cmm.getParam(eResourceSection, "query");
        if (_query == null || _query.length() <= 0) //No query configured
        {
            _logger.info("No 'query' defined for realm: "
                + _sResourceRealm);
            _logger.info("Fallback to table configuration section");
            
            // Get database table section
            Element eDatabaseTableSection = cmm.getSection(
                eResourceSection, "table");
            if (eDatabaseTableSection == null)
            {
                _logger.error("No 'table' section defined for realm: "
                    + _sResourceRealm);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }

            initDBTable(cmm, eDatabaseTableSection);
        }
        else
        {
            //Test the configured query
            testQuery();
        }       
    }

    /**
     * Initialize the Database Table.
     * 
     * @param cmm The configuration manager.
     * @param eDatabaseTableSection The database section
     * @throws OAException
     */
    protected void initDBTable(IConfigurationManager cmm, 
        Element eDatabaseTableSection) throws OAException
    {
        String sTableName = cmm.getParam(eDatabaseTableSection, "name");
        if ((sTableName == null) || sTableName.equals(""))
        {
            _logger
            .error("No table 'name' defined in 'db_table' section for realm: "
                + _sResourceRealm);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }

        String sUserColumn = cmm.getParam(eDatabaseTableSection, "user_column");
        if ((sUserColumn == null) || sUserColumn.equals(""))
        {
            _logger
            .error("No 'user_column' defined in 'db_table' section for realm: "
                + _sResourceRealm);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }

        String sPasswordColumn = cmm.getParam(eDatabaseTableSection, "password_column");
        if ((sPasswordColumn == null) || sPasswordColumn.equals(""))
        {
            _logger.error("No 'password_column' defined in 'db_table' section for realm: "
                + _sResourceRealm);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        generateDefaultQuery(sTableName, sUserColumn, sPasswordColumn);
    }

    /**
     * @see AbstractDigestorResourceHandler#getData(java.lang.String,
     *      java.lang.String)
     */
    protected byte[] getData(
        String realm, String username) throws OAException, UserException
    {
        Connection oConnection = null;
        PreparedStatement sPreparedStatementQuery = null;
        ResultSet oResultSet = null;
        byte[] result = null;
    
        try
        {
            oConnection = _oDataSource.getConnection();
        }
        catch (SQLException e)
        {
            _logger.warn("Could not open connection", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    
        try
        {
            sPreparedStatementQuery = oConnection.prepareStatement(_query);
            sPreparedStatementQuery.setString(1, username);
            oResultSet = sPreparedStatementQuery.executeQuery();
    
            if (!oResultSet.next())
            {
                _logger.debug("No result after executing query for user: "
                    + username);
                throw new UserException(UserEvent.AUTHN_METHOD_NOT_SUPPORTED);
            }
    
            result = oResultSet.getBytes(1);
    
            String sResult = oResultSet.getString(1);
    
            if(_logger.isDebugEnabled())
            {
                _logger.debug("Result Bytes: " + new String(result));
                _logger.debug("Result string: " + sResult);
            }
    
            if (result == null)
            {
                _logger.warn("No user password found for user: " + username);
                throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }
        }
        catch (SQLException e)
        {
            _logger.warn("Could not execute query", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (oConnection != null)
                {
                    oConnection.close();
                }
            }
            catch (Exception e)
            {
                _logger.error("Could not close connection", e);
            }
        }
    
        return result;
    }

    /**
     * Generate the default query.
     */
    private void generateDefaultQuery(String sTableName, String sUserColumn,
        String sPasswordColumn)
    {
        // Create dafault Query
        StringBuffer sbQuery = new StringBuffer();
        sbQuery.append("SELECT ");
        sbQuery.append(sPasswordColumn);
        sbQuery.append(" FROM ");
        sbQuery.append(sTableName);
        sbQuery.append(" WHERE UPPER(");
        sbQuery.append(sUserColumn);
        sbQuery.append(")=UPPER(?)");
        _query = sbQuery.toString();
    }
    
    //Test a configured query
    private void testQuery() throws OAException 
    {
        Connection oConnection = null;
        PreparedStatement sPreparedStatementQuery = null;
        
        try
        {
            oConnection = _oDataSource.getConnection();
        }
        catch (SQLException e)
        {
            _logger.warn("Could not open connection for realm: " 
                + _sResourceRealm, e);
            throw new OAException(SystemErrors.ERROR_RESOURCE_CONNECT);
        }

        try
        {
            sPreparedStatementQuery = oConnection.prepareStatement(_query);
            sPreparedStatementQuery.setString(1, "test_user");
            sPreparedStatementQuery.executeQuery();
            //User does not have to exist 
        }
        catch (SQLException e)
        {
            _logger.error("Invalid query defined for realm: "
                + _sResourceRealm, e);
            throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        finally
        {
            try
            {
                if (oConnection != null)
                {
                    oConnection.close();
                }
            }
            catch (Exception e)
            {
                _logger.error("Could not close connection", e);
            }
        }
       
    }
}
