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
package com.alfaariss.oa.engine.authentication.jdbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;
import java.util.Vector;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.authentication.IAuthenticationMethod;
import com.alfaariss.oa.engine.core.authentication.AuthenticationException;
import com.alfaariss.oa.engine.core.authentication.AuthenticationProfile;

/**
 * Creates the authentication profile from a JDBC resource.
 * <br>
 * This profile is read at runtime from a database table, 
 * specified by the resource configuration.               
 * 
 * @author MHO
 * @author Alfa & Ariss
 */
public class JDBCProfile extends AuthenticationProfile
{
    /** id */
    public static final String COLUMN_PROFILE_ID = "id";
    /** friendlyname */
    public static final String COLUMN_PROFILE_FRIENDLYNAME = "friendlyname";
    /** enabled */
    public static final String COLUMN_PROFILE_ENABLED = "enabled";
    /** Authentication Profile ID */
    public static final String COLUMN_PROPERTY_PROFILE_ID = "profile_id";
    /** Authentication Profile property Name */
    public static final String COLUMN_PROPERTY_NAME = "name";
    /** Authentication Profile property Value */
    public static final String COLUMN_PROPERTY_VALUE = "value";
    /** Order by id column */
    public static final String COLUMN_ORDER_ID = "order_id";
    
    private static final long serialVersionUID = 9142656710779277563L;

    private static Log _logger;
        
    /**
     * Creates a profile object.
     * @param oDataSource the JDBC datasource
     * @param oResultSet A resultset containing a row with profile information
     * @param sMethodTable methods table name
     * @param sProfilePropertiesTable authentication profile properties table name
     * @throws AuthenticationException if creation fails
     */
    public JDBCProfile(DataSource oDataSource, ResultSet oResultSet, 
        String sMethodTable, String sProfilePropertiesTable) 
        throws AuthenticationException
    {
        super();
        try
        {
            _logger = LogFactory.getLog(JDBCProfile.class);
            
            _sID = oResultSet.getString(COLUMN_PROFILE_ID);
            _sFriendlyName = oResultSet.getString(COLUMN_PROFILE_FRIENDLYNAME);
            _bEnabled = oResultSet.getBoolean(COLUMN_PROFILE_ENABLED);
            
            _listAuthenticationMethods = readMethods(oDataSource, sMethodTable);
            
            addProperties(oDataSource, sProfilePropertiesTable);
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
            throw new AuthenticationException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * @see AuthenticationProfile#toString()
     */
    public String toString()
    {
        StringBuffer sbInfo = new StringBuffer("Profile ");
        sbInfo.append(_sID);
        sbInfo.append(" contains ");
        
        for (IAuthenticationMethod oMethod: _listAuthenticationMethods)
            sbInfo.append("[").append(oMethod).append("]");

        return sbInfo.toString();
    }

    private Vector<IAuthenticationMethod> readMethods(DataSource oDataSource, 
        String sMethodTable) throws AuthenticationException
    {
        Vector<IAuthenticationMethod> vMethods = new Vector<IAuthenticationMethod>();
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        try
        {
            oConnection = oDataSource.getConnection();
            
            StringBuffer sbSelect = new StringBuffer("SELECT * FROM ");
            sbSelect.append(sMethodTable);
            sbSelect.append(" WHERE ");
            sbSelect.append(JDBCMethod.COLUMN_PROFILE);
            sbSelect.append("=? ORDER BY ");
            sbSelect.append(COLUMN_ORDER_ID);
            sbSelect.append(" ASC");
            
            oPreparedStatement = oConnection.prepareStatement(sbSelect.toString());
            oPreparedStatement.setString(1, _sID);
            oResultSet = oPreparedStatement.executeQuery();
            while (oResultSet.next())
            {
                JDBCMethod oMethod = new JDBCMethod(oResultSet);
                vMethods.add(oMethod);
            }
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
            throw new AuthenticationException(SystemErrors.ERROR_INTERNAL);
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
        
        return vMethods;
    }
    
    private void addProperties(DataSource oDataSource, 
        String sProfilePropertiesTable) throws AuthenticationException
    {
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet rsProperties = null;
        
        try
        {
            oConnection = oDataSource.getConnection();
            
            StringBuffer sbSelectProperties = new StringBuffer("SELECT ");
            sbSelectProperties.append(sProfilePropertiesTable).append(".*");
            sbSelectProperties.append(" FROM ");
            sbSelectProperties.append(sProfilePropertiesTable);            
            sbSelectProperties.append(" WHERE ");
            sbSelectProperties.append(sProfilePropertiesTable);
            sbSelectProperties.append(".");
            sbSelectProperties.append(COLUMN_PROPERTY_PROFILE_ID);
            sbSelectProperties.append("=?");
            
            oPreparedStatement = oConnection.prepareStatement(
                sbSelectProperties.toString());
            oPreparedStatement.setString(1, _sID);
            rsProperties = oPreparedStatement.executeQuery();
                        
            _properties = new Properties();
            
            while (rsProperties.next())
            {
                String sName = rsProperties.getString(COLUMN_PROPERTY_NAME);
                Object value = rsProperties.getString(COLUMN_PROPERTY_VALUE);
                _properties.put(sName, value);
            }
            _logger.debug("Retrieved properties: " + _properties);
        }
        catch (SQLException e)
        {
            _logger.error("Can not read from database", e);
            throw new AuthenticationException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during create of an authentication profile", e);
            throw new AuthenticationException(SystemErrors.ERROR_INTERNAL);
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
