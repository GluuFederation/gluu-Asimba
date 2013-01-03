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
package com.alfaariss.oa.engine.authorization.jdbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Vector;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.engine.core.authorization.AuthorizationException;
import com.alfaariss.oa.engine.core.authorization.AuthorizationMethod;
import com.alfaariss.oa.engine.core.authorization.AuthorizationProfile;

/**
 * Creates the authorization profile from a JDBC resource.
 * <br>
 * This profile is read at runtime from a database table, 
 * specified by the resource configuration.               
 * 
 * @author MHO
 * @author Alfa & Ariss
 */
public class JDBCProfile extends AuthorizationProfile
{
    /** id */
    public static final String COLUMN_PROFILE_ID = "id";
    /** friendlyname */
    public static final String COLUMN_PROFILE_FRIENDLYNAME = "friendlyname";
    /** enabled */
    public static final String COLUMN_PROFILE_ENABLED = "enabled";
    /** Order by id column */
    public static final String COLUMN_ORDER_ID = "order_id";
    
    private static Log _logger;
    
    /**
     * Creates a profile object.
     * @param oDataSource the JDBC datasource
     * @param oResultSet A resultset containing a row with profile information
     * @param sMethodsTable methods table
     * @throws AuthorizationException if creation fails
     */
    public JDBCProfile(DataSource oDataSource, ResultSet oResultSet, 
        String sMethodsTable) 
        throws AuthorizationException
    {
        super();
        try
        {
            _logger = LogFactory.getLog(JDBCProfile.class);

            _sID = oResultSet.getString(COLUMN_PROFILE_ID);
            _sFriendlyName = oResultSet.getString(COLUMN_PROFILE_FRIENDLYNAME);
            if (_sFriendlyName == null)
            {
                StringBuffer sbWarn = new StringBuffer("No '");
                sbWarn.append(COLUMN_PROFILE_FRIENDLYNAME);
                sbWarn.append("' available for profile with id: ");
                sbWarn.append(_sID);
                _logger.error(sbWarn.toString());
                throw new AuthorizationException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }
            
            _bEnabled = oResultSet.getBoolean(COLUMN_PROFILE_ENABLED);
            
            _listAuthorizationMethod = readMethods(oDataSource, sMethodsTable);
        }
        catch (AuthorizationException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
            throw new AuthorizationException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private Vector<AuthorizationMethod> readMethods(DataSource oDataSource, 
        String sMethodsTable) 
        throws AuthorizationException
    {
        Vector<AuthorizationMethod> vMethods = new Vector<AuthorizationMethod>();
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        try
        {
            oConnection = oDataSource.getConnection();
            
            StringBuffer sbSelect = new StringBuffer("SELECT * FROM ");
            sbSelect.append(sMethodsTable);
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
            throw new AuthorizationException(SystemErrors.ERROR_INTERNAL);
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
}
