/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.engine.authorization.jdbc;

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
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.datastorage.IDataStorageFactory;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.authorization.AuthorizationException;
import com.alfaariss.oa.engine.core.authorization.AuthorizationProfile;
import com.alfaariss.oa.engine.core.authorization.factory.IAuthorizationFactory;
import com.alfaariss.oa.util.database.DatabaseException;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;

/**
 * The JDBC authorization profile factory implementation.
 * 
 * Reads factory information from database resource.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class JDBCFactory implements IAuthorizationFactory, IComponent 
{
    private final static String TABLE_NAME_PROFILES = "authz_profile";
    private final static String TABLE_NAME_METHODS = "authz_method";
    
    private static Log _logger;
    private IConfigurationManager _configurationManager;
    private boolean _bEnabled;
    private DataSource _oDataSource;
    private String _sProfilesTable;
    private String _sMethodsTable;
    
	/**
	 * Creates the object. 
	 */
	public JDBCFactory()
    {
        _logger = LogFactory.getLog(JDBCFactory.class);
        _bEnabled = true;
        _sProfilesTable = null;
        _sMethodsTable = null;
	}

	/**
	 * Returns the pre authorization profile or <code>null</code> if not exists.
     * The profile is specified by it's ID.
	 * @see com.alfaariss.oa.engine.core.authorization.factory.IAuthorizationFactory#getProfile(java.lang.String)
	 */
	public AuthorizationProfile getProfile(String id) 
        throws AuthorizationException
    {
        JDBCProfile oProfile = null;
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        try
        {
            oConnection = _oDataSource.getConnection();
            
            StringBuffer sbSelect = new StringBuffer("SELECT * FROM ");
            sbSelect.append(_sProfilesTable);
            sbSelect.append(" WHERE ");
            sbSelect.append(JDBCProfile.COLUMN_PROFILE_ID);
            sbSelect.append("=?");  
            
            oPreparedStatement = oConnection.prepareStatement(sbSelect.toString());
            oPreparedStatement.setString(1, id);
            oResultSet = oPreparedStatement.executeQuery();
            if (oResultSet.next())
                oProfile = new JDBCProfile(_oDataSource, oResultSet, _sMethodsTable);
            
            _logger.debug("Retrieved profile: " + oProfile);
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during retrieval of profile: " 
                + id, e);
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
        return oProfile;
	}

    /**
     * Initializes the component.
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager
        , Element eConfig) throws OAException
    {
        Connection oConnection = null;
          
        try
        {
            _configurationManager = oConfigurationManager;
            String sEnabled = _configurationManager.getParam(eConfig, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    _bEnabled = false;
                else if (sEnabled.equalsIgnoreCase("TRUE"))
                    _bEnabled = true;
                else
                {
                    _logger.error("Unknown value in 'enabled' configuration item: " 
                        + sEnabled);
                    throw new AuthorizationException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            if (_bEnabled)
            {
                Element eResource = _configurationManager.getSection(eConfig, "resource");
                if (eResource == null)
                {
                    _logger.warn("No 'resource' section found in configuration, using default table names");
                    _sProfilesTable = TABLE_NAME_PROFILES;
                    _sMethodsTable = TABLE_NAME_METHODS;
                    
                    IDataStorageFactory databaseFactory = Engine.getInstance().getStorageFactory();
                    if (databaseFactory != null && databaseFactory.isEnabled())
                    {
                        _oDataSource = databaseFactory.createModelDatasource();
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
                else
                {
                    try
                    {
                        _oDataSource = DataSourceFactory.createDataSource(_configurationManager, eResource);
                        _logger.info("Using datasource specified in 'resource' section in configuration");
                    }
                    catch (DatabaseException e)
                    {
                        IDataStorageFactory databaseFactory = Engine.getInstance().getStorageFactory();
                        if (databaseFactory != null && databaseFactory.isEnabled())
                        {
                            _oDataSource = databaseFactory.createModelDatasource();
                            if (_oDataSource == null)
                            {
                                _logger.error("Could not create a valid datasource");
                                throw new DatabaseException(SystemErrors.ERROR_INIT);
                            }
                            _logger.info("Using datasource specified in engine");
                        }
                        else
                        {
                            _logger.error("Could not create a valid datasource", e);
                            throw new DatabaseException(SystemErrors.ERROR_INIT);
                        }
                    }
                }
                
                try
                {
                    oConnection = _oDataSource.getConnection();
                }
                catch (SQLException e)
                {
                    _logger.error("Could not connect to resource", e);
                    throw new DatabaseException(SystemErrors.ERROR_INIT, e);
                }
                
                if (eResource != null)
                {
                    Element eProfiles = _configurationManager.getSection(eResource, "profiles");
                    if (eProfiles == null)
                    {
                        _sProfilesTable = TABLE_NAME_PROFILES;
                        _logger.warn("No 'profiles' section found in configuration, using default table: " + _sProfilesTable);
                    }
                    else
                    {
                        _sProfilesTable = _configurationManager.getParam(eProfiles, "table");
                        if (_sProfilesTable == null)
                        {
                            _sProfilesTable = TABLE_NAME_PROFILES;
                            _logger.warn("No 'table' item in 'profiles' section found in configuration, using default: " + _sProfilesTable);
                        }
                    }
                }
                
                Element eValidation = _configurationManager.getSection(eConfig, "validation");
                
                StringBuffer sbVerify = new StringBuffer("SELECT ");
                sbVerify.append(JDBCProfile.COLUMN_PROFILE_ID).append(",");
                sbVerify.append(JDBCProfile.COLUMN_PROFILE_FRIENDLYNAME).append(",");
                sbVerify.append(JDBCProfile.COLUMN_PROFILE_ENABLED);
                sbVerify.append(" FROM ");
                sbVerify.append(_sProfilesTable);
                sbVerify.append(" LIMIT 1");                                
                validateTable(oConnection, eValidation, "profiles", sbVerify.toString());
                
                if (eResource != null)
                {
                    Element eMethods = _configurationManager.getSection(eResource, "methods");
                    if (eMethods == null)
                    {
                        _sMethodsTable = TABLE_NAME_METHODS;
                        _logger.warn("No 'methods' section found in configuration, using default table: " + _sMethodsTable);
                    }
                    else
                    {
                        _sMethodsTable = _configurationManager.getParam(eMethods, "table");                
                        if (_sMethodsTable == null)
                        {
                            _sMethodsTable = TABLE_NAME_METHODS;
                            _logger.warn("No 'table' item in 'methods' section found in configuration, using default: " + _sMethodsTable);
                        }
                    }
                }
                
                sbVerify = new StringBuffer("SELECT ");
                sbVerify.append(JDBCMethod.COLUMN_METHOD_ID).append(",");
                sbVerify.append(JDBCMethod.COLUMN_PROFILE);
                sbVerify.append(" FROM ");
                sbVerify.append(_sMethodsTable);
                sbVerify.append(" LIMIT 1");   
                validateTable(oConnection, eValidation, "methods", sbVerify.toString());
            }
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
     * Restarts the component.
     * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
     */
    public void restart(Element eConfig) throws OAException
    {
        synchronized(this)
        {
            stop();
            start(_configurationManager, eConfig);
        }
    }
    
    /**
     * Stops the component.
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    public void stop()
    {
        //do nothing
    }

    /**
     * Returns TRUE if the component is disabled.
     * @see com.alfaariss.oa.api.IOptional#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }
    
    //TODO move to utility class
    private void validateTable(Connection oConnection, Element eValidation, String table, 
        String sDefault) throws DatabaseException, SQLException
    {
        String sVerificationQuery = null;
        PreparedStatement pVerification = null;
        try
        {
            if(eValidation != null)
            {
                Element e = _configurationManager.getSection(eValidation, table);
                if(e != null)
                {
                    sVerificationQuery = _configurationManager.getParam(e, "query");
                    if(sVerificationQuery == null || sVerificationQuery.length() == 0)
                    {
                        //DD Do not verify the table if empty query configured
                        _logger.warn("Empty validation query found, table structure is not validated for table:  " + table);
                        //finally is executed before return
                        return;
                    }
                    _logger.info("Validation query found: " + sVerificationQuery);
                }
            }
            
            if(sVerificationQuery == null)
            {
                //DD Use default query if no query parameter configured                               
                sVerificationQuery = sDefault;
                _logger.info("No validation query found, using default: " + sDefault);
            }
            
            pVerification = oConnection.prepareStatement(sVerificationQuery);
            try
            {
                pVerification.executeQuery();
            }
            catch(Exception e)
            {
                StringBuffer sbError = new StringBuffer("Invalid table configured '");
                sbError.append(table);
                sbError.append("' verified with query: ");
                sbError.append(sVerificationQuery);
                _logger.error(sbError.toString(), e);
                throw new DatabaseException(SystemErrors.ERROR_INIT);
            }        
            _logger.info("Table structure validated for table: " + table);
        }
        catch(ConfigurationException e)
        {            
            _logger.error("Invalid validation query found for table: " + table, e);
            throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
        }
        finally
        {
            try
            {
                if (pVerification != null)
                    pVerification.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close verification statement", e);
            }
        }
    } 
}