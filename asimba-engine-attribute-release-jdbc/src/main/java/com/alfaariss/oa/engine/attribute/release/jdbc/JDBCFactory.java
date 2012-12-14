/*
 * * Asimba - Serious Open Source SSO

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
 * * Asimba - Serious Open Source SSO - More information on www.asimba.org

 * 
 */
package com.alfaariss.oa.engine.attribute.release.jdbc;

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
import com.alfaariss.oa.engine.core.attribute.AttributeException;
import com.alfaariss.oa.engine.core.attribute.release.IAttributeReleasePolicy;
import com.alfaariss.oa.engine.core.attribute.release.factory.IAttributeReleasePolicyFactory;
import com.alfaariss.oa.util.database.DatabaseException;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;

/**
 * Release policy factory.
 *
 * Reads the policy information from jdbc.
 * @author MHO
 * @author Alfa & Ariss
 */
public class JDBCFactory implements IAttributeReleasePolicyFactory, IComponent 
{
    private final static String TABLE_NAME_POLICY = "attributerelease_policy";
    private final static String TABLE_NAME_ATTRIBUTE = "attributerelease_expression";
    
    private static Log _logger;
    private IConfigurationManager _configurationManager;
    private DataSource _oDataSource;
    private String _sPolicyTable;
    private String _sAttributeTable;
    private boolean _bEnabled;
    
    /**
     * Creates the object. 
     */
    public JDBCFactory()
    {
        _logger = LogFactory.getLog(JDBCFactory.class);
        _sPolicyTable = null;
        _sAttributeTable = null;
        _bEnabled = false;
    }
    
    /**
     * Returns the policy with the supplied name or <code>null</code> if 
     * it does not exist.
     * @see IAttributeReleasePolicyFactory#getPolicy(java.lang.String)
     */
    public IAttributeReleasePolicy getPolicy(String policy) 
        throws AttributeException
    {
        IAttributeReleasePolicy oPolicy = null;
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        try
        {
            oConnection = _oDataSource.getConnection();
            StringBuffer sbSelect = new StringBuffer("SELECT * FROM ");
            sbSelect.append(_sPolicyTable);
            sbSelect.append(" WHERE ");
            sbSelect.append(JDBCPolicy.COLUMN_POLICY_ID);
            sbSelect.append("=?");
            
            oPreparedStatement = oConnection.prepareStatement(sbSelect.toString());
            oPreparedStatement.setString(1, policy);
            oResultSet = oPreparedStatement.executeQuery();
            if (oResultSet.next())
                oPolicy = new JDBCPolicy(_oDataSource, oResultSet, _sAttributeTable);
            
            _logger.debug("Retrieved profile: " + oPolicy);
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during retrieval of policy: " 
                + policy, e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL, e);
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
        return oPolicy;
    }

    /**
     * Returns TRUE if this release policy factory is enabled.
     * @see com.alfaariss.oa.api.IOptional#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }

    /**
     * Restarts the release policy factory.
     * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
     */
    public void restart(Element config) throws OAException
    {
        synchronized (this)
        {
            stop();
            start(_configurationManager, config);
        }
    }

    /**
     * Initializes the release policy factory.
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager configurationManager, Element config)
        throws OAException
    {
        Connection oConnection = null;
        try
        {
            _bEnabled = false;
            _configurationManager = configurationManager;
            
            Element eResource = _configurationManager.getSection(config, "resource");
            if (eResource == null)
            {
                _logger.warn("No 'resource' section found in configuration, using default table names");
                _sPolicyTable = TABLE_NAME_POLICY;
                _sAttributeTable = TABLE_NAME_ATTRIBUTE;
                
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
                Element ePolicy = _configurationManager.getSection(eResource, "policy");
                if (ePolicy == null)
                {
                    _sPolicyTable = TABLE_NAME_POLICY;
                    _logger.warn("No 'policy' section found in configuration, using default table: " + _sPolicyTable);
                }
                else
                {
                    _sPolicyTable = _configurationManager.getParam(ePolicy, "table");
                    if (_sPolicyTable == null)
                    {
                        _sPolicyTable = TABLE_NAME_POLICY;
                        _logger.warn("No 'table' item in 'policy' section found in configuration, using default: " + _sPolicyTable);
                    }
                }
            }
            
            
            Element eValidation = _configurationManager.getSection(config, "validation");
            StringBuffer sbPolicyVerify = new StringBuffer("SELECT ");
            sbPolicyVerify.append(JDBCPolicy.COLUMN_POLICY_ID).append(",");
            sbPolicyVerify.append(JDBCPolicy.COLUMN_POLICY_FRIENDLYNAME).append(",");
            sbPolicyVerify.append(JDBCPolicy.COLUMN_POLICY_ENABLED);
            sbPolicyVerify.append(" FROM ");
            sbPolicyVerify.append(_sPolicyTable);
            sbPolicyVerify.append(" LIMIT 1"); 
            validateTable(oConnection, eValidation, "policy", sbPolicyVerify.toString());
                       
            if (eResource != null)
            {
                Element eAttribute = _configurationManager.getSection(eResource, "attribute");
                if (eAttribute == null)
                {
                    _sAttributeTable = TABLE_NAME_ATTRIBUTE;
                    _logger.warn("No 'attribute' section found in configuration, using default table: " + _sAttributeTable);
                }
                else
                {
                    _sAttributeTable = _configurationManager.getParam(eAttribute, "table");
                    if (_sAttributeTable == null)
                    {
                        _sAttributeTable = TABLE_NAME_ATTRIBUTE;
                        _logger.warn("No 'table' item in 'attribute' section found in configuration, using default: " + _sAttributeTable);
                    }
                }
            }
            
            StringBuffer sbAttributeVerify = new StringBuffer("SELECT ");
            sbAttributeVerify.append(JDBCPolicy.COLUMN_ATTRIBUTE_POLICY_ID).append(",");
            sbAttributeVerify.append(JDBCPolicy.COLUMN_ATTRIBUTE_ATTRIBUTE);
            sbAttributeVerify.append(" FROM ");
            sbAttributeVerify.append(_sAttributeTable);
            sbAttributeVerify.append(" LIMIT 1"); 
            validateTable(oConnection, eValidation, "attribute", sbAttributeVerify.toString());
            _bEnabled = true;
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL, e);
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
     * Stops the release policy factory.
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    public void stop()
    {
        //nothing to do
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
