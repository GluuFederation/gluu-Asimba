/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2010 Alfa & Ariss B.V.
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
import java.util.Collection;
import java.util.Collections;
import java.util.Vector;

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
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.requestor.RequestorException;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
import com.alfaariss.oa.util.database.DatabaseException;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;

/**
 * The requestor pool factory.
 *
 * Reads factory information from items stored in a jdbc back end.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class JDBCFactory implements IRequestorPoolFactory, IComponent 
{
    private final static String TABLE_NAME_POOLS = "requestorpool_pool";
    private final static String TABLE_NAME_AUTHN = "requestorpool_authnprofile";
    private final static String TABLE_NAME_REQUESTORS = "requestorpool_requestor";
    private final static String TABLE_NAME_REQUESTOR_PROPS = "requestorpool_requestor_properties";
    private final static String TABLE_NAME_POOL_PROPS = "requestorpool_properties"; 
    
    private Log _logger;
    private IConfigurationManager _configurationManager;
    private DataSource _oDataSource;
    
    private String _sPoolsTable;
    private String _sPoolPropertiesTable;
    private String _sAuthenticationTable;
    private String _sRequestorsTable;
    private String _sRequestorPropertiesTable;
    
    private String _sQuerySelectPool;
    private String _sQuerySelectRequestor;
    private String _sQuerySelectRequestorProperties;
    private String _sQuerySelectPoolAvailable;
    private String _sQuerySelectRequestorAvailable;
    private String _sQuerySelectAllRequestorpools;
    private String _sQuerySelectAllEnabledRequestorpools;
    private String _sQuerySelectAllRequestors;
    private String _sQuerySelectAllEnabledRequestors;
    
	/**
	 * Creates the object.
	 */
	public JDBCFactory()
    {
        _logger = LogFactory.getLog(JDBCFactory.class);
        _oDataSource = null;
        _sPoolsTable = null;
        _sAuthenticationTable = null;
        _sRequestorsTable = null;
        _sRequestorPropertiesTable = null;
        _sPoolPropertiesTable = null;
        _sQuerySelectPool = null;
        _sQuerySelectRequestor = null;
        _sQuerySelectRequestorProperties = null;
        _sQuerySelectPoolAvailable = null;
        _sQuerySelectRequestorAvailable = null;
        _sQuerySelectAllRequestorpools = null;
        _sQuerySelectAllEnabledRequestorpools = null;
        _sQuerySelectAllRequestors = null;
        _sQuerySelectAllEnabledRequestors = null;
	}

    /**
     * Returns the requestor pool were the supplied request id is a part from.
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getRequestorPool(java.lang.String)
     */
    public RequestorPool getRequestorPool(String sRequestor) throws RequestorException
    {
        JDBCRequestorPool oRequestorPool = null;
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        try
        {
            oConnection = _oDataSource.getConnection();
                        
            oPreparedStatement = oConnection.prepareStatement(_sQuerySelectPool);
            oPreparedStatement.setString(1, sRequestor);
            oResultSet = oPreparedStatement.executeQuery();
            if (oResultSet.next())
            {
                oRequestorPool = new JDBCRequestorPool(oResultSet, _oDataSource, 
                    _sPoolsTable, _sRequestorsTable, _sRequestorPropertiesTable, 
                    _sAuthenticationTable, _sPoolPropertiesTable);
            }
            
            if (oRequestorPool != null)
                _logger.debug("Retrieved requestorpool: " + oRequestorPool);
            else
                _logger.debug("No requestorpool found for requestor: " + sRequestor);
        }
        catch (SQLException e)
        {
            _logger.error("Can not read from database", e);
            throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (RequestorException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during retrieval of requestor: " 
                + sRequestor, e);
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
        return oRequestorPool;
    }

    /**
     * Returns the requestor specified by its ID.
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getRequestor(java.lang.String)
     */
    public IRequestor getRequestor(String sRequestor) throws RequestorException
    {
        IRequestor oRequestor = null;
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet rsRequestor = null;
        ResultSet rsProperties = null;
        try
        {
            oConnection = _oDataSource.getConnection();
            
            oPreparedStatement = oConnection.prepareStatement(_sQuerySelectRequestor);
            oPreparedStatement.setString(1, sRequestor);
            rsRequestor = oPreparedStatement.executeQuery();
                                   
            oPreparedStatement = oConnection.prepareStatement(_sQuerySelectRequestorProperties);
            oPreparedStatement.setString(1, sRequestor);
            rsProperties = oPreparedStatement.executeQuery();
                        
            if (rsRequestor.next())
            {
                JDBCRequestor oJDBCRequestor = new JDBCRequestor(
                    rsRequestor, rsProperties);
                oRequestor = oJDBCRequestor.getRequestor();
                _logger.debug("Retrieved requestor: " + oRequestor);
            }
            else
                _logger.debug("Requestor not found: " + sRequestor);
        }
        catch (SQLException e)
        {
            _logger.error("Can not read from database", e);
            throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (RequestorException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during retrieval of requestor: " 
                + sRequestor, e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (rsRequestor != null)
                    rsRequestor.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close requestor resultset", e);
            }
            
            try
            {
                if (rsProperties != null)
                    rsProperties.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close requestor properties resultset", e);
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
        
        return oRequestor;
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#isPool(java.lang.String)
     */
    public boolean isPool(String sPoolID) throws RequestorException
    {
        boolean bIsPool = false;
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        try
        {
            oConnection = _oDataSource.getConnection();
            
            oPreparedStatement = oConnection.prepareStatement(_sQuerySelectPoolAvailable);
            oPreparedStatement.setString(1, sPoolID);
            oResultSet = oPreparedStatement.executeQuery();
            if (oResultSet.next())
                bIsPool = true;
        }
        catch (SQLException e)
        {
            _logger.error("Error during database retrieval, when selecting pool id: " 
                + sPoolID, e);
            throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during exist check of pool id: " 
                + sPoolID, e);
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
        return bIsPool;
    }

    /**
     * Starts the component.
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager, Element eConfig) throws OAException
    {
        Connection oConnection = null;
        
        try
        {
            _configurationManager = oConfigurationManager;
            
            Element eResource = _configurationManager.getSection(eConfig, "resource");
            if (eResource == null)
            {
                _logger.warn("No 'resource' section found in configuration, using default table names");
                _sPoolsTable = TABLE_NAME_POOLS;
                _sAuthenticationTable = TABLE_NAME_AUTHN;
                _sRequestorsTable = TABLE_NAME_REQUESTORS;
                _sRequestorPropertiesTable = TABLE_NAME_REQUESTOR_PROPS;
                _sPoolPropertiesTable = TABLE_NAME_POOL_PROPS;
                
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
                Element ePools = _configurationManager.getSection(eResource, "pools");
                if (ePools == null)
                {
                    _sPoolsTable = TABLE_NAME_POOLS;
                    _logger.warn("No 'pools' section found in configuration, using default table: " + _sPoolsTable);
                }
                else
                {
                    _sPoolsTable = _configurationManager.getParam(ePools, "table");
                    if (_sPoolsTable == null)
                    {
                        _sPoolsTable = TABLE_NAME_POOLS;
                        _logger.warn("No 'table' item in 'pools' section found in configuration, using default: " + _sPoolsTable);
                    }
                }
            }
            
            Element eValidation = _configurationManager.getSection(eConfig, "validation");
            
            StringBuffer sbVerify = new StringBuffer("SELECT ");
            sbVerify.append(JDBCRequestorPool.COLUMN_ID).append(",");           
            sbVerify.append(JDBCRequestorPool.COLUMN_ENABLED).append(",");
            sbVerify.append(JDBCRequestorPool.COLUMN_FORCED).append(",");
            sbVerify.append(JDBCRequestorPool.COLUMN_FRIENDLYNAME).append(",");
            sbVerify.append(JDBCRequestorPool.COLUMN_POSTAUTHORIZATIE).append(",");
            sbVerify.append(JDBCRequestorPool.COLUMN_PREAUTHORIZATION).append(",");
            sbVerify.append(JDBCRequestorPool.COLUMN_RELEASEPOLICY);
            sbVerify.append(" FROM ");
            sbVerify.append(_sPoolsTable);
            sbVerify.append(" LIMIT 1");   
            validateTable(oConnection, eValidation, "pools", sbVerify.toString());
            
            if (eResource != null)
            {
                Element ePoolProperties = _configurationManager.getSection(eResource, "pool_properties");
                if (ePoolProperties == null)
                {
                    _sPoolPropertiesTable = TABLE_NAME_POOL_PROPS;
                    _logger.warn("No 'pool_properties' section found in configuration, using default table: " + _sPoolPropertiesTable);
                }
                else
                {
                    _sPoolPropertiesTable = _configurationManager.getParam(ePoolProperties, "table");
                    if (_sPoolPropertiesTable == null)
                    {
                        _sPoolPropertiesTable = TABLE_NAME_POOL_PROPS;
                        _logger.warn("No 'table' item in 'pool_properties' section found in configuration, using default: " + _sRequestorPropertiesTable);
                    }
                }
            }
            
            sbVerify = new StringBuffer("SELECT ");
            sbVerify.append(JDBCRequestorPool.COLUMN_PROPERTY_POOL_ID).append(",");
            sbVerify.append(JDBCRequestorPool.COLUMN_PROPERTY_NAME).append(",");
            sbVerify.append(JDBCRequestorPool.COLUMN_PROPERTY_VALUE);          
            sbVerify.append(" FROM ");
            sbVerify.append(_sPoolPropertiesTable);
            sbVerify.append(" LIMIT 1");   
            validateTable(oConnection, eValidation, "pool_properties", sbVerify.toString());
            
            
            if (eResource != null)
            {
                Element eAuthentication = _configurationManager.getSection(eResource, "authentication");
                if (eAuthentication == null)
                {
                    _sAuthenticationTable = TABLE_NAME_AUTHN;
                    _logger.warn("No 'authentication' section found in configuration, using default table: " + _sAuthenticationTable);
                }
                else
                {
                    _sAuthenticationTable = _configurationManager.getParam(eAuthentication, "table");
                    if (_sAuthenticationTable == null)
                    {
                        _sAuthenticationTable = TABLE_NAME_AUTHN;
                        _logger.warn("No 'table' item in 'authentication' section found in configuration, using default: " + _sAuthenticationTable);
                    }
                }
            }
            
            sbVerify = new StringBuffer("SELECT ");
            sbVerify.append(JDBCRequestorPool.COLUMN_AUTHENTICATION_ID).append(",");           
            sbVerify.append(JDBCRequestorPool.COLUMN_AUTHENTICATION_POOLID);
            sbVerify.append(" FROM ");
            sbVerify.append(_sAuthenticationTable);
            sbVerify.append(" LIMIT 1");   
            validateTable(oConnection, eValidation, "authentication", sbVerify.toString());
            
            if (eResource != null)
            {
                Element eRequestors = _configurationManager.getSection(eResource, "requestors");
                if (eRequestors == null)
                {
                    _sRequestorsTable = TABLE_NAME_REQUESTORS;
                    _logger.warn("No 'requestors' section found in configuration, using default table: " + _sRequestorsTable);
                }
                else
                {
                    _sRequestorsTable = _configurationManager.getParam(eRequestors, "table");
                    if (_sRequestorsTable == null)
                    {
                        _sRequestorsTable = TABLE_NAME_REQUESTORS;
                        _logger.warn("No 'table' item in 'requestors' section found in configuration, using default: " + _sRequestorsTable);
                    }
                }
            }
            
            sbVerify = new StringBuffer("SELECT ");
            sbVerify.append(JDBCRequestor.COLUMN_ID).append(",");
            sbVerify.append(JDBCRequestor.COLUMN_ENABLED).append(",");
            sbVerify.append(JDBCRequestor.COLUMN_FRIENDLYNAME).append(",");           
            sbVerify.append(JDBCRequestor.COLUMN_POOLID);
            sbVerify.append(" FROM ");
            sbVerify.append(_sRequestorsTable);
            sbVerify.append(" LIMIT 1");   
            validateTable(oConnection, eValidation, "requestors", sbVerify.toString());
            
            if (eResource != null)
            {
                Element eRequestorProperties = _configurationManager.getSection(eResource, "requestor_properties");
                if (eRequestorProperties == null)
                {
                    _sRequestorPropertiesTable = TABLE_NAME_REQUESTOR_PROPS;
                    _logger.warn("No 'requestor_properties' section found in configuration, using default table: " + _sRequestorPropertiesTable);
                }
                else
                {
                    _sRequestorPropertiesTable = _configurationManager.getParam(eRequestorProperties, "table");
                    if (_sRequestorPropertiesTable == null)
                    {
                        _sRequestorPropertiesTable = TABLE_NAME_REQUESTOR_PROPS;
                        _logger.warn("No 'table' item in 'requestor_properties' section found in configuration, using default: " + _sRequestorPropertiesTable);
                    }
                }
            }
            
            sbVerify = new StringBuffer("SELECT ");
            sbVerify.append(JDBCRequestor.COLUMN_PROPERTY_REQUESTOR_ID).append(",");
            sbVerify.append(JDBCRequestor.COLUMN_PROPERTY_NAME).append(",");
            sbVerify.append(JDBCRequestor.COLUMN_PROPERTY_VALUE);          
            sbVerify.append(" FROM ");
            sbVerify.append(_sRequestorPropertiesTable);
            sbVerify.append(" LIMIT 1");   
            validateTable(oConnection, eValidation, "requestor_properties", sbVerify.toString());
            
            createQueries();
        }
        catch(RequestorException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
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
        _oDataSource = null;
        
        _sPoolsTable = null;
        _sAuthenticationTable = null;
        _sRequestorsTable = null;
        _sRequestorPropertiesTable = null;
        _sPoolPropertiesTable = null;
        
        _sQuerySelectPool = null;
        _sQuerySelectRequestor = null;
        _sQuerySelectRequestorProperties = null;
        _sQuerySelectPoolAvailable = null;
        _sQuerySelectRequestorAvailable = null;
        _sQuerySelectAllRequestorpools = null;
        _sQuerySelectAllEnabledRequestorpools = null;
        _sQuerySelectAllRequestors = null;
        _sQuerySelectAllEnabledRequestors = null;
    }

    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getAllRequestorPools()
     */
    public Collection<RequestorPool> getAllRequestorPools() throws RequestorException
    {
        Collection<RequestorPool> collPools = new Vector<RequestorPool>();
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        try
        {
            oConnection = _oDataSource.getConnection();
                        
            oPreparedStatement = oConnection.prepareStatement(_sQuerySelectAllRequestorpools);
            oResultSet = oPreparedStatement.executeQuery();
            while (oResultSet.next())
            {
                JDBCRequestorPool oRequestorPool = new JDBCRequestorPool(oResultSet, _oDataSource, 
                    _sPoolsTable, _sRequestorsTable, _sRequestorPropertiesTable, 
                    _sAuthenticationTable, _sPoolPropertiesTable);
                
                if (oRequestorPool != null)
                    collPools.add(oRequestorPool);
            }
        }
        catch (SQLException e)
        {
            _logger.error("Can not read requestorpools from database", e);
            throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (RequestorException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during retrieving all requestorpools", e);
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
        
        return Collections.unmodifiableCollection(collPools);
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getAllEnabledRequestorPools()
     */
    public Collection<RequestorPool> getAllEnabledRequestorPools()
        throws RequestorException
    {
        Collection<RequestorPool> collPools = new Vector<RequestorPool>();
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        try
        {
            oConnection = _oDataSource.getConnection();
                        
            oPreparedStatement = oConnection.prepareStatement(_sQuerySelectAllEnabledRequestorpools);
            oPreparedStatement.setBoolean(1, true);
            oResultSet = oPreparedStatement.executeQuery();
            while (oResultSet.next())
            {
                JDBCRequestorPool oRequestorPool = new JDBCRequestorPool(oResultSet, _oDataSource, 
                    _sPoolsTable, _sRequestorsTable, _sRequestorPropertiesTable, 
                    _sAuthenticationTable, _sPoolPropertiesTable);
                
                if (oRequestorPool != null)
                    collPools.add(oRequestorPool);
            }
        }
        catch (SQLException e)
        {
            _logger.error("Can not read enabled requestorpools from database", e);
            throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (RequestorException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during retrieving all enabled requestorpools", e);
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
        
        return Collections.unmodifiableCollection(collPools);
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getAllEnabledRequestors()
     */
    public Collection<IRequestor> getAllEnabledRequestors() throws RequestorException
    {
        Collection<IRequestor> collRequestors = new Vector<IRequestor>();
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet rsRequestor = null;
        ResultSet rsProperties = null;
        try
        {
            oConnection = _oDataSource.getConnection();
            
            oPreparedStatement = oConnection.prepareStatement(_sQuerySelectAllEnabledRequestors);
            oPreparedStatement.setBoolean(1, true);
            rsRequestor = oPreparedStatement.executeQuery();
                                   
            while (rsRequestor.next())
            {
                oPreparedStatement = oConnection.prepareStatement(_sQuerySelectRequestorProperties);
                oPreparedStatement.setString(1, rsRequestor.getString(JDBCRequestor.COLUMN_ID));
                rsProperties = oPreparedStatement.executeQuery();
                
                JDBCRequestor oJDBCRequestor = new JDBCRequestor(
                    rsRequestor, rsProperties);
                IRequestor oRequestor = oJDBCRequestor.getRequestor();
                if (oRequestor != null)
                    collRequestors.add(oRequestor);
                
                rsProperties.close();
                
                _logger.debug("Retrieved requestor: " + oRequestor);
            }
        }
        catch (SQLException e)
        {
            _logger.error("Can not read all enabled requestors from database", e);
            throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (RequestorException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during retrieval of all enabled requestors", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (rsRequestor != null)
                    rsRequestor.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close requestor resultset", e);
            }
            
            try
            {
                if (rsProperties != null)
                    rsProperties.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close requestor properties resultset", e);
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
        
        return Collections.unmodifiableCollection(collRequestors);
    }

    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getAllRequestors()
     */
    public Collection<IRequestor> getAllRequestors() throws RequestorException
    {
        Collection<IRequestor> collRequestors = new Vector<IRequestor>();
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet rsRequestor = null;
        ResultSet rsProperties = null;
        try
        {
            oConnection = _oDataSource.getConnection();
            
            oPreparedStatement = oConnection.prepareStatement(_sQuerySelectAllRequestors);
            rsRequestor = oPreparedStatement.executeQuery();
                                   
            while (rsRequestor.next())
            {
                oPreparedStatement = oConnection.prepareStatement(_sQuerySelectRequestorProperties);
                oPreparedStatement.setString(1, rsRequestor.getString(JDBCRequestor.COLUMN_ID));
                rsProperties = oPreparedStatement.executeQuery();
                
                JDBCRequestor oJDBCRequestor = new JDBCRequestor(
                    rsRequestor, rsProperties);
                IRequestor oRequestor = oJDBCRequestor.getRequestor();
                if (oRequestor != null)
                    collRequestors.add(oRequestor);
                
                rsProperties.close();
                
                _logger.debug("Retrieved requestor: " + oRequestor);
            }
        }
        catch (SQLException e)
        {
            _logger.error("Can not read all requestors from database", e);
            throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (RequestorException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during retrieval of all requestors", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (rsRequestor != null)
                    rsRequestor.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close requestor resultset", e);
            }
            
            try
            {
                if (rsProperties != null)
                    rsProperties.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close requestor properties resultset", e);
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
        
        return Collections.unmodifiableCollection(collRequestors);
    }

    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#isRequestor(java.lang.String)
     */
    public boolean isRequestor(String requestorID) throws RequestorException
    {
        boolean bIsRequestor = false;
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        try
        {
            oConnection = _oDataSource.getConnection();
          
            oPreparedStatement = oConnection.prepareStatement(_sQuerySelectRequestorAvailable);
            oPreparedStatement.setString(1, requestorID);
            oResultSet = oPreparedStatement.executeQuery();
            if (oResultSet.next())
                bIsRequestor = true;
        }
        catch (SQLException e)
        {
            _logger.error("Error during database retrieval, when selecting requestor id: " 
                + requestorID, e);
            throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during exist check of requestor id: " 
                + requestorID, e);
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
        return bIsRequestor;
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#getRequestor(java.lang.Object, java.lang.String)
     */
    public IRequestor getRequestor(Object id, String type)
        throws RequestorException
    {
        IRequestor oRequestor = null;
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet rsRequestor = null;
        ResultSet rsProperties = null;
        try
        {
            oConnection = _oDataSource.getConnection();
                        
            StringBuffer sbQuery = new StringBuffer("SELECT * FROM ");
            sbQuery.append(_sRequestorsTable);
            sbQuery.append(" WHERE ");
            sbQuery.append(type);
            sbQuery.append(" =?");
            
            oPreparedStatement = oConnection.prepareStatement(sbQuery.toString());
            oPreparedStatement.setObject(1, id);
            rsRequestor = oPreparedStatement.executeQuery();
            
            if (rsRequestor.next())
            {
                oPreparedStatement = oConnection.prepareStatement(_sQuerySelectRequestorProperties);
                oPreparedStatement.setString(1, rsRequestor.getString(JDBCRequestor.COLUMN_ID));
                rsProperties = oPreparedStatement.executeQuery();
                
                JDBCRequestor oJDBCRequestor = new JDBCRequestor(
                    rsRequestor, rsProperties);
                oRequestor = oJDBCRequestor.getRequestor();
                _logger.debug("Retrieved requestor: " + oRequestor);
            }
            else
                _logger.debug("Requestor not found with alternate ID: " + id);
            
        }
        catch (SQLException e)
        {
            StringBuffer sbError = new StringBuffer("SQL error during database retrieval, when selecting requestor with alternate id '");
            sbError.append(id);
            sbError.append("' of type: ");
            sbError.append(type);
            _logger.error(sbError.toString(), e);
            throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch(Exception e)
        {
            StringBuffer sbError = new StringBuffer("Internal error during database retrieval, when selecting requestor with alternate id '");
            sbError.append(id);
            sbError.append("' of type: ");
            sbError.append(type);
            _logger.fatal(sbError.toString(), e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (rsRequestor != null)
                    rsRequestor.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close requestor resultset", e);
            }
            
            try
            {
                if (rsProperties != null)
                    rsProperties.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close requestor properties resultset", e);
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
        return oRequestor;
    }

    /**
     * @see com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory#isRequestorIDSupported(java.lang.String)
     */
    public boolean isRequestorIDSupported(String type)
        throws RequestorException
    {
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        try
        {
            oConnection = _oDataSource.getConnection();
                        
            StringBuffer sbQuery = new StringBuffer("SELECT ");
            sbQuery.append(type);
            sbQuery.append(" FROM ");
            sbQuery.append(_sRequestorsTable);
            
            oPreparedStatement = oConnection.prepareStatement(sbQuery.toString());
            oResultSet = oPreparedStatement.executeQuery();

            return true;
        }
        catch (SQLException e)
        {
            _logger.debug("Type not available as column: " + type);
            return false;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during retrieving all enabled requestorpools", e);
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
    
    private void createQueries()
    {
        StringBuffer sbSelectPool = new StringBuffer("SELECT ");
        sbSelectPool.append(_sPoolsTable).append(".*");
        sbSelectPool.append(" FROM ");
        sbSelectPool.append(_sRequestorsTable);
        sbSelectPool.append(",");
        sbSelectPool.append(_sPoolsTable);
        sbSelectPool.append(" WHERE ");
        sbSelectPool.append(_sRequestorsTable);
        sbSelectPool.append(".");
        sbSelectPool.append(JDBCRequestor.COLUMN_ID);
        sbSelectPool.append("=? AND ");
        sbSelectPool.append(_sRequestorsTable);
        sbSelectPool.append(".");
        sbSelectPool.append(JDBCRequestor.COLUMN_POOLID);
        sbSelectPool.append("=");
        sbSelectPool.append(_sPoolsTable);
        sbSelectPool.append(".");
        sbSelectPool.append(JDBCRequestorPool.COLUMN_ID);
        _sQuerySelectPool = sbSelectPool.toString();
        _logger.debug("Using requestorpool select query: " + _sQuerySelectPool);
        
        StringBuffer sbSelectRequestor = new StringBuffer("SELECT ");
        sbSelectRequestor.append(_sRequestorsTable).append(".*");
        sbSelectRequestor.append(" FROM ");
        sbSelectRequestor.append(_sRequestorsTable);
        sbSelectRequestor.append(",");
        sbSelectRequestor.append(_sPoolsTable);
        sbSelectRequestor.append(" WHERE ");
        sbSelectRequestor.append(_sRequestorsTable);
        sbSelectRequestor.append(".");
        sbSelectRequestor.append(JDBCRequestor.COLUMN_ID);
        sbSelectRequestor.append("=? AND ");
        sbSelectRequestor.append(_sRequestorsTable);
        sbSelectRequestor.append(".");
        sbSelectRequestor.append(JDBCRequestor.COLUMN_POOLID);
        sbSelectRequestor.append("=");
        sbSelectRequestor.append(_sPoolsTable);
        sbSelectRequestor.append(".");
        sbSelectRequestor.append(JDBCRequestorPool.COLUMN_ID);
        _sQuerySelectRequestor = sbSelectRequestor.toString();
        _logger.debug("Using requestor select query: " + _sQuerySelectRequestor);
                
        StringBuffer sbSelectRequestorProperties = new StringBuffer("SELECT ");
        sbSelectRequestorProperties.append(_sRequestorPropertiesTable).append(".*");
        sbSelectRequestorProperties.append(" FROM ");
        sbSelectRequestorProperties.append(_sRequestorPropertiesTable);            
        sbSelectRequestorProperties.append(" WHERE ");
        sbSelectRequestorProperties.append(_sRequestorPropertiesTable);
        sbSelectRequestorProperties.append(".");
        sbSelectRequestorProperties.append(JDBCRequestor.COLUMN_PROPERTY_REQUESTOR_ID);
        sbSelectRequestorProperties.append("=?");
        _sQuerySelectRequestorProperties = sbSelectRequestorProperties.toString();
        _logger.debug("Using requestor properties select query: " + _sQuerySelectRequestorProperties);
                
        StringBuffer sbSelectPoolAvailable = new StringBuffer("SELECT ");
        sbSelectPoolAvailable.append(JDBCRequestorPool.COLUMN_ID);
        sbSelectPoolAvailable.append(" FROM ");
        sbSelectPoolAvailable.append(_sPoolsTable);
        sbSelectPoolAvailable.append(" WHERE ");
        sbSelectPoolAvailable.append(JDBCRequestorPool.COLUMN_ID);
        sbSelectPoolAvailable.append("=?");
        _sQuerySelectPoolAvailable = sbSelectPoolAvailable.toString();
        _logger.debug("Using requestorpool available select query: " + _sQuerySelectPoolAvailable);
        
        StringBuffer sbSelectRequestorAvailable = new StringBuffer("SELECT ");
        sbSelectRequestorAvailable.append(JDBCRequestor.COLUMN_ID);
        sbSelectRequestorAvailable.append(" FROM ");
        sbSelectRequestorAvailable.append(_sRequestorsTable);
        sbSelectRequestorAvailable.append(" WHERE ");
        sbSelectRequestorAvailable.append(JDBCRequestor.COLUMN_ID);
        sbSelectRequestorAvailable.append("=?");
        _sQuerySelectRequestorAvailable = sbSelectRequestorAvailable.toString();
        _logger.debug("Using requestor available select query: " + _sQuerySelectRequestorAvailable);

        _sQuerySelectAllRequestorpools = "SELECT * FROM " + _sPoolsTable;
        _logger.debug("Using select all requestorpools query: " + _sQuerySelectAllRequestorpools);
        
        StringBuffer sbSelectAllEnabledRequestorpools = new StringBuffer("SELECT * FROM ");
        sbSelectAllEnabledRequestorpools.append(_sPoolsTable);
        sbSelectAllEnabledRequestorpools.append(" WHERE ");
        sbSelectAllEnabledRequestorpools.append(JDBCRequestorPool.COLUMN_ENABLED);
        sbSelectAllEnabledRequestorpools.append(" =? ");
        _sQuerySelectAllEnabledRequestorpools = sbSelectAllEnabledRequestorpools.toString();
        _logger.debug("Using select all enabled requestorpools query: " + _sQuerySelectAllEnabledRequestorpools);
        
        _sQuerySelectAllRequestors = "SELECT * FROM " + _sRequestorsTable;
        _logger.debug("Using select all requestors query: " + _sQuerySelectAllRequestors);
        
        StringBuffer sbSelectAllEnabledRequestors = new StringBuffer("SELECT * FROM ");
        sbSelectAllEnabledRequestors.append(_sRequestorsTable);
        sbSelectAllEnabledRequestors.append(" WHERE ");
        sbSelectAllEnabledRequestors.append(JDBCRequestor.COLUMN_ENABLED);
        sbSelectAllEnabledRequestors.append(" =? ");
        _sQuerySelectAllEnabledRequestors = sbSelectAllEnabledRequestors.toString();
        _logger.debug("Using select all enabled requestors query: " + _sQuerySelectAllEnabledRequestors);
    }

}