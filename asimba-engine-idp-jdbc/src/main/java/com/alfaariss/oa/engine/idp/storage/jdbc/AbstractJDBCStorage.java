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
package com.alfaariss.oa.engine.idp.storage.jdbc;

import java.sql.Connection;
import java.sql.SQLException;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.datastorage.IDataStorageFactory;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.engine.core.idp.storage.IIDPStorage;
import com.alfaariss.oa.util.database.DatabaseException;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;

/**
 * IDP Storage implementation using JDBC.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @param <IDP> type of IDP.
 * @since 1.4
 */
abstract public class AbstractJDBCStorage<IDP extends IIDP> implements IIDPStorage
{
    /** System logger */
    protected static Log _logger;
    /** Datasource */
    protected DataSource _dataSource;

    /**
     * Constructor. 
     */
    public AbstractJDBCStorage()
    {
        _logger = LogFactory.getLog(this.getClass());
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager configManager, Element config)
        throws OAException
    {
        Connection oConnection = null;
        try
        {
            Element eResource = configManager.getSection(config, "resource");
            if (eResource == null)
            {
                IDataStorageFactory databaseFactory = Engine.getInstance().getStorageFactory();
                if (databaseFactory != null && databaseFactory.isEnabled())
                {
                    _dataSource = databaseFactory.createModelDatasource();
                    if (_dataSource == null)
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
                    _dataSource = DataSourceFactory.createDataSource(configManager, eResource);
                    _logger.info("Using datasource specified in 'resource' section in configuration");
                }
                catch (DatabaseException e)
                {
                    IDataStorageFactory databaseFactory = Engine.getInstance().getStorageFactory();
                    if (databaseFactory != null && databaseFactory.isEnabled())
                    {
                        _dataSource = databaseFactory.createModelDatasource();
                        if (_dataSource == null)
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
                oConnection = _dataSource.getConnection();
            }
            catch (SQLException e)
            {
                _logger.error("Could not connect to resource", e);
                throw new DatabaseException(SystemErrors.ERROR_INIT);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during start", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
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
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#stop()
     */
    public void stop()
    {
        _dataSource = null;
    }

}
