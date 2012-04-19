/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2011 Alfa & Ariss B.V.
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
package com.alfaariss.oa.engine.storage.jdbc;

import java.sql.Connection;
import java.sql.SQLException;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.datastorage.IDataStorageFactory;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;

/**
 * The default internal jdbc store.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.5
 */
public class JDBCFactory implements IComponent, IDataStorageFactory
{
    private Log _logger;
    private IConfigurationManager _configurationManager;
    private boolean _bEnabled;
    private DataSource _dsModel;
    private DataSource _dsSystem;

    /**
     * Constructor creates the object.
     */
    public JDBCFactory()
    {
        _logger = LogFactory.getLog(JDBCFactory.class);
        _bEnabled = false;
        _dsModel = null;
        _dsSystem = null;
    }
    
    /**
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
     * @see com.alfaariss.oa.api.IComponent#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager configurationManager, Element config)
        throws OAException
    {
        Connection conModel = null;
        Connection conSystem = null;
        try
        {
            _configurationManager = configurationManager;
            
            _bEnabled = true;
            String sEnabled = _configurationManager.getParam(config, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    _bEnabled = false;
                else if (!sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _logger.error("Unknown value in 'enabled' configuration item: " 
                        + sEnabled);
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            if (_bEnabled)
            {
                Element eModel = _configurationManager.getSection(config, "model");
                if (eModel == null)
                {
                    _logger.info("No optional 'model' section found in configuration, disabling global model store");
                }
                else
                {
                    _dsModel = DataSourceFactory.createDataSource(_configurationManager, eModel);
                    
                    try
                    {
                        conModel = _dsModel.getConnection();
                    }
                    catch (SQLException e)
                    {
                        _logger.error("Could not connect to model resource", e);
                        throw new OAException(SystemErrors.ERROR_INIT);
                    }
                }
                
                Element eSystem = _configurationManager.getSection(config, "system");
                if (eSystem == null)
                {
                    _logger.info("No optional 'system' section found in configuration, disabling global system store");
                }
                else
                {
                    _dsSystem = DataSourceFactory.createDataSource(_configurationManager, eSystem);
                    
                    try
                    {
                        conSystem = _dsSystem.getConnection();
                    }
                    catch (SQLException e)
                    {
                        _logger.error("Could not connect to system resource", e);
                        throw new OAException(SystemErrors.ERROR_INIT);
                    }
                }
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (conModel != null)
                    conModel.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close model connection", e);
            }
            
            try
            {
                if (conSystem != null)
                    conSystem.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close system connection", e);
            }
        }
    }

    /**
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    public void stop()
    {
        _bEnabled = false;
        _dsSystem = null;
        _dsModel = null;
    }
    
    /**
     * @see com.alfaariss.oa.api.IOptional#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }

    /**
     * @see com.alfaariss.oa.api.datastorage.IDataStorageFactory#createModelDatasource()
     */
    public DataSource createModelDatasource() throws OAException
    {
        return _dsModel;
    }
    
    /**
     * @see com.alfaariss.oa.api.datastorage.IDataStorageFactory#createSystemDatasource()
     */
    public DataSource createSystemDatasource() throws OAException
    {
        return _dsSystem;
    }
}
