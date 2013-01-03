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
package com.alfaariss.oa.sso.web.profile.ssoquery.whitelist.jdbc;

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
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.datastorage.IDataStorageFactory;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.sso.web.profile.ssoquery.whitelist.IWhitelist;
import com.alfaariss.oa.util.database.DatabaseException;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;

/**
 * Whitelist implementation that uses the JDBC as storage.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class JDBCWhitelist implements IWhitelist
{
    private static Log _logger;
    
    private final static String TABLE = "ssoquery_whitelist";
    private final static String COLUMN_ITEM = "item";
    
    private DataSource _dataSource;
    private String _querySelectItem;
    
    /**
     * Constructor. 
     */
    public JDBCWhitelist()
    {
        _logger = LogFactory.getLog(this.getClass());
        _dataSource = null;
    }
    
	/**
	 * @see com.alfaariss.oa.sso.web.profile.ssoquery.whitelist.IWhitelist#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
	 */
	public void start(IConfigurationManager configurationManager, Element config)
			throws OAException 
	{
	    Connection oConnection = null;
        try
        {
            Element eResource = configurationManager.getSection(config, "resource");
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
                    _dataSource = DataSourceFactory.createDataSource(configurationManager, eResource);
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
            
            String sTable = TABLE;
            if (eResource != null)
            {
                Element eTable = configurationManager.getSection(eResource, "table");
                if (eTable != null)
                {
                    sTable = configurationManager.getParam(eTable, "name");
                    if (sTable != null)
                    {
                        _logger.error("No 'name' parameter found in 'table' section in configuration");
                        throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    _logger.info("Using configured whitelist table: " + sTable);
                }
            }
            
            StringBuffer sbQuery = new StringBuffer("SELECT ");
            sbQuery.append(COLUMN_ITEM);
            sbQuery.append(" FROM ");
            sbQuery.append(sTable);
            sbQuery.append(" WHERE ");
            sbQuery.append(COLUMN_ITEM);
            sbQuery.append("=?");
            
            _querySelectItem = sbQuery.toString();
            _logger.info("Using item selection query: " + _querySelectItem);
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
	 * @see com.alfaariss.oa.sso.web.profile.ssoquery.whitelist.IWhitelist#isWhitelisted(java.lang.String)
	 */
	public boolean isWhitelisted(String item) throws OAException 
	{
	    Connection connection = null;
        PreparedStatement pSelect = null;
        ResultSet resultSet = null;
        try
        {
            connection = _dataSource.getConnection();
            
            pSelect = connection.prepareStatement(_querySelectItem);
            pSelect.setString(1, item);
            resultSet = pSelect.executeQuery();
            if (resultSet.next())
            {
                return true;
            }
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during exist check for item: " + item, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (pSelect != null)
                    pSelect.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close select statement", e);
            }
                        
            try
            {
                if (connection != null)
                    connection.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close connection", e);
            }
        }
        return false;
	}

	/**
	 * @see com.alfaariss.oa.sso.web.profile.ssoquery.whitelist.IWhitelist#stop()
	 */
	public void stop() 
	{
		//do nothing
	}

}
