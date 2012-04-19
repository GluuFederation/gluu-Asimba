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
package com.alfaariss.oa.util.idmapper.jdbc;


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
import com.alfaariss.oa.api.idmapper.IIDMapper;
import com.alfaariss.oa.util.database.DatabaseException;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;

/**
 * JDBC User id mapper.
 * <br>
 * Example mapping table:
 * <pre>
 * CREATE TABLE `mappingtable` (              
 * `id` varchar(100) NOT NULL,          
 * `mapping` varchar(100) NOT NULL,
 *  PRIMARY KEY  (`id`,`mapping`)       
 * ) ENGINE=InnoDB DEFAULT CHARSET=utf8  
 * </pre>
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class JDBCMapper implements IIDMapper
{
    private Log _logger;
    private DataSource _oDataSource;
    private String _sSelectUser;
    private String _sSelectMapped;
        
    /**
     * Constructor.
     */
    public JDBCMapper()
    {
        _logger = LogFactory.getLog(JDBCMapper.class);
        _sSelectUser = null;
        _sSelectMapped = null;
    }
    /**
     * @see IIDMapper#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigManager, Element eConfig) 
        throws OAException
    {
        Connection oConnection = null;
        PreparedStatement pTable = null;
        PreparedStatement pVerifyMap = null;
        PreparedStatement pVerifyRemap = null;
        try
        {
            Element eResource = oConfigManager.getSection(eConfig, "resource");
            if (eResource == null)
            {
                _logger.error("No 'resource' section found in configuration");
                throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
            }
            _oDataSource = DataSourceFactory.createDataSource(oConfigManager, eResource);
            
            Element eQueries = oConfigManager.getSection(eResource, "queries");
            if (eQueries != null)
            {
                _sSelectMapped = oConfigManager.getParam(eQueries, "map");
                _sSelectUser = oConfigManager.getParam(eQueries, "remap");
            }
            
            if (_sSelectUser == null && _sSelectMapped == null)
            {
                Element eTable = oConfigManager.getSection(eResource, "table");
                if (eTable == null)
                {
                    _logger.error("No 'table' section found in configuration");
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                String sTableName = oConfigManager.getParam(eTable, "name");
                if (sTableName == null)
                {
                    _logger.error("No 'name' item in 'table' section found in configuration");
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
                            
                Element eId = oConfigManager.getSection(eTable, "id");
                if (eId == null)
                {
                    _logger.error("No 'id' section found in configuration");
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                String sUserIDColumn = oConfigManager.getParam(eId, "column");
                if (sUserIDColumn == null)
                {
                    _logger.error("No 'column' item in 'id' section found in configuration");
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                Element eMapper = oConfigManager.getSection(eTable, "mapper");
                if (eMapper == null)
                {
                    _logger.error("No 'mapper' section found in configuration");
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                String sMapperIDColumn = oConfigManager.getParam(eMapper, "column");
                if (sMapperIDColumn == null)
                {
                    _logger.error("No 'column' item in 'mapper' section found in configuration");
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                StringBuffer sbSelectMapped = new StringBuffer("SELECT ");
                sbSelectMapped.append(sMapperIDColumn);
                sbSelectMapped.append(" FROM ");
                sbSelectMapped.append(sTableName);
                sbSelectMapped.append(" WHERE UPPER(");
                sbSelectMapped.append(sUserIDColumn);
                sbSelectMapped.append(")=UPPER(?)");
                _sSelectMapped = sbSelectMapped.toString();
                
                StringBuffer sbSelectUser = new StringBuffer("SELECT ");
                sbSelectUser.append(sUserIDColumn);
                sbSelectUser.append(" FROM ");
                sbSelectUser.append(sTableName);
                sbSelectUser.append(" WHERE UPPER(");
                sbSelectUser.append(sMapperIDColumn);
                sbSelectUser.append(")=UPPER(?)");
                _sSelectUser = sbSelectUser.toString();
            }
            
            try
            {
                oConnection = _oDataSource.getConnection();
            }
            catch (SQLException e)
            {
                _logger.error("Could not connect to resource", e);
                throw new DatabaseException(SystemErrors.ERROR_INIT);
            }
            
            pVerifyMap = oConnection.prepareStatement(_sSelectMapped);
            pVerifyMap.setString(1, "test_user");
            try
            {
                pVerifyMap.executeQuery();
            }
            catch(Exception e)
            {
                _logger.error("Invalid map query: " + _sSelectMapped);
                throw new DatabaseException(SystemErrors.ERROR_INIT);
            }
            
            _logger.debug("Using map query: " + _sSelectMapped);
            
            pVerifyRemap = oConnection.prepareStatement(_sSelectUser);
            pVerifyRemap.setString(1, "test_user");
            try
            {
                pVerifyRemap.executeQuery();
            }
            catch(Exception e)
            {
                _logger.error("Invalid remap query: " + _sSelectUser);
                throw new DatabaseException(SystemErrors.ERROR_INIT);
            }
            
            _logger.debug("Using remap query: " + _sSelectUser);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during object creation", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        } 
        finally
        {
            try
            {
                if (pTable != null)
                    pTable.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close statement", e);
            }
            
            try
            {
                if (pVerifyMap != null)
                    pVerifyMap.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close map statement", e);
            }
            
            try
            {
                if (pVerifyRemap != null)
                    pVerifyRemap.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close remap statement", e);
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

    /**
     * @see IIDMapper#map(java.lang.String)
     */
    public String map(String sUserID) throws OAException
    {
        String sReturn = null;
        Connection oConnection = null;
        PreparedStatement psSelect = null;
        ResultSet rsSelect = null;
        
        try
        {
            oConnection = _oDataSource.getConnection();
            psSelect = oConnection.prepareStatement(_sSelectMapped);
            psSelect.setString(1, sUserID);
            rsSelect = psSelect.executeQuery();
            if(rsSelect.next())
                sReturn = rsSelect.getString(1);
        }
        catch (Exception e)
        {
            _logger.error("Internal error while mapping id: " + sUserID, e);
            throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }       
        finally
        {  
            try
            {
                if (rsSelect != null)
                    rsSelect.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close resultset", e);
            }
            
            try
            {
                if (psSelect != null)
                    psSelect.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close statement", e);
            } 
            try
            {
                if (oConnection != null)
                    oConnection.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close connection", e);
            }            
        }
        
        return sReturn;
    }
    
    /**
     * @see IIDMapper#remap(java.lang.String)
     */
    public String remap(String sMappedUserID) throws OAException
    {
        String sReturn = null;
        Connection oConnection = null;
        PreparedStatement psSelect = null;
        ResultSet rsSelect = null;
        
        try
        {
            oConnection = _oDataSource.getConnection();
            psSelect = oConnection.prepareStatement(_sSelectUser);
            psSelect.setString(1, sMappedUserID);
            rsSelect = psSelect.executeQuery();
            if(rsSelect.next())
                sReturn = rsSelect.getString(1);
        }
        catch (Exception e)
        {
            _logger.error("Internal error while remapping id: " + sMappedUserID, e);
            throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }       
        finally
        {    
            try
            {
                if (rsSelect != null)
                    rsSelect.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close resultset", e);
            }
            try
            {
                if (psSelect != null)
                    psSelect.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close statement", e);
            } 
            try
            {
                if (oConnection != null)
                    oConnection.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close connection", e);
            }            
        }
        
        return sReturn;
    }

    /**
     * @see IIDMapper#stop()
     */
    public void stop()
    {
        //do nothing
    }
}
