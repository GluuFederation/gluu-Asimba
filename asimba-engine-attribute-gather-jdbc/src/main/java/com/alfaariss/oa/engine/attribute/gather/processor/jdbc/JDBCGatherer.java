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
package com.alfaariss.oa.engine.attribute.gather.processor.jdbc;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.attribute.AttributeException;
import com.alfaariss.oa.engine.core.attribute.gather.processor.IProcessor;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;

/**
 * Attribute gatherer that resolves attributes from JDBC storage.
 *
 * Reads attributes from a JDBC storage.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class JDBCGatherer implements IProcessor 
{
    private static final Log _logger = LogFactory.getLog(JDBCGatherer.class);;
    private boolean _bEnabled;
    private String _sID;
    private String _sFriendlyName;
    
    private DataSource _oDataSource;
    private String _sSelectQuery;
    private final Hashtable<String, String> _htMapper;
    private final List<String> _listGather;
    
    /**
     * Creates the object.
     */
    public JDBCGatherer()
    {
        _sID = null;
        _sFriendlyName = null;
        _bEnabled = false;
        _htMapper = new Hashtable<String, String>();
        _listGather = new Vector<String>();
    }

    /**
     * Starts the object.
     * <br>
     * Reads its configuration and tests the JDBC connection.
     * @see IProcessor#start(IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws AttributeException
    {
        try
        {
            _bEnabled = true;
            String sEnabled = oConfigurationManager.getParam(eConfig, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    _bEnabled = false;
                else if (!sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _logger.error("Unknown value in 'enabled' configuration item: " 
                        + sEnabled);
                    throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            if (!_bEnabled)
                return; //object is disabled, so why should I bother to load its configuration?
            
            _sID = oConfigurationManager.getParam(eConfig, "id");
            if (_sID == null)
            {
                _logger.error("No 'id' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            _sFriendlyName = oConfigurationManager.getParam(eConfig, "friendlyname");
            if (_sFriendlyName == null)
            {
                _logger.error("No 'friendlyname' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eResource = oConfigurationManager.getSection(eConfig, "resource");
            if (eResource == null)
            {
                _logger.error("No 'resource' section found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _oDataSource = DataSourceFactory.createDataSource(oConfigurationManager, eResource);
            
            _sSelectQuery = oConfigurationManager.getParam(eResource, "query");
            if (_sSelectQuery == null)
            {
                Element eTable = oConfigurationManager.getSection(eResource, "table");
                if(eTable == null)
                {
                    _logger.error("No 'table' section found in 'resource' section");
                    throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                String sTableName = oConfigurationManager.getParam(eTable, "name");
                if(sTableName == null)
                {
                    _logger.error("No 'name' item found in 'table' section");
                    throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                Element eColumn = oConfigurationManager.getSection(eTable, "column");
                if(eColumn == null)
                {
                    _logger.error("No 'column' section found in 'table' section");
                    throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                String sColumnUserId = oConfigurationManager.getParam(eColumn, "userid");
                if(sColumnUserId == null)
                {
                    _logger.error("No 'userid' item found in 'column' section");
                    throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                Element eGather = oConfigurationManager.getSection(eConfig, "gather");
                if (eGather == null)
                    _logger.info("No optional 'gather' section found in configuration");
                else
                {
                    Element eAttribute = oConfigurationManager.getSection(eGather, "attribute");
                    while (eAttribute != null)
                    {
                        String sName = oConfigurationManager.getParam(eAttribute, "name");
                        if (sName == null)
                        {
                            _logger.error("No 'name' item found in 'attribute' section");
                            throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                        }
                        
                        if (sName.trim().length() == 0)
                        {
                            _logger.error("Empty 'name' item found in 'attribute' section");
                            throw new AttributeException(SystemErrors.ERROR_INIT);
                        }
                        
                        if (_listGather.contains(sName))
                        {
                            _logger.error("Attribute name not unique: " + sName);
                            throw new AttributeException(SystemErrors.ERROR_INIT);
                        }
                        
                        _listGather.add(sName);
                        
                        eAttribute = oConfigurationManager.getNextSection(eAttribute);
                    }
                    
                    _logger.info("Configured to gather only the following subset: " 
                        + _listGather.toString());
                }
            
                StringBuffer sbSelectQuery = new StringBuffer("SELECT ");
                
                if (_listGather.size() == 0)
                    sbSelectQuery.append("*");
                else
                {
                    StringBuffer sbSelect = new StringBuffer();
                    for (String sAttribName: _listGather)
                    {
                        if (sbSelect.length() > 0)
                            sbSelect.append(",");
                        sbSelect.append(sAttribName);
                    }
                    sbSelectQuery.append(sbSelect);
                }
                sbSelectQuery.append(" FROM ");
                sbSelectQuery.append(sTableName);
                sbSelectQuery.append(" WHERE UPPER(");
                sbSelectQuery.append(sColumnUserId);
                sbSelectQuery.append(")=UPPER(?)");
                _sSelectQuery = sbSelectQuery.toString();
            }
            _logger.info("Using query: " + _sSelectQuery);
            
            Element eMapper = oConfigurationManager.getSection(eConfig, "mapper");
            if (eMapper == null)
                _logger.info("No optional 'mapper' section found in configuration");
            else
            {
                Element eMap = oConfigurationManager.getSection(eMapper, "map");
                while (eMap != null)
                {
                    String sExt = oConfigurationManager.getParam(eMap, "ext");
                    if (sExt == null)
                    {
                        _logger.error("No 'ext' item found in 'map' section");
                        throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    String sInt = oConfigurationManager.getParam(eMap, "int");
                    if (sInt == null)
                    {
                        _logger.error("No 'int' item found in 'map' section");
                        throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    if (_htMapper.containsKey(sExt))
                    {
                        _logger.error("Ext name not unique in map with 'ext' value: " 
                            + sExt);
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    if (_htMapper.contains(sInt))
                    {
                        _logger.error("Int name not unique in map with 'int' value: " 
                            + sInt);
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    _htMapper.put(sExt, sInt);
                    
                    eMap = oConfigurationManager.getNextSection(eMap);
                }
            }
            
            _logger.info("Started: JDBC Attribute Gatherer");
        }
        catch (AttributeException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not initialize object", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Gathers attributes from JDBC storage to the supplied attributes object.
     * @see com.alfaariss.oa.engine.core.attribute.gather.processor.IProcessor#process(java.lang.String, com.alfaariss.oa.api.attribute.IAttributes)
     */
    @Override
    public void process(String sUserId, IAttributes oAttributes) 
        throws AttributeException
    {
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        Connection oConnection = null;
        try
        {
            oConnection = _oDataSource.getConnection();
            oPreparedStatement = oConnection.prepareStatement(_sSelectQuery);
            oPreparedStatement.setString(1, sUserId);
            oResultSet = oPreparedStatement.executeQuery();
            if (oResultSet.next())
            {
                ResultSetMetaData oResultSetMetaData = oResultSet.getMetaData();
                int iCount = oResultSetMetaData.getColumnCount();
                for (int i = 1; i <= iCount; i++)
                {
                    String sName = oResultSetMetaData.getColumnName(i);
                    Object oValue = oResultSet.getObject(sName);
                    
                    String sMappedName = _htMapper.get(sName);
                    if (sMappedName != null) 
                        sName = sMappedName;
                    
                    if (oValue == null) 
                        oValue = "";
                    
                    oAttributes.put(sName, oValue);
                }
            }
        }
        catch (SQLException e)
        {
            _logger.error("Could not gather attributes for user with id: " + sUserId, e);
            throw new AttributeException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch(Exception e)
        {
            _logger.fatal("Could not initialize object", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
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
                _logger.error("Could not disconnect prepared statement", e);
            }
        }
    }

    /**
     * Stops the object.
     * @see com.alfaariss.oa.engine.core.attribute.gather.processor.IProcessor#stop()
     */
    @Override
    public void stop()
    {
        if (_htMapper != null)
            _htMapper.clear();
        if (_listGather != null)
            _listGather.clear();
    }

    /**
     * Returns the gatherer id.
     * @see com.alfaariss.oa.api.IManagebleItem#getID()
     */
    @Override
    public String getID()
    {
        return _sID;
    }

    /**
     * Returns the gatherer friendly name.
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    @Override
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }

    /**
     * Returns TRUE if the gatherer is enabled.
     * @see com.alfaariss.oa.api.IManagebleItem#isEnabled()
     */
    @Override
    public boolean isEnabled()
    {
        return _bEnabled;
    }

}