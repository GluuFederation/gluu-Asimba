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
package com.alfaariss.oa.engine.user.provisioning.storage.external.jdbc;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Hashtable;
import java.util.List;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.engine.user.provisioning.storage.IStorage;
import com.alfaariss.oa.engine.user.provisioning.storage.external.IExternalStorage;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;

/**
 * JDBC external storage object.
 * <br>
 * Uses the configured JDBC storage as external storage.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class JDBCExternalStorage implements IExternalStorage
{
    private String _sSelectQuery;
    private Log _logger;
    private DataSource _oDataSource;
    
    private String _sTableName;
    private String _sColumnUserId;
    
	/**
	 * Creates the object.
	 */
	public JDBCExternalStorage()
    {
        _logger = LogFactory.getLog(JDBCExternalStorage.class);
        _sTableName = "";
        _sColumnUserId = "";
	}
    
    /**
     * Starts the object.
     * <br>
     * Reads the configuration and checks the connection.
     * @see IStorage#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws UserException
    {
        try
        {
            Element eResource = oConfigurationManager.getSection(
                eConfig, "resource");
            if (eResource == null)
            {
                _logger.error(
                    "No 'resource' section found in 'externalstorage' section");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _oDataSource = DataSourceFactory.createDataSource(oConfigurationManager, eResource);
                        
            Element eTable = oConfigurationManager.getSection(eResource, "table");
            if(eTable == null)
            {
                _logger.error("No 'table' section found in 'resource' section");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _sTableName = oConfigurationManager.getParam(eTable, "name");
            if(_sTableName == null)
            {
                _logger.error("No 'name' item found in 'table' section");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eColumn = oConfigurationManager.getSection(eTable, "column");
            if(eColumn == null)
            {
                _logger.error("No 'column' section found in 'table' section");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _sColumnUserId = oConfigurationManager.getParam(eColumn, "userid");
            if(_sColumnUserId == null)
            {
                _logger.error("No 'userid' item found in 'column' section");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            StringBuffer sbSelectQuery = new StringBuffer("SELECT ");
            sbSelectQuery.append(_sColumnUserId).append(" FROM ");
            sbSelectQuery.append(_sTableName);
            sbSelectQuery.append(" WHERE ");
            sbSelectQuery.append(_sColumnUserId);
            sbSelectQuery.append("=?");
            _sSelectQuery = sbSelectQuery.toString();
        }
        catch (UserException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not initialize object", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
        }
	}
    
    /**
     * Verifies whether the supplied id exists.
     * <br>
     * Returns <code>true</code> if the id exists in the storage.
     * @see IStorage#exists(java.lang.String)
     */
    public boolean exists(String sID) throws UserException
    {
        boolean bReturn = false;
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        
        try
        {
            oConnection = _oDataSource.getConnection();
            oPreparedStatement = oConnection.prepareStatement(_sSelectQuery);
            oPreparedStatement.setString(1, sID);
            oResultSet = oPreparedStatement.executeQuery();
            if (oResultSet.next())
                bReturn = true;
        }
        catch (SQLException e)
        {
            _logger.error("Could not verify if user exists with id: " + sID, e);
            throw new UserException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
        }
        catch (Exception e)
        {
            _logger.fatal("Could not verify if user exists with id: " + sID, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
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
        
        return bReturn;
    }
    
	/**
	 * Returns the value of the supplied field for the supplied id.
	 * @see IExternalStorage#getField(java.lang.String, java.lang.String)
	 */
	public Object getField(String id, String field) throws UserException
    {
        Object oValue = null;
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        
        try
        {
            StringBuffer sbQuery = new StringBuffer("SELECT ");
            sbQuery.append(field);
            sbQuery.append(" FROM ");
            sbQuery.append(_sTableName);
            sbQuery.append(" WHERE ");
            sbQuery.append(_sColumnUserId);
            sbQuery.append("=?");
            
            oConnection = _oDataSource.getConnection();
            oPreparedStatement = oConnection.prepareStatement(sbQuery.toString());
            oPreparedStatement.setString(1, id);
            oResultSet = oPreparedStatement.executeQuery();
            
            if (oResultSet.next())
                oValue = oResultSet.getObject(field);
        }
        catch (SQLException e)
        {
            StringBuffer sbError = new StringBuffer(
                "Could not retrieve field with name '");
            sbError.append(field);
            sbError.append("' for id: ");
            sbError.append(id);
            _logger.error(sbError.toString(), e);
            throw new UserException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer(
                "Could not retrieve field with name '");
            sbError.append(field);
            sbError.append("' for id: ");
            sbError.append(id);
            _logger.fatal(sbError.toString(), e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
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
        
		return oValue;
	}
    
    /**
     * Returns the values of the supplied fields for the supplied id.
     * @see IExternalStorage#getFields(java.lang.String, java.util.List)
     */
    public Hashtable<String, Object> getFields(String id, List<String> fields) 
        throws UserException
    {
        Hashtable<String, Object> htReturn = new Hashtable<String, Object>();
        
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        
        try
        {
            if (fields.size() == 0)
            {
                _logger.debug("No fields requested for id: " + id);
                return htReturn;
            }
            
            StringBuffer sbFields = new StringBuffer();
            
            for (String sField: fields)
            {
                if (sbFields.length() > 0)
                    sbFields.append(",");
                sbFields.append(sField);
            }
            
            StringBuffer sbQuery = new StringBuffer("SELECT ");
            sbQuery.append(sbFields);
            sbQuery.append(" FROM ");
            sbQuery.append(_sTableName);
            sbQuery.append(" WHERE ");
            sbQuery.append(_sColumnUserId);
            sbQuery.append("=?");
            
            oConnection = _oDataSource.getConnection();
            oPreparedStatement = oConnection.prepareStatement(sbQuery.toString());
            oPreparedStatement.setString(1, id);
            oResultSet = oPreparedStatement.executeQuery();
            if (!oResultSet.next())
            {
                _logger.error("No result with query: " + sbQuery.toString());
                throw new UserException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }
            
            for (String sField: fields)
            { 
                Object oValue = oResultSet.getObject(sField);
                if (oValue != null)
                    htReturn.put(sField, oValue);
            }
        }
        catch (UserException e)
        {
            throw e;
        }
        catch (SQLException e)
        {
            StringBuffer sbError = new StringBuffer(
                "Could not retrieve fields with names '");
            sbError.append(fields.toString());
            sbError.append("' for id: ");
            sbError.append(id);
            _logger.error(sbError.toString(), e);
            throw new UserException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer(
                "Could not retrieve fields with names '");
            sbError.append(fields.toString());
            sbError.append("' for id: ");
            sbError.append(id);
            
            _logger.fatal(sbError.toString(), e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
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
        
        return htReturn;
    }
    
    /**
     * Stops the object by closing the JDBC manager.
     * @see com.alfaariss.oa.engine.user.provisioning.storage.IStorage#stop()
     */
    public void stop()
    {
        //do nothing yet
    }

}