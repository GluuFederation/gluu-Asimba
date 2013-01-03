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
package com.alfaariss.oa.engine.tgt.jdbc;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.tgt.TGTException;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.util.database.DatabaseException;

/**
 * Stores TGT aliasses in a JDBC database.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class JDBCTGTAliasStore implements ITGTAliasStore
{
    private final static String ALIAS_STORE_TABLE_NAME_PREFIX = "alias_store_";
    private final static String ALIAS_STORE_COLUMN_TGT_ID = "tgt_id";
    private final static String ALIAS_STORE_COLUMN_ENTITY_ID_POSTFIX = "_id";
    
    private String _sTGTTableName;
    private String _sTGTColumnID;
    
    private String _sAliasTableName;
    private String _sAliasColumnTGTID;
    private String _sAliasColumnEntityID;
    
    private String _sAliasQueryRemoveExpired;
    private String _sAliasQueryRowExists;
    private String _sAliasQueryDelete;
    private String _sAliasQueryDeleteAll;
   
    //The JDBC manager 
    private DataSource _oDataSource;
    //The system logger
    private Log _logger;
    
    private String _sID;
       
	/**
     * Create a new <code>JDBCTGTAliasStore</code>.
	 * @param configurationManager The configuration manager.
	 * @param config The configuration section for this object.
	 * @param dataSource The datasource to be used.
	 * @param sTGTTableName TGT table name
	 * @param sTGTColumnID TGT id column name
	 * @throws OAException If invalid configuration is supplied.
     */
    public JDBCTGTAliasStore(IConfigurationManager configurationManager, 
        Element config, DataSource dataSource, String sTGTTableName, 
        String sTGTColumnID) throws OAException
    {
        _logger = LogFactory.getLog(JDBCTGTAliasStore.class);
        _oDataSource = dataSource;
        _sTGTTableName = sTGTTableName;
        _sTGTColumnID = sTGTColumnID;
                
        _sID = configurationManager.getParam(config, "id");
        if (_sID == null)
        {
            _logger.error("No 'id' parameter in alias store section in configuration");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        boolean bIsAliasSupportEnabled = false;
        String sEnabled = configurationManager.getParam(config, "enabled");
        if (sEnabled != null)
        {
            if (sEnabled.equalsIgnoreCase("TRUE"))
                bIsAliasSupportEnabled = true;
            else if (!sEnabled.equalsIgnoreCase("FALSE"))
            {
                _logger.error("Unknown value in 'enabled' configuration item: " 
                    + sEnabled);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        
        if (bIsAliasSupportEnabled)
        {
            createAliasQueries(configurationManager, config);
            verifyAliasTableConfig(configurationManager, config);
        }
        
        StringBuffer sbInfo = new StringBuffer("Alias store '");
        sbInfo.append(_sID);
        sbInfo.append("' : ");
        sbInfo.append(bIsAliasSupportEnabled ? "enabled" : "disabled");
        _logger.info(sbInfo.toString());
    }
     
	/**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore#putAlias(java.lang.String, java.lang.String, java.lang.String, java.lang.String)
     */
    public void putAlias(String type, String requestorID, String tgtID,
        String alias) throws OAException
    {
        Connection connection = null;
        PreparedStatement psSelect = null;
        ResultSet rsSelect = null;

        try
        {
            connection = _oDataSource.getConnection();
            psSelect = connection.prepareStatement(_sAliasQueryRowExists);
            psSelect.setString(1, tgtID);
            psSelect.setString(2, requestorID);
            
            rsSelect = psSelect.executeQuery();
            if (rsSelect.next())
                update(connection, tgtID, requestorID, type, alias);
            else
                insert(connection, tgtID, requestorID, type, alias);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute query: " + _sAliasQueryRowExists, e);
            throw new OAException(SystemErrors.ERROR_RESOURCE_INSERT);
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer("Internal error during insert of alias '");
            sbError.append(alias);
            sbError.append("' in column '");
            sbError.append(type);
            sbError.append("' for requestor id '");
            sbError.append(requestorID);
            sbError.append("' and TGT id: ");
            sbError.append(tgtID);
            _logger.error(sbError.toString(), e);
            throw new OAException(SystemErrors.ERROR_RESOURCE_INSERT);
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
                if (connection != null)
                    connection.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close connection", e);
            }            
        }
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore#getAlias(java.lang.String, java.lang.String, java.lang.String)
     */
    public String getAlias(String type, String requestorID, String tgtID)
        throws OAException
    {
        String sAlias = null;
        Connection connection = null;
        PreparedStatement psSelect = null;
        ResultSet rsSelect = null;
        StringBuffer sbQuerySearchTransient = null;

        try
        {
            sbQuerySearchTransient = new StringBuffer("SELECT ");
            sbQuerySearchTransient.append(type);
            sbQuerySearchTransient.append(" FROM ").append(_sAliasTableName);
            sbQuerySearchTransient.append(" WHERE ").append(_sAliasColumnTGTID).append("=?");
            sbQuerySearchTransient.append(" AND ").append(_sAliasColumnEntityID).append("=?");
            
            connection = _oDataSource.getConnection();
            psSelect = connection.prepareStatement(
                sbQuerySearchTransient.toString());
            psSelect.setString(1, tgtID);
            psSelect.setString(2, requestorID);
            rsSelect = psSelect.executeQuery();
            if(rsSelect.next())
            {
                sAlias = rsSelect.getString(type);
            }
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute select query: " 
                + sbQuerySearchTransient.toString(), e);
            throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer(
                "Internal error during retrieval of value from column '");
            sbError.append(type);
            sbError.append("' for requestor with id: ");
            sbError.append(requestorID);
            _logger.error(sbError.toString(), e);
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
                if (connection != null)
                    connection.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close connection", e);
            }            
        }
        return sAlias;
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore#getTGTID(java.lang.String, java.lang.String, java.lang.String)
     */
    public String getTGTID(String type, String requestorID, String alias)
        throws OAException
    {
        
        String sTGTID = null;
        Connection connection = null;
        PreparedStatement psSelect = null;
        ResultSet rsSelect = null;
        StringBuffer sbQuerySearch = null;
    
        try
        {
            sbQuerySearch = new StringBuffer("SELECT ");
            sbQuerySearch.append(_sAliasColumnTGTID);
            sbQuerySearch.append(" FROM ").append(_sAliasTableName);
            sbQuerySearch.append(" WHERE ").append(_sAliasColumnEntityID).append("=?");
            sbQuerySearch.append(" AND ").append(type).append("=?");
            
            connection = _oDataSource.getConnection();
            psSelect = connection.prepareStatement(
                sbQuerySearch.toString());
            psSelect.setString(1, requestorID);
            psSelect.setString(2, alias);
            rsSelect = psSelect.executeQuery();
            if(rsSelect.next())
            {
                sTGTID = rsSelect.getString(_sAliasColumnTGTID);
            }
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute select query: " 
                + sbQuerySearch.toString(), e);
            throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer(
                "Internal error during retrieval of value from column '");
            sbError.append(type);
            sbError.append("' for requestor with id: ");
            sbError.append(requestorID);
            _logger.error(sbError.toString(), e);
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
                if (connection != null)
                    connection.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close connection", e);
            }            
        }
        return sTGTID;
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore#isAlias(java.lang.String, java.lang.String, java.lang.String)
     */
    public boolean isAlias(String type, String requestorID, String alias)
        throws OAException
    {
        boolean bRet = false;
        Connection connection = null;
        PreparedStatement psSelect = null;
        ResultSet rsSelect = null;
        StringBuffer sbQuerySearch = null;

        try
        {
            sbQuerySearch = new StringBuffer("SELECT ");
            sbQuerySearch.append(type);
            sbQuerySearch.append(" FROM ").append(_sAliasTableName);
            sbQuerySearch.append(" WHERE ").append(_sAliasColumnEntityID).append("=?");
            sbQuerySearch.append(" AND ").append(type).append("=?");
            
            connection = _oDataSource.getConnection();
            psSelect = connection.prepareStatement(sbQuerySearch.toString());
            psSelect.setString(1, requestorID);
            psSelect.setString(2, alias);
            rsSelect = psSelect.executeQuery();
            if(rsSelect.next())
               bRet = true;
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute select query: " 
                + sbQuerySearch.toString(), e);
            throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer(
                "Internal error during exist check for value '");
            sbError.append(alias);
            sbError.append("' on column '");
            sbError.append(type);
            sbError.append("' for  requestor id: ");
            sbError.append(requestorID);
            _logger.error(sbError.toString(), e);
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
                if (connection != null)
                    connection.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close connection", e);
            }            
        }
        return bRet;
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore#removeAlias(java.lang.String, java.lang.String, java.lang.String)
     */
    public void removeAlias(String type, String entityID, String alias) 
        throws OAException
    {
        Connection connection = null;
        PreparedStatement ps = null;
        StringBuffer sbQueryRemove = null;
        try
        {
            sbQueryRemove = new StringBuffer("UPDATE ");
            sbQueryRemove.append(_sAliasTableName);
            sbQueryRemove.append(" SET ");
            sbQueryRemove.append(type);
            sbQueryRemove.append("=? WHERE ");
            sbQueryRemove.append(_sAliasColumnEntityID);
            sbQueryRemove.append("=? AND ");
            sbQueryRemove.append(type);
            sbQueryRemove.append("=?");
            
            connection = _oDataSource.getConnection();
            ps = connection.prepareStatement(sbQueryRemove.toString());
            ps.setNull(1, Types.VARCHAR);
            ps.setString(2, entityID);
            ps.setString(3, alias);
            ps.executeUpdate();
        }
        catch (SQLException e)
        {                    
            _logger.error("Could not execute alias remove query: " + 
                sbQueryRemove.toString(), e);
        }
        finally
        {            
            try
            {
                if (ps != null)
                    ps.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close statement", e);
            } 
            try
            {
                if (connection != null)
                    connection.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close connection", e);
            }   
        }
    }

    /**
     * @see com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore#removeAll(java.lang.String, java.lang.String)
     */
    public void removeAll(String entityID, String tgtID) throws OAException
    {
        Connection connection = null;
        PreparedStatement ps = null;
        try
        {
            connection = _oDataSource.getConnection();
            ps = connection.prepareStatement(_sAliasQueryDeleteAll);
            ps.setString(1, entityID);
            ps.setString(2, tgtID);
            ps.executeUpdate();
        }
        catch (SQLException e)
        {                    
            _logger.error("Could not execute remove all aliasses query: " + 
                _sAliasQueryDeleteAll, e);
        }
        finally
        {            
            try
            {
                if (ps != null)
                    ps.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close statement", e);
            } 
            try
            {
                if (connection != null)
                    connection.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close connection", e);
            }   
        }
    }

    /**
     * Cleans all aliasses for the specified tgt. 
     * @param tgtID the tgt id
     * @return number of cleaned aliasses
     */
    int remove(Connection connection, String tgtID)
    {
        PreparedStatement ps = null;
        int iAlias = 0;
        try
        {
            ps = connection.prepareStatement(_sAliasQueryDelete);
            ps.setString(1, tgtID);
            iAlias = ps.executeUpdate();
        }
        catch (SQLException e)
        {                    
            _logger.error("Could not execute alias delete query: " + 
                _sAliasQueryDelete, e);
        }
        finally
        {            
            try
            {
                if (ps != null)
                    ps.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close statement", e);
            } 
        }
        return iAlias;
    }
    
    /**
     * Cleans all aliasses for the specified tgt. 
     * @param tgtID the tgt id
     * @return number of cleaned aliasses
     */
    int clean(Connection connection)
    {
        PreparedStatement ps = null;
        int iAlias = 0;
        try
        {
            ps = connection.prepareStatement(_sAliasQueryRemoveExpired);
            iAlias = ps.executeUpdate();
        }
        catch (SQLException e)
        {                    
            _logger.error("Could not execute alias delete query: " + 
                _sAliasQueryRemoveExpired, e);
        }
        finally
        {            
            try
            {
                if (ps != null)
                    ps.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close statement", e);
            } 
        }
        return iAlias;
    }
    
    /**
     * Returns the alias remove query which requires the TGT id on position 1.
     * @return The SQL query.
     */
    String getQueryAliasRemove()
    {
        return _sAliasQueryDelete;
    }
    
    private void createAliasQueries(IConfigurationManager configurationManager,
         Element eConfig) throws TGTException, ConfigurationException
     {
         Element eEntity = configurationManager.getSection(eConfig, "entity");
         if (eEntity == null)
         {
             _logger.info("No optional 'entity' section found in configuration, using default table and column names");
         }
         else
         {
             _sAliasTableName = configurationManager.getParam(eEntity, "table");
             
             Element eColumnTGTID = configurationManager.getSection(eConfig, 
                 "property", "name=tgtId");
             if(eColumnTGTID == null)
                 _logger.warn("No optional 'property' section found for property with name: tgtId");
             else
             {
                 _sAliasColumnTGTID = configurationManager.getParam(eColumnTGTID, "column"); 
                 if(_sAliasColumnTGTID == null)
                 {
                     _logger.error("Could not find column name for property tgtId");
                     throw new TGTException(SystemErrors.ERROR_CONFIG_READ);
                 }
             }
             
             Element eColumnRequestorID = configurationManager.getSection(eConfig, 
                 "property", "name=requestorId");
             if(eColumnRequestorID == null)
                 _logger.warn("No optional 'property' section found for property with name: requestorId");
             else
             {
                 _sAliasColumnEntityID = configurationManager.getParam(eColumnRequestorID, "column"); 
                 if(_sAliasColumnEntityID == null)
                 {
                     _logger.error("Could not find column name for property requestorId");
                     throw new TGTException(SystemErrors.ERROR_CONFIG_READ);
                 }
             }
         }
         
         if(_sAliasTableName == null)
             _sAliasTableName = ALIAS_STORE_TABLE_NAME_PREFIX + _sID;
          
         if (_sAliasColumnTGTID == null)
             _sAliasColumnTGTID = ALIAS_STORE_COLUMN_TGT_ID;
         
         if (_sAliasColumnEntityID == null)
             _sAliasColumnEntityID = _sID + ALIAS_STORE_COLUMN_ENTITY_ID_POSTFIX;
         
         //queries for Alias store
         StringBuffer sbQueryRemoveExpired = new StringBuffer("DELETE FROM ");
         sbQueryRemoveExpired.append(_sAliasTableName);
         sbQueryRemoveExpired.append(" WHERE ");
         sbQueryRemoveExpired.append(_sAliasColumnTGTID);
         sbQueryRemoveExpired.append(" NOT IN (SELECT ");
         sbQueryRemoveExpired.append(_sTGTTableName).append(".").append(_sTGTColumnID);
         sbQueryRemoveExpired.append(" FROM ");
         sbQueryRemoveExpired.append(_sTGTTableName);
         sbQueryRemoveExpired.append(")");
         _sAliasQueryRemoveExpired = sbQueryRemoveExpired.toString();
         _logger.debug("Using alias remove expired query: " + _sAliasQueryRemoveExpired);
         
         StringBuffer sbQuerySelect = new StringBuffer("SELECT ");
         sbQuerySelect.append(_sAliasColumnTGTID);
         sbQuerySelect.append(" FROM ");
         sbQuerySelect.append(_sAliasTableName);
         sbQuerySelect.append(" WHERE ");
         sbQuerySelect.append(_sAliasColumnTGTID);
         sbQuerySelect.append("=? AND ");
         sbQuerySelect.append(_sAliasColumnEntityID);
         sbQuerySelect.append("=?");
         _sAliasQueryRowExists = sbQuerySelect.toString();
         _logger.debug("Using alias row exists query: " + _sAliasQueryRowExists);
         
         StringBuffer sbQueryDelete = new StringBuffer("DELETE FROM ");
         sbQueryDelete.append(_sAliasTableName);
         sbQueryDelete.append(" WHERE ");
         sbQueryDelete.append(_sAliasColumnTGTID);
         sbQueryDelete.append("=?");
         _sAliasQueryDelete = sbQueryDelete.toString();
         _logger.debug("Using alias delete query: " + _sAliasQueryDelete);
                  
         StringBuffer sbQueryRemove = new StringBuffer("DELETE FROM ");
         sbQueryRemove.append(_sAliasTableName);
         sbQueryRemove.append(" WHERE ");
         sbQueryRemove.append(_sAliasColumnEntityID);
         sbQueryRemove.append("=? AND ");
         sbQueryRemove.append(_sAliasColumnTGTID);
         sbQueryRemove.append("=?");
         _sAliasQueryDeleteAll = sbQueryRemove.toString();
         _logger.debug("Using all aliasses remove query: " + _sAliasQueryDeleteAll);
     }
     
     private void verifyAliasTableConfig(IConfigurationManager 
         configurationManager, Element eAlias) throws OAException
     {
         Connection oConnection = null;
         PreparedStatement pVerify = null;
         try
         {   
             try
             {
                 oConnection = _oDataSource.getConnection();
             }
             catch (SQLException e)
             {
                 _logger.error("Could not connect to resource", e);
                 throw new DatabaseException(SystemErrors.ERROR_INIT);
             }
             
             String sVerificationQuery = null;
             try
             {
                 //<validation query=""/>    
                 Element eValidation = configurationManager.getSection(eAlias, "validation");
                 if(eValidation != null)
                 {
                     sVerificationQuery = configurationManager.getParam(eValidation, "query");
                     if(sVerificationQuery == null || sVerificationQuery.length() == 0)
                     {
                         //DD Do not verify the table if empty query configured
                         _logger.warn("Empty validation query found for table, alias store table structure is not validated");
                         //finally is executed before return
                         return;
                     }
                 }
                 
                 if(sVerificationQuery == null)
                 {
                     //DD Use default query if no validation.query parameter configured                     
                     StringBuffer sbVerificationQuery = new StringBuffer("SELECT ");
                     sbVerificationQuery.append(_sAliasColumnTGTID).append(",");
                     sbVerificationQuery.append(_sAliasColumnEntityID);
                     sbVerificationQuery.append(" FROM ");
                     sbVerificationQuery.append(_sAliasTableName);
                     sbVerificationQuery.append(" LIMIT 1"); 
                     sVerificationQuery = sbVerificationQuery.toString();
                     _logger.info("No validation query found for alias store table, using default: " + sVerificationQuery);
                 }
             }
             catch(ConfigurationException e)
             {
                 
                 _logger.error("Invalid validation query found for alias store table", e);
                 throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
             }           
             
             pVerify = oConnection.prepareStatement(sVerificationQuery);
             try
             {
                 pVerify.executeQuery();
             }
             catch(Exception e)
             {
                 StringBuffer sbError = new StringBuffer("Invalid alias store table configured '");
                 sbError.append(_sAliasTableName);
                 sbError.append("' verified with query: ");
                 sbError.append(sVerificationQuery);
                 _logger.error(sbError.toString(), e);
                 throw new DatabaseException(SystemErrors.ERROR_INIT);
             }  
         }
         catch (OAException e)
         {
             throw e;
         }
         catch (Exception e)
         {
             _logger.error("Internal error during verification of configured alias store table", e);          
             throw new OAException(SystemErrors.ERROR_INIT);
         }       
         finally
         {
             try
             {
                 if (pVerify != null)
                     pVerify.close();
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
     }
     
     private void update(Connection connection, String sTGTID, 
         String sEntityID, String sColumn, String sAlias) throws OAException
     {
        PreparedStatement psUpdate = null;
        StringBuffer sbQueryUpdate = null;

        try
        {
            sbQueryUpdate = new StringBuffer("UPDATE ");
            sbQueryUpdate.append(_sAliasTableName);
            sbQueryUpdate.append(" SET ");
            sbQueryUpdate.append(sColumn);
            sbQueryUpdate.append("=? WHERE ");
            sbQueryUpdate.append(_sAliasColumnTGTID);
            sbQueryUpdate.append("=? AND ");
            sbQueryUpdate.append(_sAliasColumnEntityID);
            sbQueryUpdate.append("=?");
            
            psUpdate = connection.prepareStatement(sbQueryUpdate.toString());
            psUpdate.setString(1, sAlias);
            psUpdate.setString(2, sTGTID);
            psUpdate.setString(3, sEntityID);
            
            int iUpdated = psUpdate.executeUpdate();
            if(iUpdated != 1)
            {
                _logger.error("Nothing updated while executing query: " 
                    + sbQueryUpdate.toString());
                throw new OAException(SystemErrors.ERROR_RESOURCE_UPDATE);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute query: " 
                + sbQueryUpdate.toString(), e);
            throw new OAException(SystemErrors.ERROR_RESOURCE_INSERT);
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer(
                "Internal error during update of row with alias '");
            sbError.append(sAlias);
            sbError.append("' in column '");
            sbError.append(sColumn);
            sbError.append("' for requestor id '");
            sbError.append(sEntityID);
            sbError.append("' and TGT id: ");
            sbError.append(sTGTID);
            _logger.error(sbError.toString(), e);
            throw new OAException(SystemErrors.ERROR_RESOURCE_INSERT);
        }       
        finally
        { 
            try
            {
                if (psUpdate != null)
                    psUpdate.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close statement", e);
            } 
        }
    }
    
    private void insert(Connection connection, String sTGTID, 
        String sRequestorID, String sColumn, String sAlias) throws OAException
    {
        PreparedStatement psInsert = null;
        StringBuffer sbQueryInsert = null;

        try
        {
            sbQueryInsert = new StringBuffer("INSERT INTO ");
            sbQueryInsert.append(_sAliasTableName);
            sbQueryInsert.append(" (");
            sbQueryInsert.append(_sAliasColumnTGTID);
            sbQueryInsert.append(",");
            sbQueryInsert.append(_sAliasColumnEntityID);
            sbQueryInsert.append(",");
            sbQueryInsert.append(sColumn);
            sbQueryInsert.append(") VALUES (?,?,?)");
            
            psInsert = connection.prepareStatement(sbQueryInsert.toString());
            psInsert.setString(1, sTGTID);
            psInsert.setString(2, sRequestorID);
            psInsert.setString(3, sAlias);
            
            int iInserted = psInsert.executeUpdate();
            if(iInserted != 1)
            {
                _logger.error("Nothing inserted while executing query: " 
                    + sbQueryInsert.toString());
                throw new OAException(SystemErrors.ERROR_RESOURCE_UPDATE);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute query: " 
                + sbQueryInsert.toString(), e);
            throw new OAException(SystemErrors.ERROR_RESOURCE_INSERT);
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer(
                "Internal error during insert of alias '");
            sbError.append(sAlias);
            sbError.append("' in column '");
            sbError.append(sColumn);
            sbError.append("' for requestor id '");
            sbError.append(sRequestorID);
            sbError.append("' and TGT id: ");
            sbError.append(sTGTID);
            _logger.error(sbError.toString(), e);
            throw new OAException(SystemErrors.ERROR_RESOURCE_INSERT);
        }       
        finally
        { 
            try
            {
                if (psInsert != null)
                    psInsert.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close statement", e);
            } 
        }
    }
}