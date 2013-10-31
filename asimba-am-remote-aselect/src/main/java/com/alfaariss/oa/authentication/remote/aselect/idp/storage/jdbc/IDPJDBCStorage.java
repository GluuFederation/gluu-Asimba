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
package com.alfaariss.oa.authentication.remote.aselect.idp.storage.jdbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.remote.aselect.idp.storage.ASelectIDP;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.engine.idp.storage.jdbc.AbstractJDBCStorage;
import com.alfaariss.oa.util.database.DatabaseException;

/**
 * Uses JDBC as IDP storage.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class IDPJDBCStorage extends AbstractJDBCStorage
{
    private final static String DEFAULT_ID = "aselect";
    private final static String DEFAULT_TABLE_NAME = "aselect_orgs";
    
    private final static String COLUMN_ID = "id";
    private final static String COLUMN_FRIENDLYNAME = "friendlyname";
    private final static String COLUMN_ENABLED = "enabled";
    
    private final static String COLUMN_SERVER_ID = "server_id";
    private final static String COLUMN_LEVEL = "level";
    private final static String COLUMN_SIGNING = "signing";
    private final static String COLUMN_URL = "url";
    private final static String COLUMN_COUNTRY = "country";
    private final static String COLUMN_LANGUAGE = "language";
    private final static String COLUMN_ASYNCHRONOUS_LOGOUT = "asynchronouslogout";
    private final static String COLUMN_SYNCHRONOUS_LOGOUT = "synchronouslogout";
    private final static String COLUMN_SEND_ARP_TARGET = "send_arp_target";
    
    /** Local logger instance */
    private static Log _logger = LogFactory.getLog(IDPJDBCStorage.class);
    
    private String _sID;
    private String _sTable;
    private String _querySelectAll;
    private String _querySelect;
    private String _queryExist;
    
    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager configManager, Element config)
        throws OAException
    {
        _sID = configManager.getParam(config, "id");
        if (_sID == null)
        {
            _logger.info("No optional 'id' item for storage configured, using default");
            _sID = DEFAULT_ID;
        }
        
        super.start(configManager, config);

        Element eResource = configManager.getSection(config, "resource");
        if (eResource == null)
        {
            _sTable = DEFAULT_TABLE_NAME;
        }
        else
        {
            _sTable = configManager.getParam(eResource, "table");
            if (_sTable == null)
                _sTable = DEFAULT_TABLE_NAME;
        }
        
        _logger.info("Using table: " + _sTable);
        
        createQueries();
        
        _logger.info("Started storage with id: " + _sID);
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#exists(java.lang.String)
     */
    public boolean exists(String id) throws OAException
    {
        Connection connection = null;
        PreparedStatement pSelect = null;
        ResultSet resultSet = null;
        try
        {
            connection = _dataSource.getConnection();
            
            pSelect = connection.prepareStatement(_queryExist);
            pSelect.setString(1, id);
            resultSet = pSelect.executeQuery();
            if (resultSet.next())
            {
                return true;
            }
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during exist check for IDP: " + id, e);
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
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getAll()
     */
    public List<IIDP> getAll() throws OAException
    {
        Connection connection = null;
        PreparedStatement pSelect = null;
        ResultSet resultSet = null;
        List<IIDP> listIDPs = new Vector<IIDP>();
        try
        {
            connection = _dataSource.getConnection();
            
            pSelect = connection.prepareStatement(_querySelectAll);
            pSelect.setBoolean(1, true);
            resultSet = pSelect.executeQuery();
            while (resultSet.next())
            {
                ASelectIDP idp = new ASelectIDP(
                    resultSet.getString(COLUMN_ID),
                    resultSet.getString(COLUMN_FRIENDLYNAME),
                    resultSet.getString(COLUMN_SERVER_ID),
                    resultSet.getString(COLUMN_URL),
                    resultSet.getInt(COLUMN_LEVEL),
                    resultSet.getBoolean(COLUMN_SIGNING),
                    resultSet.getString(COLUMN_COUNTRY),
                    resultSet.getString(COLUMN_LANGUAGE),
                    resultSet.getBoolean(COLUMN_ASYNCHRONOUS_LOGOUT),
                    resultSet.getBoolean(COLUMN_SYNCHRONOUS_LOGOUT),
                    resultSet.getBoolean(COLUMN_SEND_ARP_TARGET));
                listIDPs.add(idp);
            }
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during retrieval of all IDPs", e);
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
        return listIDPs;
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getID()
     */
    public String getID()
    {
        return _sID;
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getIDP(java.lang.String)
     */
    public IIDP getIDP(String id) throws OAException
    {
        Connection connection = null;
        PreparedStatement pSelect = null;
        ResultSet resultSet = null;
        ASelectIDP oASelectIDP = null;
        try
        {
            connection = _dataSource.getConnection();
            
            pSelect = connection.prepareStatement(_querySelect);
            pSelect.setBoolean(1, true);
            pSelect.setString(2, id);
            resultSet = pSelect.executeQuery();
            if (resultSet.next())
            {
                oASelectIDP = new ASelectIDP(
                    resultSet.getString(COLUMN_ID),
                    resultSet.getString(COLUMN_FRIENDLYNAME),
                    resultSet.getString(COLUMN_SERVER_ID),
                    resultSet.getString(COLUMN_URL),
                    resultSet.getInt(COLUMN_LEVEL),
                    resultSet.getBoolean(COLUMN_SIGNING),
                    resultSet.getString(COLUMN_COUNTRY),
                    resultSet.getString(COLUMN_LANGUAGE),
                    resultSet.getBoolean(COLUMN_ASYNCHRONOUS_LOGOUT),
                    resultSet.getBoolean(COLUMN_SYNCHRONOUS_LOGOUT),
                    resultSet.getBoolean(COLUMN_SEND_ARP_TARGET));
            }
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during retrieval of IDP with id: " + id, e);
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
        return oASelectIDP;
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getIDP(java.lang.Object, java.lang.String)
     */
    public IIDP getIDP(Object id, String type) throws OAException
    {
    	Connection connection = null;
        PreparedStatement pSelect = null;
        ResultSet resultSet = null;
        ASelectIDP oASelectIDP = null;
        try
        {
            connection = _dataSource.getConnection();
            
            StringBuffer sbSelect = new StringBuffer(_querySelectAll);
            sbSelect.append(" AND ");
            sbSelect.append(type);
            sbSelect.append("=?");
            pSelect = connection.prepareStatement(sbSelect.toString());
            pSelect.setBoolean(1, true);
            pSelect.setObject(2, id);
            resultSet = pSelect.executeQuery();
            if (resultSet.next())
            {
                oASelectIDP = new ASelectIDP(
                    resultSet.getString(COLUMN_ID),
                    resultSet.getString(COLUMN_FRIENDLYNAME),
                    resultSet.getString(COLUMN_SERVER_ID),
                    resultSet.getString(COLUMN_URL),
                    resultSet.getInt(COLUMN_LEVEL),
                    resultSet.getBoolean(COLUMN_SIGNING),
                    resultSet.getString(COLUMN_COUNTRY),
                    resultSet.getString(COLUMN_LANGUAGE),
                    resultSet.getBoolean(COLUMN_ASYNCHRONOUS_LOGOUT),
                    resultSet.getBoolean(COLUMN_SYNCHRONOUS_LOGOUT),
                    resultSet.getBoolean(COLUMN_SEND_ARP_TARGET)
                    );
            }
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during retrieval of IDP with id: " + id, e);
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
        return oASelectIDP;
    }

    private void createQueries() throws OAException
    {
        Connection connection = null;
        PreparedStatement pVerify = null;
        try
        {   
            StringBuffer sbSelectAllOrgs = new StringBuffer("SELECT ");
            sbSelectAllOrgs.append(COLUMN_ID).append(",");
            sbSelectAllOrgs.append(COLUMN_SERVER_ID).append(",");
            sbSelectAllOrgs.append(COLUMN_LEVEL).append(",");
            sbSelectAllOrgs.append(COLUMN_SIGNING).append(",");
            sbSelectAllOrgs.append(COLUMN_URL).append(",");
            sbSelectAllOrgs.append(COLUMN_FRIENDLYNAME).append(",");
            sbSelectAllOrgs.append(COLUMN_COUNTRY).append(",");
            sbSelectAllOrgs.append(COLUMN_LANGUAGE).append(",");
            sbSelectAllOrgs.append(COLUMN_ASYNCHRONOUS_LOGOUT).append(",");
            sbSelectAllOrgs.append(COLUMN_SYNCHRONOUS_LOGOUT).append(",");
            sbSelectAllOrgs.append(COLUMN_SEND_ARP_TARGET);
            sbSelectAllOrgs.append(" FROM ");
            sbSelectAllOrgs.append(_sTable);
            
            StringBuffer sbVerify = new StringBuffer(sbSelectAllOrgs);
            sbVerify.append(" LIMIT 1");
            
            connection = _dataSource.getConnection();
            
            pVerify = connection.prepareStatement(sbVerify.toString());
            try
            {
                pVerify.executeQuery();
            }
            catch(Exception e)
            {
                StringBuffer sbError = new StringBuffer("Invalid idp table '");
                sbError.append(_sTable);
                sbError.append("' verified with query: ");
                sbError.append(sbVerify.toString());
                _logger.error(sbError.toString(), e);
                throw new DatabaseException(SystemErrors.ERROR_INIT);
            }    
            
            sbSelectAllOrgs.append(" WHERE ");
            sbSelectAllOrgs.append(COLUMN_ENABLED);
            sbSelectAllOrgs.append("=?");
            _querySelectAll = sbSelectAllOrgs.toString();
            _logger.info("Using select all IDPs query: " + _querySelectAll);
            
            StringBuffer sbSelectOnID = new StringBuffer(sbSelectAllOrgs);
            sbSelectOnID.append(" AND ");
            sbSelectOnID.append(COLUMN_ID);
            sbSelectOnID.append("=?");
            
            _querySelect = sbSelectOnID.toString();
            _logger.info("Using IDP select query: " + _querySelect);
            
            StringBuffer sbExist = new StringBuffer("SELECT COUNT(");
            sbExist.append(COLUMN_ID);
            sbExist.append(") FROM ");
            sbExist.append(_sTable);
            sbExist.append(" WHERE ");
            sbExist.append(COLUMN_ID);
            sbExist.append("=?");
            _queryExist = sbExist.toString();
            _logger.info("Using IDP exist query: " + _queryExist);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during query creation", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            try
            {
                if (pVerify != null)
                    pVerify.close();
            }
            catch (Exception e)
            {
                _logger.error("Could not close verification statement", e);
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
    }

}
