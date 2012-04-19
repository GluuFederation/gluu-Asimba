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
package com.alfaariss.oa.util.saml2.storage.artifact.jdbc;
import java.io.StringReader;
import java.io.StringWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.datastorage.IDataStorageFactory;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.storage.IStorageFactory;
import com.alfaariss.oa.api.storage.clean.ICleanable;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.util.database.DatabaseException;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;
import com.alfaariss.oa.util.saml2.storage.artifact.ArtifactMapEntry;
import com.alfaariss.oa.util.storage.factory.AbstractStorageFactory;

/**
 * <code>SAMLArtifactMap</code> which uses a JDBC source for storage.
 * 
 * @author MHO
 * @author EVB
 * @author Alfa & Ariss
 */
public class JDBCArtifactMapFactory 
    extends AbstractStorageFactory implements SAMLArtifactMap
{  
    //The JDBC manager 
    private DataSource _oDataSource;
    //The XML parser pool
    private BasicParserPool _pool;
    //The system logger
    private Log _logger;
    
    //Default Database properties
    private final static String TABLE_NAME = "artifact";
    private final static String COLUMN_ID = "id";
    private final static String COLUMN_ISSUER = "issuer";
    private final static String COLUMN_RELYING_PARTY = "relyingParty";
    private final static String COLUMN_MESSAGE = "message";
    private final static String COLUMN_EXPIRATION = "expiration";
    
    private String _sTableName;
    private String _sColumnID;
    private String _sColumnISSUER;
    private String _sColumnRELYING_PARTY;
    private String _sColumnMESSAGE;    
    private String _sColumnEXPIRATION;   
    
    //Queries
    private String _sSearchQuery = null;
    private String _sInsertQuery = null; 
    private String _sRemoveQuery = null; 
    private String _sRemoveExpiredQuery = null; 
       
	/**
     * Create a new <code>JDBCFactory</code>.
     */
    public JDBCArtifactMapFactory()
    {
        super();        
        _logger = LogFactory.getLog(JDBCArtifactMapFactory.class);
    }

    /**
     * Call super class and start cleaner.
     * @see IStorageFactory#start()
     */
    public void start() throws OAException
    {

        Element eResource = _configurationManager.getSection(_eConfig, "resource");
        if (eResource != null)
        {
            _oDataSource = DataSourceFactory.createDataSource(_configurationManager, eResource);
            _logger.info("Using datasource specified in 'resource' section in configuration");
        }
        else
        {
            IDataStorageFactory databaseFactory = Engine.getInstance().getStorageFactory();
            if (databaseFactory != null && databaseFactory.isEnabled())
            {
                _oDataSource = databaseFactory.createSystemDatasource();
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
                
        _pool = new BasicParserPool();
        _pool.setNamespaceAware(true);  
        
        createQueries(_eConfig);        
        verifyTableConfig();
        
        if(_tCleaner != null)
            _tCleaner.start();    
    }

    /**
     * Check if the given artifact exists.
     * @see org.opensaml.common.binding.artifact.SAMLArtifactMap#contains(java.lang.String)
     */
    public boolean contains(String artifact)
    {
        if(artifact == null)
            throw new IllegalArgumentException("Suplied artifact is empty");
        
        boolean bRet = false;
        Connection oConnection = null;
        PreparedStatement psSelect = null;
        ResultSet rsSelect = null;

        try
        {
            oConnection = _oDataSource.getConnection();
            psSelect = oConnection.prepareStatement(_sSearchQuery);
            psSelect.setString(1, artifact);
            rsSelect = psSelect.executeQuery();
            if(rsSelect.next())
               bRet = true;
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute search query, artifact not found", e);            
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
        return bRet;
    }

    /**
     * Retrieve the given artifact.
     * @see org.opensaml.common.binding.artifact.SAMLArtifactMap#get(java.lang.String)
     */
    public SAMLArtifactMapEntry get(String artifact)
    {
        if(artifact == null )
            throw new IllegalArgumentException("Suplied artifact is empty");
        
        Connection oConnection = null;
        SAMLArtifactMapEntry artifactEntry = null;
        PreparedStatement ps = null;
        ResultSet rs = null;

        try
        {
            oConnection = _oDataSource.getConnection();
            ps = oConnection.prepareStatement(_sSearchQuery);
            ps.setString(1, artifact);
            rs = ps.executeQuery();
            if(rs.next())
            {
                //Get message
                String sMessage = rs.getString(4);
                Element eMessage = 
                    _pool.parse(new StringReader(sMessage)).getDocumentElement();
                Unmarshaller unmarshaller = 
                    Configuration.getUnmarshallerFactory().getUnmarshaller(eMessage);
               SAMLObject message = (SAMLObject)unmarshaller.unmarshall(eMessage);
               //Construct entry
               artifactEntry = new ArtifactMapEntry(rs.getString(1), 
                   rs.getString(2), rs.getString(3), 
                   rs.getTimestamp(5).getTime(), message); 
            }      
        }
        catch (SQLException e)
        {
            _logger.error(
                "Could not execute search query: " + _sSearchQuery, e);           
        }
        catch(ClassCastException e)
        {
            _logger.error(
                "Could not unmarshall SAML message, not a valid SAMLObject, artifact: " 
                + artifact, e);          
        }
        catch (XMLParserException e)
        {
            _logger.error(
                "Could not deserialize SAML message, associated with artifact: " 
                + artifact, e);
        }
        catch (UnmarshallingException e)
        {
            _logger.error(
                "Could not unmarshall SAML message, associated with artifact: " 
                + artifact, e);
        }
        finally
        {
            try
            {
                if (rs != null)
                    rs.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close resultset", e);
            }
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
                if (oConnection != null)
                    oConnection.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close connection", e);
            }
        }
        return artifactEntry;
    }

    /**
     * Store the given artifact in the JDBC resource.
     * @see org.opensaml.common.binding.artifact.SAMLArtifactMap#put(
     *  java.lang.String, java.lang.String, java.lang.String, 
     *  org.opensaml.common.SAMLObject)
     */
    public void put(String artifact, String relyingPartyId, String issuerId,
        SAMLObject samlMessage) throws MarshallingException
    {
        if (artifact == null)
            throw new IllegalArgumentException(
                "Suplied artifact is empty");
        if (samlMessage == null)
            throw new IllegalArgumentException(
                "Suplied samlMessage is empty");

        if (relyingPartyId == null)
            _logger.debug("Suplied relyingPartyId is empty");
        if (issuerId == null)
            _logger.debug("Suplied issuerId is empty");
        
        Connection oConnection = null;
        PreparedStatement psInsert = null;
                
        try
        {
            oConnection = _oDataSource.getConnection();
                           
            //Serialize message 
            //TODO EVB: store object bytes instead of serialization
            StringWriter writer = new StringWriter();
            Marshaller marshaller = Configuration.getMarshallerFactory(
                ).getMarshaller(samlMessage);
            XMLHelper.writeNode(marshaller.marshall(samlMessage), writer);
            String serializedMessage = writer.toString();               
            // Update expiration time and id
            long expiration = System.currentTimeMillis() + _lExpiration;
                               
            //Create statement                  
            psInsert = oConnection.prepareStatement(_sInsertQuery);
            psInsert.setString(1, artifact);                   
            psInsert.setString(2, issuerId);
            psInsert.setString(3, relyingPartyId);                   
            psInsert.setString(4, serializedMessage);
            psInsert.setTimestamp(5, new Timestamp(expiration));           
            
            int i = psInsert.executeUpdate();
            _logger.debug(i + " new artifact stored: " + artifact);
        }
        catch (SQLException e)
        {                    
            _logger.error("Could not execute insert query: " + _sInsertQuery, e);
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
                _logger.debug("Could not close insert statement", e);
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

    /**
     * Remove artifact from the JDBC resource.
     * @see org.opensaml.common.binding.artifact.SAMLArtifactMap#remove(java.lang.String)
     */
    public void remove(String artifact)
    {
        if (artifact == null)
            throw new IllegalArgumentException(
                "Suplied artifact is empty");
        
        Connection oConnection = null;
        PreparedStatement psDelete = null;
        
        try
        {        
            oConnection = _oDataSource.getConnection();
            
            psDelete = oConnection.prepareStatement(_sRemoveQuery);
            psDelete.setString(1, artifact);
            int i = psDelete.executeUpdate();
            _logger.debug(i + " artifact removed: " + artifact);
        }
        catch (SQLException e)
        {                    
            _logger.error("Could not execute delete query: " + _sRemoveQuery, e);
        }
        finally
        {
            try
            {
                if (psDelete != null)
                    psDelete.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close insert statement", e);
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

    /**
     * Remove all expired artifacts.
     * 
     * e.g. <code>DELETE FROM artifacts WHERE expiration <= NOW()</code>
     * @see ICleanable#removeExpired()
     */
    public void removeExpired() throws PersistenceException
    {
        Connection oConnection = null;
        PreparedStatement ps = null;
        try
        {
            oConnection = _oDataSource.getConnection();
            ps = oConnection.prepareStatement(_sRemoveExpiredQuery);
            ps.setTimestamp(1, new Timestamp(System.currentTimeMillis()));           
            int i = ps.executeUpdate();
            if(i > 0)
                _logger.debug(i + " artifact(s) expired");
        }
        catch (SQLException e)
        {
            _logger.error("Could not execute delete expired", e);          
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_REMOVE, e);
        }
        catch (Exception e)
        {
            _logger.error("Internal error while delete expired artifacts", e);          
            throw new PersistenceException(SystemErrors.ERROR_RESOURCE_REMOVE, e);
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
                if (oConnection != null)
                    oConnection.close();
            }
            catch (SQLException e)
            {
                _logger.debug("Could not close connection", e);
            }
        }        
        
    }
    
    /*
     * Read the entity storage configuration and create queries. 
     * 
     * If no configuration section is present the default queries are used.
     */
     private void createQueries(Element eConfig) throws OAException
     {
     
         Element eEntity = _configurationManager.getSection(eConfig, "entity");
         if (eEntity == null)
         {
             _logger.info("No optional 'entity' section found in configuration, using default table and column names");
         }
         else
         {
             _sTableName = _configurationManager.getParam(eEntity, "table");
             _sColumnID = getIdColumnName(eEntity); 
             _sColumnISSUER = getColumnName(eEntity, "issuer");
             _sColumnMESSAGE = getColumnName(eEntity, "message");
             _sColumnRELYING_PARTY = getColumnName(eEntity, "relyingParty");
             _sColumnEXPIRATION = getColumnName(eEntity, "expTime");            
         }
         
         if(_sTableName == null)
             _sTableName = TABLE_NAME;
         
         if (_sColumnID == null)
             _sColumnID = COLUMN_ID;    
          
         if (_sColumnISSUER == null)
             _sColumnISSUER = COLUMN_ISSUER;
          
         if (_sColumnRELYING_PARTY == null)
             _sColumnRELYING_PARTY = COLUMN_RELYING_PARTY;   
         
         if (_sColumnMESSAGE == null)
             _sColumnMESSAGE = COLUMN_MESSAGE;  
                  
         if (_sColumnEXPIRATION == null)
             _sColumnEXPIRATION = COLUMN_EXPIRATION;  
                             
         //SearchQuery
         StringBuffer sb = new StringBuffer("SELECT ");
         sb.append(_sColumnID).append(", ");
         sb.append(_sColumnISSUER).append(", ");
         sb.append(_sColumnRELYING_PARTY).append(", ");
         sb.append(_sColumnMESSAGE).append(", ");        
         sb.append(_sColumnEXPIRATION);
         sb.append(" FROM ").append(_sTableName);
         sb.append(" WHERE ").append(_sColumnID).append("=?");
         _sSearchQuery = sb.toString();
         _logger.debug("Using SearchQuery: " + _sSearchQuery);

         //InsertQuery
         sb = new StringBuffer("INSERT INTO ");
         sb.append(_sTableName).append("(");
         sb.append(_sColumnID).append(",");
         sb.append(_sColumnISSUER).append(", ");
         sb.append(_sColumnRELYING_PARTY).append(", ");
         sb.append(_sColumnMESSAGE).append(", ");        
         sb.append(_sColumnEXPIRATION);
         sb.append(") VALUES(?,?,?,?,?)");             
         _sInsertQuery = sb.toString();
         _logger.debug("Using InsertQuery: " + _sInsertQuery);
         
         //RemoveQuery
         sb = new StringBuffer("DELETE FROM ");
         sb.append(_sTableName).append(" WHERE ");
         sb.append(_sColumnID).append("=?");
         _sRemoveQuery = sb.toString();
         _logger.debug("Using RemoveQuery: " + _sRemoveQuery);
         
         //RemoveExpiredQuery 
         sb = new StringBuffer("DELETE FROM ");
         sb.append(_sTableName).append(" WHERE ");
         sb.append(_sColumnEXPIRATION).append("<=?");
         _sRemoveExpiredQuery = sb.toString();
         _logger.debug("Using RemoveExpiredQuery: " + _sRemoveExpiredQuery);            
     }
     
     //Retrieve id column name
     private String getIdColumnName(
         Element eConfig) throws OAException, ConfigurationException
     {
         String sIdColumn = null;
         if (eConfig != null)
         {
             Element eIdColumn = _configurationManager.getSection(eConfig, "id");
             if(eIdColumn == null)
                 _logger.error("No optional 'id' section found");
             else
             {
                 sIdColumn = _configurationManager.getParam(eIdColumn, "column"); 
                 if(sIdColumn == null)
                 {
                     _logger.error("Could not find column name for id");
                     throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                 }
             }
         }
         return sIdColumn;
     }

     //Retrieve property column name
     private String getColumnName(Element eConfig, 
         String sName) throws OAException, ConfigurationException
     {
         String sColumn = null;
         if (eConfig != null || sName != null)
         {
             Element eColumn = _configurationManager.getSection(
                 eConfig, "property", "name=" + sName);
             if(eColumn == null)
                 _logger.error("No optional 'property' section found for property with name: " + sName);
             else
             {
                 sColumn = _configurationManager.getParam(eColumn, "column"); 
                 if(sColumn == null)
                 {
                     _logger.error("Could not find column name for property " + sName);
                     throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                 }
             }
         }
         return sColumn;
     }
     
     private void verifyTableConfig() throws OAException
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
                 throw new DatabaseException(SystemErrors.ERROR_INIT, e);
             }
             
             StringBuffer sb = new StringBuffer("SELECT ");
             sb.append(_sColumnID).append(", ");
             sb.append(_sColumnISSUER).append(", ");
             sb.append(_sColumnRELYING_PARTY).append(", ");
             sb.append(_sColumnMESSAGE).append(", ");        
             sb.append(_sColumnEXPIRATION);
             sb.append(" FROM ");
             sb.append(_sTableName);
            //DD LIMIT 1 is not supported by derby, setMaxRows(1) is       
             
             pVerify = oConnection.prepareStatement(sb.toString());
             pVerify.setMaxRows(1);
             try
             {
                 pVerify.executeQuery();
             }
             catch(Exception e)
             {
                 StringBuffer sbError = new StringBuffer("Invalid table configured '");
                 sbError.append(_sTableName);
                 sbError.append("' verified with query: ");
                 sbError.append(sb.toString());
                 _logger.error(sbError.toString());
                 throw new DatabaseException(SystemErrors.ERROR_INIT);
             }  
         }
         catch (OAException e)
         {
             throw e;
         }
         catch (SQLException e)
         {
             _logger.error("SQL error during verification of configured table: " + e.getErrorCode(), e);          
             throw new OAException(SystemErrors.ERROR_INIT, e);
         }
         catch (Exception e)
         {
             _logger.error("Internal error during verification of configured table", e);          
             throw new OAException(SystemErrors.ERROR_INIT, e);
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
}