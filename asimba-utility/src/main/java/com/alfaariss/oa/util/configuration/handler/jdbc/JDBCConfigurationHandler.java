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
package com.alfaariss.oa.util.configuration.handler.jdbc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;

import javax.sql.DataSource;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.handler.IConfigurationHandler;
import com.alfaariss.oa.util.database.DatabaseException;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;

/**
 * A configuration handler for JDBC database configuration.
 * 
 * Uses a JDBC DataSource for reading and writing the 
 * configuration to and from a JDBC source. 
 * 
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class JDBCConfigurationHandler implements IConfigurationHandler 
{
	/**
	 * The name of the database column that indicates the configuration 
     * that must be read by this config handler.
	 */
	public static final String ID_COLUMN = "id";
	/**
	 * The name of the database column that is used to store the XML 
     * configuration in the configuration table.
	 */
    public static final String DATA_COLUMN = "data";
    
    /** Charset: UTF-8 */
    public static final String CHARSET = "UTF-8";
    
	private Log _logger;
	private DataSource _oDataSource;
    
	/**
	 * The id of the configuration that indicates the configuration 
     * in the database.
	 */
	private String _sConfigId;
    
	private String _sReadQuery;
    private String _sUpdateQuery;
	
    /**
     * Create a new <code>JDBCConfigHandler</code>.
     */
    public JDBCConfigurationHandler()
    {
        _logger = LogFactory.getLog(JDBCConfigurationHandler.class);
    }
    
    /**
     * @see IConfigurationHandler#init(java.util.Properties)
     */
    public void init(Properties pConfig)
      throws ConfigurationException
    {
        try
        {
            String sTable = pConfig.getProperty("configuration.handler.table");
            if (sTable == null)
            {
                _logger.error("Property with name 'configuration.handler.table' not found");
                throw new ConfigurationException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _sConfigId = pConfig.getProperty("configuration.handler.configid");
            if (_sConfigId == null)
            {
                _logger.error("Property with name 'configuration.handler.configid' not found");
                throw new ConfigurationException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            //create read query
            StringBuffer sbQuery = new StringBuffer("Select ");
            sbQuery.append(DATA_COLUMN);
            sbQuery.append(" FROM ");
            sbQuery.append(sTable);
            sbQuery.append(" WHERE ").append(ID_COLUMN);
            sbQuery.append("=?");
            _sReadQuery = sbQuery.toString();
            //create update query
            sbQuery = new StringBuffer("UPDATE ");
            sbQuery.append(sTable).append(" SET ");
            sbQuery.append(DATA_COLUMN).append("=? WHERE ");
            sbQuery.append(ID_COLUMN).append("=?");
            _sUpdateQuery = sbQuery.toString();
            
            try
            {
                _oDataSource = DataSourceFactory.createDataSource(pConfig);   
            }
            catch (DatabaseException e)
            {
                _logger.error("Error creating database connector", e);
                throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_CONNECT);
            }
        }
        catch (ConfigurationException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Internal error during initialization", e);
            throw new ConfigurationException(SystemErrors.ERROR_INTERNAL);
        }
    }

	/**
	 * Parse the database configuration using the read query and 
     * a {@link DocumentBuilder}.
	 * @see IConfigurationHandler#parseConfiguration()
	 */
	public Document parseConfiguration()
	  throws ConfigurationException
    {
        PreparedStatement psRead = null;
        Connection oConnection = null;
        ResultSet rs = null;
        Document dRet = null;
        try
        {
            //open DB connection
            oConnection = _oDataSource.getConnection();
            psRead = oConnection.prepareStatement(_sReadQuery);
            psRead.setString(1, _sConfigId);
            rs = psRead.executeQuery();
            if (rs.next())
            {
                String sData = rs.getString(1);
                //create DocumentBuilderFactory to parse config file.
                DocumentBuilderFactory oDocumentBuilderFactory = 
                    DocumentBuilderFactory.newInstance();

                //Create parser
                DocumentBuilder oDocumentBuilder = oDocumentBuilderFactory
                    .newDocumentBuilder();

                ByteArrayInputStream oByteArrayInputStream = 
                    new ByteArrayInputStream(sData.getBytes(CHARSET));

                InputSource oInputSource = 
                    new InputSource(oByteArrayInputStream);

                //parse
                dRet =  oDocumentBuilder.parse(oInputSource);
            }
            else
            {
                _logger.error(
                    "Could not read configuration from te database, no configuration found");          
                throw new ConfigurationException(SystemErrors.ERROR_CONFIG_READ);
            }
            
        }
        catch (ParserConfigurationException e)
        {
            _logger.error(
                "Could not read configuration from te database, parse error"
                , e);
            throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (SQLException e)
        {
            _logger.error(
                "Could not read configuration from te database, SQL error"
                , e);
            throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (UnsupportedEncodingException e)
        {
            _logger.error(
                "Could not read configuration from te database, unsupported encoding"
                , e);
            throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }       
        catch (SAXException e)
        {
            _logger.error(
                "Could not read configuration from te database, SAX error"
                , e);
            throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (IOException e)
        {
            _logger.error(
                "Could not read configuration from te database, I/O error"
                , e);
            throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch(Exception e)
        {
            _logger.error("Internal error during the parsing of configuration", e);          
            throw new ConfigurationException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
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
                if (psRead != null)
                    psRead.close();
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
        return dRet;
	}

	/**
	 * Saves the database configuration using the update query.
	 * @see IConfigurationHandler#saveConfiguration(org.w3c.dom.Document)
	 */
	public void saveConfiguration(Document oConfigurationDocument)
	  throws ConfigurationException
    {
        Connection oConnection = null;
        OutputStream os = null;
        PreparedStatement ps = null;
        
        try
        {
            os = new ByteArrayOutputStream();
            
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty(OutputKeys.VERSION, "1.0");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.transform(new DOMSource(oConfigurationDocument), new StreamResult(os));
            
            //Save to DB
            oConnection = _oDataSource.getConnection();
            ps = oConnection.prepareStatement(_sUpdateQuery);
            ps.setString(1, os.toString());
            ps.setString(2, _sConfigId);
            ps.executeUpdate();
        }
        catch (SQLException e)
        {
            _logger.error("Database error while writing configuration, SQL eror"
                ,e);    
            throw new ConfigurationException(SystemErrors.ERROR_CONFIG_WRITE);
        }
        catch (TransformerException e)
        {
            _logger.error("Error while transforming document", e);
            throw new ConfigurationException(SystemErrors.ERROR_CONFIG_WRITE);
        }
        catch (Exception e)
        {
            _logger.error("Internal error during during configuration save", e);    
            throw new ConfigurationException(SystemErrors.ERROR_CONFIG_WRITE);
        }
        finally
        {
            
            try
            {
                if(os != null)
                    os.close();
            }
            catch (IOException e)
            {
               _logger.debug("Error closing configuration outputstream", e);
            }
            
            try
            {
                if(ps != null) 
                    ps.close();
            }
            catch (SQLException e)
            {
               _logger.debug("Error closing statement", e);
            }
            
            try
            {
                if (oConnection != null)
                    oConnection.close();
            }
            catch (SQLException e)
            {
               _logger.debug("Error closing connection", e);
            }
        }
	}

}