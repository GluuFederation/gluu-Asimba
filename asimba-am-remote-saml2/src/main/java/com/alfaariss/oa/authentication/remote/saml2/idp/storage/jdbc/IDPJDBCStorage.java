/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authentication.remote.saml2.idp.storage.jdbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;
import java.util.List;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.util.saml2.metadata.provider.IMetadataProviderManager;
import org.asimba.util.saml2.metadata.provider.management.MdMgrManager;
import org.asimba.util.saml2.metadata.provider.management.MetadataProviderManagerUtil;
import org.asimba.util.saml2.metadata.provider.management.StandardMetadataProviderManager;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.engine.idp.storage.jdbc.AbstractJDBCStorage;
import com.alfaariss.oa.util.database.DatabaseException;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;

/**
 * Uses a JDBC table as organization storage.
 *
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.1
 */
public class IDPJDBCStorage extends AbstractJDBCStorage 
{   
	/** Configuration elements */
	public static final String EL_MPMANAGER = "mp_manager";

	/** Local logger instance */
	private static Log _oLogger = LogFactory.getLog(IDPJDBCStorage.class);
			
    private final static String DEFAULT_TABLE_NAME = "saml2_orgs";
    private final static String COLUMN_ID = "id";
    private final static String COLUMN_ENABLED = "enabled";
    
    private final static String COLUMN_SOURCEID = "sourceid";
    private final static String COLUMN_FRIENDLYNAME = "friendlyname";
    private final static String COLUMN_METADATA_URL = "metadata_url";
    private final static String COLUMN_METADATA_TIMEOUT = "metadata_timeout";
    private final static String COLUMN_METADATA_FILE = "metadata_file";
    private final static String COLUMN_ACS_INDEX = "acs_index";
    private final static String COLUMN_SCOPING = "scoping";
    private final static String COLUMN_NAMEIDPOLICY = "nameidpolicy";
    private final static String COLUMN_ALLOW_CREATE = "allow_create";
    private final static String COLUMN_NAMEIDFORMAT = "nameidformat";
    private final static String COLUMN_AVOID_SUBJCONF = "avoid_subjconf";
    private final static String COLUMN_DISABLE_SSO = "disable_sso";
    /** date last modified */
    public static final String COLUMN_DATELASTMODIFIED = "date_last_modified";

    
    private final static String DEFAULT_ID = "saml2";
    private String _sId;
    
    /** Id of the MetadataProviderManager that manages metadata for the SAML2IDPs that are
     * created by this Storage; configurable; defaults to the Id of the Storage (_sId) */
    protected String _sMPMId;
    protected boolean _bOwnMPM;
    
    
    private String _sTable;
    
    private String _sQuerySelectOnID;
    private String _sQuerySelectOnSourceID;
    private String _sQuerySelectAll;

    
    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager configManager, Element config)
        throws OAException
    {
        _sId = configManager.getParam(config, "id");
        if (_sId == null)
        {
            _oLogger.info("No optional 'id' item for storage configured, using default");
            _sId = DEFAULT_ID;
        }
        
        // Establish MetadataProviderManager Id that refers to existing IMetadataProviderManager
        Element elMPManager = configManager.getSection(config, EL_MPMANAGER);
        if (elMPManager == null) {
        	_oLogger.info("Using MetadataProviderManager Id from IDPStorage@id: '"+_sId+"'");
        	_sMPMId = _sId;
        } else {
        	_sMPMId = configManager.getParam(elMPManager, "id");
        	if (_sMPMId == null) {
        		_oLogger.error("Missing @id attribute for '"+EL_MPMANAGER+"' configuration");
        		throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        	}
        	_oLogger.info("Using MetadataProviderManager Id from configuration: '"+_sMPMId+"'");
        }
        
        // Make sure the MetadataProviderManager exists
        boolean bCreated = MetadataProviderManagerUtil.establishMPM(_sMPMId, configManager, elMPManager);
        
        if (elMPManager == null) {
        	_bOwnMPM = bCreated;
        } else {
        	String sPrimary = configManager.getParam(elMPManager, "primary");
        	if (sPrimary == null ) {
        		_bOwnMPM = false;
        	} else {
        		if ("false".equalsIgnoreCase(sPrimary)) {
        			_bOwnMPM = false;
        		} else if ("true".equalsIgnoreCase(sPrimary)) {
        			_bOwnMPM = true;
        		} else {
        			_oLogger.error("Invalid value for '@primary': '"+sPrimary+"'");
        			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        		}
        	}
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
        
        _oLogger.info("Using table: " + _sTable);
        
        createQueries(configManager, config);
        
        // Instantiate MetadataProviderManager
        // Set with ID of this IDPStorage instance
        StandardMetadataProviderManager oMPM = new StandardMetadataProviderManager(_sId);
        MdMgrManager.getInstance().setMetadataProviderManager(_sId, oMPM);
        
        _oLogger.info("Started storage with id: " + _sId);
    }
    
    @Override
    public void stop() {
        // Clean up the MetadataProviderManager?
        if (_bOwnMPM) {
        	_oLogger.info("Cleaning up MetadataProviderManager '"+_sMPMId+"'");
        	MdMgrManager.getInstance().deleteMetadataProviderManager(_sMPMId);
        }
    	
    	super.stop();
        
    	_oLogger.info("Stopped storage with id: " + _sId);
    }
    
    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getID()
     */
    public String getID()
    {
        return _sId;
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#exists(java.lang.String)
     */
    public boolean exists(String id) throws OAException
    {
        return retrieveByID(id) != null;
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
        
        IMetadataProviderManager oMPM = MdMgrManager.getInstance().getMetadataProviderManager(_sId);
        
        try
        {
	        boolean dateLastModifiedExists = true;
	        
            connection = _dataSource.getConnection();
            
            pSelect = connection.prepareStatement(_sQuerySelectAll);
            pSelect.setBoolean(1, true);
            resultSet = pSelect.executeQuery();
            while (resultSet.next())
            {
                boolean bACSIndex = resultSet.getBoolean(COLUMN_ACS_INDEX);
                
                Boolean boolAllowCreate = null;
                String sAllowCreate = resultSet.getString(COLUMN_ALLOW_CREATE);
                if (sAllowCreate != null)
                {
                    boolean bAllowCreate = resultSet.getBoolean(COLUMN_ALLOW_CREATE);
                    boolAllowCreate = new Boolean(bAllowCreate);
                }
                
                boolean bScoping = resultSet.getBoolean(COLUMN_SCOPING);
                boolean bNameIDPolicy = resultSet.getBoolean(COLUMN_NAMEIDPOLICY);
                boolean bAvoidSubjectConfirmation = resultSet.getBoolean(COLUMN_AVOID_SUBJCONF);
                boolean bDisableSSOForIDP = resultSet.getBoolean(COLUMN_DISABLE_SSO);
                
                // Implement date_last_modified column as optional
            	Date dLastModified = null;
            	if (dateLastModifiedExists) {
	            	try {
	            		dLastModified = resultSet.getTimestamp(COLUMN_DATELASTMODIFIED);
	            	} catch (Exception e) {
	            		_oLogger.info("No "+COLUMN_DATELASTMODIFIED+" column found; ignoring.");
	            		dateLastModifiedExists = false;
	            	}
            	}
                
                SAML2IDP idp = new SAML2IDP(
                    resultSet.getString(COLUMN_ID),
                    resultSet.getBytes(COLUMN_SOURCEID),
                    resultSet.getString(COLUMN_FRIENDLYNAME),
                    resultSet.getString(COLUMN_METADATA_FILE),
                    resultSet.getString(COLUMN_METADATA_URL),
                    resultSet.getInt(COLUMN_METADATA_TIMEOUT),
                    bACSIndex, boolAllowCreate, 
                    bScoping, bNameIDPolicy,
                    resultSet.getString(COLUMN_NAMEIDFORMAT),
                    bAvoidSubjectConfirmation,
                    bDisableSSOForIDP,
                    dLastModified,
                    oMPM.getId());
                listIDPs.add(idp);
            }
        }
        catch(Exception e)
        {
            _oLogger.fatal("Internal error during retrieval of all IDPs", e);
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
                _oLogger.error("Could not close select statement", e);
            }
                        
            try
            {
                if (connection != null)
                    connection.close();
            }
            catch (Exception e)
            {
                _oLogger.error("Could not close connection", e);
            }
        }
        return listIDPs;
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getIDP(java.lang.String)
     */
    public IIDP getIDP(String id) throws OAException
    {
        return retrieveByID(id);
    }

    /**
     * @see com.alfaariss.oa.engine.core.idp.storage.IIDPStorage#getIDP(java.lang.Object, java.lang.String)
     */
    public IIDP getIDP(Object id, String type) throws OAException
    {
        if (type.equals(SAML2IDP.TYPE_ID) && id instanceof String)
            return getIDP((String)id);
        else if (type.equals(SAML2IDP.TYPE_SOURCEID) && id instanceof byte[])
            return getIDPBySourceID((byte[])id);

        //else not supported
        return null;
    }
    
    /**
     * @see com.alfaariss.oa.authentication.remote.saml2.org.storage.IOrganizationStorage#getIDPBySourceID(byte[])
     */
    /**
     * Returns the IDP based on the SourceID.
     *
     * @param baSourceID Source ID
     * @return The IDP with the SourceID as ID.
     * @throws OAException If database lookup fails
     */
    protected SAML2IDP getIDPBySourceID(byte[] baSourceID) throws OAException
    {
        return retrieveBySourceID(baSourceID);
    }

    private void createQueries(IConfigurationManager configManager, Element config) throws OAException
    {
        Connection connection = null;
        PreparedStatement pVerify = null;
        try
        {  
            connection = _dataSource.getConnection();
        	
        	Element eValidation = configManager.getSection(config, "validation");
            StringBuffer sbSelectIDPs = new StringBuffer("SELECT ");
            sbSelectIDPs.append(COLUMN_ID).append(",");
            sbSelectIDPs.append(COLUMN_SOURCEID).append(",");
            sbSelectIDPs.append(COLUMN_FRIENDLYNAME).append(",");
            sbSelectIDPs.append(COLUMN_METADATA_URL).append(",");
            sbSelectIDPs.append(COLUMN_METADATA_TIMEOUT).append(",");
            sbSelectIDPs.append(COLUMN_METADATA_FILE).append(",");
            sbSelectIDPs.append(COLUMN_ACS_INDEX).append(",");
            sbSelectIDPs.append(COLUMN_ALLOW_CREATE).append(",");
            sbSelectIDPs.append(COLUMN_SCOPING).append(",");
            sbSelectIDPs.append(COLUMN_NAMEIDPOLICY).append(",");
            sbSelectIDPs.append(COLUMN_NAMEIDFORMAT).append(",");
            sbSelectIDPs.append(COLUMN_AVOID_SUBJCONF).append(",");
            sbSelectIDPs.append(COLUMN_DISABLE_SSO).append(",");
            sbSelectIDPs.append(COLUMN_DATELASTMODIFIED);
            sbSelectIDPs.append(" FROM ");
            sbSelectIDPs.append(_sTable);
            
            StringBuffer sbVerify = new StringBuffer(sbSelectIDPs);
            sbVerify.append(" LIMIT 1");
            
            validateTable(configManager, connection, eValidation, "saml2_orgs", sbVerify.toString());
            
            sbSelectIDPs.append(" WHERE ");
            sbSelectIDPs.append(COLUMN_ENABLED);
            sbSelectIDPs.append("=?");
            _sQuerySelectAll = sbSelectIDPs.toString();
            _oLogger.info("Using select all IDPs query: " + _sQuerySelectAll);
            
            StringBuffer sbSelectOnID = new StringBuffer(sbSelectIDPs);
            sbSelectOnID.append(" AND ");
            sbSelectOnID.append(COLUMN_ID);
            sbSelectOnID.append("=?");
            _sQuerySelectOnID = sbSelectOnID.toString();
            _oLogger.info("Using organization select on ID query: " + _sQuerySelectOnID);
                        
            StringBuffer sbSelectOnSourceID = new StringBuffer(sbSelectIDPs);
            sbSelectOnSourceID.append(" AND ");
            sbSelectOnSourceID.append(COLUMN_SOURCEID);
            sbSelectOnSourceID.append("=?");
            _sQuerySelectOnSourceID = sbSelectOnSourceID.toString();
            _oLogger.info("Using organization select on SourceID query: " + _sQuerySelectOnSourceID);

        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _oLogger.fatal("Internal error during start", e);
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
                _oLogger.error("Could not close verification statement", e);
            }
                        
            try
            {
                if (connection != null)
                    connection.close();
            }
            catch (Exception e)
            {
                _oLogger.error("Could not close connection", e);
            }
        }
    }
    
    private SAML2IDP retrieveByID(String id) throws OAException
    {
        Connection connection = null;
        PreparedStatement pSelect = null;
        ResultSet resultSet = null;
        SAML2IDP saml2IDP = null;
        
        IMetadataProviderManager oMPM = MdMgrManager.getInstance().getMetadataProviderManager(_sId);
        
        try
        {
            connection = _dataSource.getConnection();
            
            pSelect = connection.prepareStatement(_sQuerySelectOnID);
            pSelect.setBoolean(1, true);
            pSelect.setString(2, id);
            resultSet = pSelect.executeQuery();
            if (resultSet.next())
            {
                boolean bACSIndex = resultSet.getBoolean(COLUMN_ACS_INDEX);
                
                Boolean boolAllowCreate = null;
                String sAllowCreate = resultSet.getString(COLUMN_ALLOW_CREATE);
                if (sAllowCreate != null)
                {
                    boolean bAllowCreate = resultSet.getBoolean(COLUMN_ALLOW_CREATE);
                    boolAllowCreate = new Boolean(bAllowCreate);
                }
                
                boolean bScoping = resultSet.getBoolean(COLUMN_SCOPING);
                boolean bNameIDPolicy = resultSet.getBoolean(COLUMN_NAMEIDPOLICY);
                boolean bAvoidSubjectConfirmation = resultSet.getBoolean(COLUMN_AVOID_SUBJCONF);
                boolean bDisableSSOForIDP = resultSet.getBoolean(COLUMN_DISABLE_SSO);

                Date dLastModified = null;
            	try {
            		dLastModified = resultSet.getTimestamp(COLUMN_DATELASTMODIFIED);
            	} catch (Exception e) {
            		_oLogger.info("No "+COLUMN_DATELASTMODIFIED+" column found for SAML2IDP '"+id+"'; ignoring.");
            	}

                
                saml2IDP = new SAML2IDP(id, 
                    resultSet.getBytes(COLUMN_SOURCEID),
                    resultSet.getString(COLUMN_FRIENDLYNAME),
                    resultSet.getString(COLUMN_METADATA_FILE),
                    resultSet.getString(COLUMN_METADATA_URL),
                    resultSet.getInt(COLUMN_METADATA_TIMEOUT),
                    bACSIndex, boolAllowCreate, 
                    bScoping, bNameIDPolicy,
                    resultSet.getString(COLUMN_NAMEIDFORMAT),
                    bAvoidSubjectConfirmation,
                    bDisableSSOForIDP,
                    dLastModified,
                    oMPM.getId());
            }
        }
        catch(OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _oLogger.fatal("Internal error during retrieval of organization with ID: " + id, e);
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
                _oLogger.error("Could not close select statement", e);
            }
                        
            try
            {
                if (connection != null)
                    connection.close();
            }
            catch (Exception e)
            {
                _oLogger.error("Could not close connection", e);
            }
        }
        return saml2IDP;
    }
    
    private SAML2IDP retrieveBySourceID(byte[] baSourceID) throws OAException
    {
        Connection connection = null;
        PreparedStatement pSelect = null;
        ResultSet resultSet = null;
        SAML2IDP saml2IDP = null;
        
        IMetadataProviderManager oMPM = MdMgrManager.getInstance().getMetadataProviderManager(_sId);
        
        try
        {
            connection = _dataSource.getConnection();
            
            pSelect = connection.prepareStatement(_sQuerySelectOnSourceID);
            pSelect.setBoolean(1, true);
            pSelect.setBytes(2, baSourceID);
            resultSet = pSelect.executeQuery();
            if (resultSet.next())
            {
                boolean bACSIndex = resultSet.getBoolean(COLUMN_ACS_INDEX);
                
                Boolean boolAllowCreate = null;
                String sAllowCreate = resultSet.getString(COLUMN_ALLOW_CREATE);
                if (sAllowCreate != null)
                {
                    boolean bAllowCreate = resultSet.getBoolean(COLUMN_ALLOW_CREATE);
                    boolAllowCreate = new Boolean(bAllowCreate);
                }
                
                boolean bScoping = resultSet.getBoolean(COLUMN_SCOPING);
                boolean bNameIDPolicy = resultSet.getBoolean(COLUMN_NAMEIDPOLICY);
                boolean bAvoidSubjectConfirmation = resultSet.getBoolean(COLUMN_AVOID_SUBJCONF);
                boolean bDisableSSOForIDP = resultSet.getBoolean(COLUMN_DISABLE_SSO);

                Date dLastModified = null;
            	try {
            		dLastModified = resultSet.getTimestamp(COLUMN_DATELASTMODIFIED);
            	} catch (Exception e) {
            		_oLogger.info("No "+COLUMN_DATELASTMODIFIED+" column found for SAML2IDP with sourceid '"+baSourceID+"'; ignoring.");
            	}
                
                saml2IDP = new SAML2IDP(resultSet.getString(COLUMN_ID),
                    baSourceID,
                    resultSet.getString(COLUMN_FRIENDLYNAME),
                    resultSet.getString(COLUMN_METADATA_FILE),
                    resultSet.getString(COLUMN_METADATA_URL),
                    resultSet.getInt(COLUMN_METADATA_TIMEOUT),
                    bACSIndex, boolAllowCreate, 
                    bScoping, bNameIDPolicy,
                    resultSet.getString(COLUMN_NAMEIDFORMAT),
                    bAvoidSubjectConfirmation,
                    bDisableSSOForIDP,
                    dLastModified,
                    oMPM.getId());
            }
        }
        catch(OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _oLogger.fatal("Internal error during retrieval of organization with SourceID: " 
                + baSourceID, e);
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
                _oLogger.error("Could not close select statement", e);
            }
                        
            try
            {
                if (connection != null)
                    connection.close();
            }
            catch (Exception e)
            {
                _oLogger.error("Could not close connection", e);
            }
        }
        return saml2IDP;
    }
    
    
    //TODO move to utility class
    private void validateTable(IConfigurationManager configManager, Connection oConnection, 
    		Element eValidation, String table, String sDefault) throws DatabaseException, SQLException
    {
        String sVerificationQuery = null;
        PreparedStatement pVerification = null;
        try
        {
            if(eValidation != null)
            {
                Element e = configManager.getSection(eValidation, table);
                if(e != null)
                {
                    sVerificationQuery = configManager.getParam(e, "query");
                    if(sVerificationQuery == null || sVerificationQuery.length() == 0)
                    {
                        //DD Do not verify the table if empty query configured
                        _oLogger.warn("Empty validation query found, table structure is not validated for table:  " + table);
                        //finally is executed before return
                        return;
                    }
                    _oLogger.info("Validation query found: " + sVerificationQuery);
                }
            }
            
            if(sVerificationQuery == null)
            {
                //DD Use default query if no query parameter configured                               
                sVerificationQuery = sDefault;
                _oLogger.info("No validation query found, using default: " + sDefault);
            }
            
            pVerification = oConnection.prepareStatement(sVerificationQuery);
            try
            {
                pVerification.executeQuery();
            }
            catch(Exception e)
            {
                StringBuffer sbError = new StringBuffer("Invalid table configured '");
                sbError.append(table);
                sbError.append("' verified with query: ");
                sbError.append(sVerificationQuery);
                _oLogger.error(sbError.toString(), e);
                throw new DatabaseException(SystemErrors.ERROR_INIT);
            }        
            _oLogger.info("Table structure validated for table: " + table);
        }
        catch(ConfigurationException e)
        {            
        	_oLogger.error("Invalid validation query found for table: " + table, e);
            throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
        }
        finally
        {
            try
            {
                if (pVerification != null)
                    pVerification.close();
            }
            catch (Exception e)
            {
            	_oLogger.error("Could not close verification statement", e);
            }
        }
    } 
}
