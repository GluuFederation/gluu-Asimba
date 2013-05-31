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
package com.alfaariss.oa.engine.requestor.jdbc;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.requestor.Requestor;
import com.alfaariss.oa.engine.core.requestor.RequestorException;

/**
 * Creates the requestor from a JDBC resource.
 * <br>
 * This requestor is read at runtime from a database table, 
 * specified by the resource configuration.               
 * 
 * @author MHO
 * @author Alfa & Ariss
 */
public class JDBCRequestor
{
    /** id */
    public static final String COLUMN_ID = "id";
    /** friendly name */
    public static final String COLUMN_FRIENDLYNAME = "friendlyname";
    /** enabled */
    public static final String COLUMN_ENABLED = "enabled";
    /** pool_id */
    public static final String COLUMN_POOLID = "pool_id";   
    /** date last modified */
    public static final String COLUMN_DATELASTMODIFIED = "date_last_modified";
    
    /** Requestor ID */
    public static final String COLUMN_PROPERTY_REQUESTOR_ID = "requestor_id";
    /** Requestor property Name */
    public static final String COLUMN_PROPERTY_NAME = "name";
    /** Requestor property Value */
    public static final String COLUMN_PROPERTY_VALUE = "value";
    
    private static Log _logger;
    private IRequestor _oRequestor;
    
    /**
     * Creates the object.
     * @param rsRequestor containing a row with all requestor information
     * @param rsProperties containing a row with all requestor properties
     * @throws RequestorException if creation fails
     */
    public JDBCRequestor(ResultSet rsRequestor, ResultSet rsProperties) throws RequestorException
    {
        try
        {
            _logger = LogFactory.getLog(JDBCRequestor.class);
            _oRequestor = getRequestor(rsRequestor, rsProperties);
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during create", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Returns a Requestor object.
     * <br>
     * @return IRequestor that is a Requestor
     */
    public IRequestor getRequestor()
    {
        return _oRequestor;
    }
    
    /**
     * Creates a Requestor object.
     * <br>
     * @param rsRequestor containing the requestor information 
     * @return Requestor object
     * @throws RequestorException if creation fails
     */
    private Requestor getRequestor(ResultSet rsRequestor, ResultSet rsProperties) 
        throws RequestorException
    {
        Requestor oRequestor = null;
        try
        {
            String sID = rsRequestor.getString(COLUMN_ID);
            
            String sFriendlyName = rsRequestor.getString(COLUMN_FRIENDLYNAME);
            if (sFriendlyName == null)
            {
                StringBuffer sbWarn = new StringBuffer("No '");
                sbWarn.append(COLUMN_FRIENDLYNAME);
                sbWarn.append("' available for requestor with id: ");
                sbWarn.append(sID);
                _logger.error(sbWarn.toString());
                throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }
            
            boolean bEnabled = rsRequestor.getBoolean(COLUMN_ENABLED);          
            Properties prop = new Properties();
            
            while (rsProperties.next())
            {
                String sName = rsProperties.getString(JDBCRequestor.COLUMN_PROPERTY_NAME);
                Object value = rsProperties.getString(JDBCRequestor.COLUMN_PROPERTY_VALUE);
                prop.put(sName, value);
            }
            _logger.debug("Retrieved properties: " + prop);

            Date dLastModified = null;
        	try {
        		dLastModified = rsRequestor.getTimestamp(JDBCRequestor.COLUMN_DATELASTMODIFIED);
        	} catch (Exception e) {
        		_logger.info("No "+JDBCRequestor.COLUMN_DATELASTMODIFIED+" column found for requestor '"+sID+"'; ignoring.");
        	}
            
            oRequestor = new Requestor(sID, sFriendlyName, bEnabled, prop, dLastModified);
        }
        catch (RequestorException e)
        {
            throw e;
        }
        catch (SQLException e)
        {
            _logger.error("Can not read from database", e);
            throw new RequestorException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during create of a requestor", e);
            throw new RequestorException(SystemErrors.ERROR_INTERNAL);
        }
        
        return oRequestor;
    }

}
