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
package com.alfaariss.oa.engine.authentication.jdbc;

import java.sql.ResultSet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.engine.core.authentication.AuthenticationException;
import com.alfaariss.oa.engine.core.authentication.AuthenticationMethod;

/**
 * Creates the authentication method from JDBC resource.
 * <br>
 * This method is read at runtime from a database table, 
 * specified by the resource configuration.   
 *  
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class JDBCMethod extends AuthenticationMethod
{
    /** id */
    public static final String COLUMN_METHOD_ID = "id";
    /** profile */
    public static final String COLUMN_PROFILE = "profile_id";
    
    private static final long serialVersionUID = -8798513876097599670L;
    private static Log _logger;
    
    /**
     * Creates a method object.
     * @param oResultSet A resultset containing a row with method information
     * @throws AuthenticationException if creation fails
     */
    public JDBCMethod(ResultSet oResultSet) 
        throws AuthenticationException
    {
        super();
        try
        {
            _logger = LogFactory.getLog(JDBCMethod.class);
            _sID = oResultSet.getString(COLUMN_METHOD_ID);
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
            throw new AuthenticationException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * @see AuthenticationMethod#toString()
     */
    public String toString()
    {
        return _sID;
    }

}
