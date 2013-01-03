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
package com.alfaariss.oa.engine.authorization.jdbc;


import java.sql.ResultSet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.engine.core.authorization.AuthorizationException;
import com.alfaariss.oa.engine.core.authorization.AuthorizationMethod;

/**
 * Creates the authorization method from JDBC resource.
 * <br>
 * This method is read at runtime from a database table, 
 * specified by the resource configuration.   
 *  
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class JDBCMethod extends AuthorizationMethod
{
    /** id */
    public static final String COLUMN_METHOD_ID = "id";
    /** profile */
    public static final String COLUMN_PROFILE = "profile_id";

    private static final long serialVersionUID = -3240384803046260936L;

    private static Log _logger;
    
    /**
     * Creates a method object.
     * 
     * @param oResultSet
     * @throws AuthorizationException
     */
    public JDBCMethod(ResultSet oResultSet) throws AuthorizationException
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
            throw new AuthorizationException(SystemErrors.ERROR_INTERNAL);
        }
    }

}
