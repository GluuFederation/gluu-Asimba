/*
 * * Asimba - Serious Open Source SSO

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
 * * Asimba - Serious Open Source SSO - More information on www.asimba.org

 * 
 */
package com.alfaariss.oa.engine.attribute.release.jdbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Enumeration;
import java.util.Vector;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.engine.core.attribute.AttributeException;
import com.alfaariss.oa.engine.core.attribute.UserAttributes;
import com.alfaariss.oa.engine.core.attribute.release.IAttributeReleasePolicy;

/**
 * Release policy class.
 *
 * Reads configuration from the configuration document and matches the 
 * attribute names with or without wildcard (*).
 * @author MHO
 * @author Alfa & Ariss
 */
public class JDBCPolicy implements IAttributeReleasePolicy
{
    /** id */
    public static final String COLUMN_POLICY_ID = "id";
    /** friendlyname */
    public static final String COLUMN_POLICY_FRIENDLYNAME = "friendlyname";
    /** enabled */
    public static final String COLUMN_POLICY_ENABLED = "enabled";
    /** attribute */
    public static final String COLUMN_ATTRIBUTE_POLICY_ID = "policy_id";
    /** attribute */
    public static final String COLUMN_ATTRIBUTE_ATTRIBUTE = "expression";

    private static Log _logger;
    private String _sID;
    private String _sFriendlyName;
    private boolean _bEnabled;
    private Vector<String> _vAttributeNames;
    
    /**
     * Initializes the policy.
     * 
     * @param dataSource the JDBC datasource
     * @param resultSet A resultset containing a row with policy information
     * @param attributeTable attribute table name
     * @throws AttributeException if initialization fails
     */
    public JDBCPolicy (DataSource dataSource, ResultSet resultSet,
        String attributeTable) throws AttributeException
    {
        try
        {
            _logger = LogFactory.getLog(JDBCPolicy.class);
            
            _sID = resultSet.getString(COLUMN_POLICY_ID);
            _sFriendlyName = resultSet.getString(COLUMN_POLICY_FRIENDLYNAME);
            _bEnabled = resultSet.getBoolean(COLUMN_POLICY_ENABLED);
            
            _vAttributeNames = readAttributes(dataSource, attributeTable);
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Applies the policy to the given attributes.
     * @see com.alfaariss.oa.engine.core.attribute.release.IAttributeReleasePolicy#apply(com.alfaariss.oa.api.attribute.IAttributes)
     */
    public IAttributes apply(IAttributes attributes) throws AttributeException
    {
        IAttributes oReturnAttributes = new UserAttributes();
        try
        {
            if (_bEnabled)
            {
                Enumeration enumNames = attributes.getNames();
                while (enumNames.hasMoreElements())
                {
                    String sName = (String)enumNames.nextElement();
                    if (matches(sName))
                        oReturnAttributes.put(sName, 
                            attributes.getFormat(sName), attributes.get(sName));
                }
            }
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during apply of release policy: " + _sID, e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
        }
        return oReturnAttributes;
    }

    /**
     * This policy its friendly name.
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }

    /**
     * This policy its unique ID.
     * @see com.alfaariss.oa.api.IManagebleItem#getID()
     */
    public String getID()
    {
        return _sID;
    }

    /**
     * Return TRUE if this policy is enabled.
     * @see com.alfaariss.oa.api.IManagebleItem#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        return _sID;
    }

    private Vector<String> readAttributes(DataSource dataSource,
        String attributeTable) throws AttributeException
    {
        Vector<String> vAttributeNames = new Vector<String>();
        Connection oConnection = null;
        PreparedStatement oPreparedStatement = null;
        ResultSet oResultSet = null;
        try
        {
            oConnection = dataSource.getConnection();
            
            StringBuffer sbSelect = new StringBuffer("SELECT ");
            sbSelect.append(COLUMN_ATTRIBUTE_ATTRIBUTE);
            sbSelect.append(" FROM ");
            sbSelect.append(attributeTable);
            sbSelect.append(" WHERE ");
            sbSelect.append(COLUMN_ATTRIBUTE_POLICY_ID);
            sbSelect.append("=?");
            
            oPreparedStatement = oConnection.prepareStatement(sbSelect.toString());
            oPreparedStatement.setString(1, _sID);
            oResultSet = oPreparedStatement.executeQuery();
            while (oResultSet.next())
            {
                vAttributeNames.add(oResultSet.getString(COLUMN_ATTRIBUTE_ATTRIBUTE));
            }
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during initialization", e);
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
                _logger.error("Could not close connection", e);
            }
        }
        return vAttributeNames;
    }

    /**
     * Matches the supplied attribute name with the policy.
     *
     * Matches agains the configured attribute names or wildcard combination:
     * <ul>
     * <li>*</li>
     * <li>*[matching chars]</li>
     * <li>*[matching chars]*</li>
     * <li>[matching chars]*</li> 
     * <li>exact match</li>
     * </ul>
     * @param sName the name to match the policy
     * @return TRUE if the attribute matches the policy
     */
    private boolean matches(String sName)
    {
        if (_vAttributeNames.contains(sName))
            return true;
            
        for (String sReleaseName: _vAttributeNames)
        {
            int iWildcard = sReleaseName.indexOf("*");
            if (iWildcard == 0)
            {
                String sEnd = sReleaseName.substring(1, sReleaseName.length());
                if (sEnd.length() == 0)//support: *
                    return true;
                else if (sName.endsWith(sEnd))//support: *[name]
                    return true;
                else if (sEnd.endsWith("*"))
                {
                    String sIntermediate = sEnd.substring(0, sEnd.length() - 1);
                    if (sName.contains(sIntermediate))//support: *[name]*
                        return true;
                }
            }  
            else if (iWildcard == sReleaseName.length()-1)
            {
                String sStart = sReleaseName.substring(0, iWildcard);
                if (sName.startsWith(sStart))//support: [name]*
                    return true;
            }
        }
        return false;
    }
}
