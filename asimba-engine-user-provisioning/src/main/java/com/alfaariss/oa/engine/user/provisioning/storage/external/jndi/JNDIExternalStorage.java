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
package com.alfaariss.oa.engine.user.provisioning.storage.external.jndi;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.InvalidSearchFilterException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.engine.user.provisioning.storage.IStorage;
import com.alfaariss.oa.engine.user.provisioning.storage.external.IExternalStorage;
import com.alfaariss.oa.util.ldap.JNDIUtil;
/**
 * JNDI external storage object.
 * <br>
 * Uses the configured JNDI storage as external storage.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class JNDIExternalStorage implements IExternalStorage 
{
    private Log _logger;
    private String _sDNBase;
    private String _sDNUser;
    private String _sFilter;
    private Hashtable<String,String> _htJNDIEnvironment;

	/**
	 * Creates the object.
	 */
	public JNDIExternalStorage()
    {
        _logger = LogFactory.getLog(JNDIExternalStorage.class);
        _sDNBase = null;
        _sDNUser = null;
        _sFilter = null;
        _htJNDIEnvironment = null;
	}

    /**
     * Starts the JNDI object.
     * @see IStorage#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws UserException
    {
        InitialDirContext context = null;
	    try
        {
            Element eResource = oConfigurationManager.getSection(eConfig, "resource");
            if(eResource == null)
            {
                _logger.error("No 'resource' section found in configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eDN = oConfigurationManager.getSection(eResource, "dn");
            if(eDN == null)
            {
                _logger.error("No 'dn' section found in 'resource' section in configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _sDNBase = oConfigurationManager.getParam(eDN, "base");
            if(_sDNBase == null)
            {
                _logger.error("No 'dn' item found in 'base' section in configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }

            _sDNUser = oConfigurationManager.getParam(eDN, "user");
            _sFilter = oConfigurationManager.getParam(eDN, "filter");
            if (_sFilter != null && _sDNUser != null)
            {
                _logger.error("Invalid configuration: Both 'user' and 'filter' item found in 'base' section in configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            else if (_sFilter != null)
            {
                _logger.info("Using search filter: " + _sFilter);
            }
            else if (_sDNUser != null)
            {
                _logger.info("Generating search filter with user: " + _sDNUser);
            }
            else
            {
                _logger.error("No 'user' or 'filter' item found in 'base' section in configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _htJNDIEnvironment = readJNDIContext(oConfigurationManager, eResource);
           
            //test connection
            context = new InitialDirContext(_htJNDIEnvironment);
            
        }
        catch (UserException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Could not create object", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            //Close context
            try
            {
                if(context != null)
                    context.close();
            }
            catch (NamingException e)
            {
                _logger.error("Could not close initial context", e);
            }
        }
	}

    /**
     * Returns <code>true</code> if the supplied id is found in the JNDI storage.
     * @see IStorage#exists(java.lang.String)
     */
    public boolean exists(String id) throws UserException
    {
        DirContext oDirContext = null;
        NamingEnumeration oNamingEnumeration = null;
        
        boolean bReturn = false;
        try
        {       
            try
            {
                oDirContext = new InitialDirContext(_htJNDIEnvironment);
            }
            catch (NamingException e)
            {
                _logger.error(
                    "Could not create the connection: " + _htJNDIEnvironment);
                throw new UserException(SystemErrors.ERROR_RESOURCE_CONNECT, e);
            }
            
            SearchControls oScope = new SearchControls();
            oScope.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            String searchFilter = resolveSearchQuery(id);
            try
            {
                oNamingEnumeration = oDirContext.search(
                    _sDNBase, searchFilter, oScope);
                bReturn = oNamingEnumeration.hasMore();
            }
            catch (InvalidSearchFilterException e)
            {
                _logger.error("Wrong filter: " + searchFilter);
                throw new UserException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
            }
            catch (NamingException e)
            {
                _logger.debug("User unknown, naming exception. query: " 
                    + searchFilter, e);
                return false; //user unknown
            }
        }
        catch (UserException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Could not verify if user exists: " + id, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
        }
        finally
        {
            if (oNamingEnumeration != null)
            {
                try
                {
                    oNamingEnumeration.close();
                }
                catch (Exception e)
                {
                    _logger.error(
                        "Could not close Naming Enumeration after searching for user with id: " 
                        + id, e);
                }
            }
            if (oDirContext != null)
            {
                try
                {
                    oDirContext.close();
                }
                catch (NamingException e)
                {
                    _logger.error(
                        "Could not close Dir Context after searching for user with id: " 
                        + id, e);
                }
            }
        }
        return bReturn;
    }

    /**
     * Returns the field value of the specified field for the specified id. 
     * @see IExternalStorage#getField(java.lang.String, java.lang.String)
     */
    public Object getField(String id, String field) throws UserException
    {
        DirContext oDirContext = null;
        NamingEnumeration oNamingEnumeration = null;
        Object oValue = null;
        try
        {
            try
            {
                oDirContext = new InitialDirContext(_htJNDIEnvironment);
            }
            catch (NamingException e)
            {
                _logger.error("Could not create the connection: " 
                    + _htJNDIEnvironment);
                throw new UserException(SystemErrors.ERROR_RESOURCE_CONNECT, e);
            }
            
            SearchControls oScope = new SearchControls();
            oScope.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            String searchFilter = resolveSearchQuery(id);
            try
            {
                oNamingEnumeration = oDirContext.search(
                    _sDNBase, searchFilter, oScope);
            }
            catch (InvalidSearchFilterException e)
            {
                StringBuffer sbFailed = new StringBuffer("Wrong filter: ");
                sbFailed.append(searchFilter);
                sbFailed.append(" while searching for attribute '");
                sbFailed.append(field);
                sbFailed.append("' for id: ");
                sbFailed.append(id);
                _logger.error(sbFailed.toString(), e);
                throw new UserException(SystemErrors.ERROR_INTERNAL, e);
            }
            catch (NamingException e)
            {
                _logger.error("User unknown: " + id);
                throw new UserException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
            }
        
            if (!oNamingEnumeration.hasMore())
            {
                StringBuffer sbFailed = new StringBuffer("User with id '");
                sbFailed.append(id);
                sbFailed.append("' not found after LDAP search with filter: ");
                sbFailed.append(searchFilter);
                _logger.error(sbFailed.toString());
                throw new UserException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }

            SearchResult oSearchResult = (SearchResult)oNamingEnumeration.next();
            Attributes oAttributes = oSearchResult.getAttributes();
            NamingEnumeration oAttrEnum = oAttributes.getAll();
            if (oAttrEnum.hasMore())
            {
                Attribute oAttribute = (Attribute)oAttrEnum.next();
                oValue = oAttribute.get();
            }
        }
        catch (UserException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Could not retrieve field: " + field, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
        }
        finally
        {
            if (oNamingEnumeration != null)
            {
                try
                {
                    oNamingEnumeration.close();
                }
                catch (Exception e)
                {
                    _logger.error(
                        "Could not close Naming Enumeration after searching for user with id: " 
                        + id, e);
                }
            }
            if (oDirContext != null)
            {
                try
                {
                    oDirContext.close();
                }
                catch (NamingException e)
                {
                    _logger.error(
                        "Could not close Dir Context after searching for user with id: " 
                        + id, e);
                }
            }
        }
        return oValue;
    }
    
    /**
     * Returns the values of the specified fields for the supplied id. 
     * @see IExternalStorage#getFields(java.lang.String, java.util.List)
     */
    public Hashtable<String, Object> getFields(
        String id, List<String> fields) throws UserException
    {
        Hashtable<String, Object> htReturn = new Hashtable<String, Object>();
        DirContext oDirContext = null;
        NamingEnumeration oNamingEnumeration = null;
        try
        {
            try
            {
                oDirContext = new InitialDirContext(_htJNDIEnvironment);
            }
            catch (NamingException e)
            {
                _logger.error("Could not create the connection: " 
                    + _htJNDIEnvironment);
                throw new UserException(SystemErrors.ERROR_RESOURCE_CONNECT, e);
            }
            
            SearchControls oScope = new SearchControls();
            oScope.setSearchScope(SearchControls.SUBTREE_SCOPE);
            String[] saFields = fields.toArray(new String[0]);
            oScope.setReturningAttributes(saFields);
            
            String searchFilter = resolveSearchQuery(id);
            try
            {
                oNamingEnumeration = oDirContext.search(
                    _sDNBase, searchFilter, oScope);
            }
            catch (InvalidSearchFilterException e)
            {
                StringBuffer sbFailed = new StringBuffer("Wrong filter: ");
                sbFailed.append(searchFilter);
                sbFailed.append(" while searching for attributes '");
                sbFailed.append(fields);
                sbFailed.append("' for id: ");
                sbFailed.append(id);
                _logger.error(sbFailed.toString(), e);
                throw new UserException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
            }
            catch (NamingException e)
            {
                _logger.error("User unknown: " + id);
                throw new UserException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
            }
        
            if (!oNamingEnumeration.hasMore())
            {
                StringBuffer sbFailed = new StringBuffer("User with id '");
                sbFailed.append(id);
                sbFailed.append("' not found after LDAP search with filter: ");
                sbFailed.append(searchFilter);
                _logger.error(sbFailed.toString());
                throw new UserException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }

            SearchResult oSearchResult = (SearchResult)oNamingEnumeration.next();
            Attributes oAttributes = oSearchResult.getAttributes();
            NamingEnumeration neAttributes = oAttributes.getAll();
            while (neAttributes.hasMore())
            {
                Attribute oAttribute = (Attribute)neAttributes.next();
                String sAttributeName = oAttribute.getID();
                
                if (oAttribute.size() > 1)
                {
                    Vector<Object> vValue = new Vector<Object>();
                    NamingEnumeration neAttribute = oAttribute.getAll();
                    while (neAttribute.hasMore())
                        vValue.add(neAttribute.next());
                    
                    htReturn.put(sAttributeName, vValue);                                                        
                }
                else
                {                      
                    Object oValue = oAttribute.get();
                    if (oValue == null) oValue = "";
                    htReturn.put(sAttributeName, oValue);
                }  
            }
        }
        catch (UserException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not retrieve fields: " + fields, e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
        }
        finally
        {
            if (oNamingEnumeration != null)
            {
                try
                {
                    oNamingEnumeration.close();
                }
                catch (Exception e)
                {
                    _logger.error(
                        "Could not close Naming Enumeration after searching for user with id: " 
                        + id, e);
                }
            }
            if (oDirContext != null)
            {
                try
                {
                    oDirContext.close();
                }
                catch (NamingException e)
                {
                    _logger.error(
                        "Could not close Dir Context after searching for user with id: " 
                        + id, e);
                }
            }
        }
        return htReturn;
    }

    /**
     * Stops the object.
     * @see com.alfaariss.oa.engine.user.provisioning.storage.IStorage#stop()
     */
    public void stop()
    {
        //do nothing
    }
    
    /**
     * Reads JNDI connection information from the configuration.
     * <br>
     * Creates an <code>Hashtable</code> containing the JNDI environment variables.
     * @param oConfigurationManager The configuration manager
     * @param eConfig the configuration section
     * @return <code>DirContext</code> that contains the JNDI connection
     * @throws UserException if configuration reading fails
     */
    private Hashtable<String,String> readJNDIContext(
        IConfigurationManager oConfigurationManager, Element eConfig) 
        throws UserException
    {
        Hashtable<String,String> htEnvironment = new Hashtable<String,String>();
        
        try
        {
            Element eSecurityPrincipal = oConfigurationManager.getSection(
                eConfig, "security_principal");
            if (eSecurityPrincipal == null)
            {
                _logger.error(
                    "No 'security_principal' section found in 'resource' configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
    
            String sPrincipal = oConfigurationManager.getParam(
                eSecurityPrincipal, "dn");
            if(sPrincipal == null)
            {
                _logger.error("No item 'dn' item found in configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
    
            String sPassword = oConfigurationManager.getParam(
                eSecurityPrincipal, "password");
            if(sPassword == null)
            {
                _logger.error("No 'password' item found in configuration ");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sDriver = oConfigurationManager.getParam(eConfig, "driver");
            if(sDriver == null)
            {
                _logger.error("No 'driver' item found in configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sUrl = oConfigurationManager.getParam(eConfig, "url");
            if(sUrl == null)
            {
                _logger.error("No valid config item 'url' found in configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            if (sUrl.length() >= 5 && 
                sUrl.substring(0,5).equalsIgnoreCase("ldaps"))
            {
                // Request SSL transport
                htEnvironment.put(Context.SECURITY_PROTOCOL, "ssl");
                _logger.info("SSL enabled");
            }
            else
            {
                _logger.info("SSL disabled");
            }
            
            htEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, sDriver);
            htEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");
            htEnvironment.put(Context.SECURITY_PRINCIPAL, sPrincipal);
            htEnvironment.put(Context.SECURITY_CREDENTIALS, sPassword);
            htEnvironment.put(Context.PROVIDER_URL, sUrl);
            
        }
        catch (UserException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Could not create a connection", e);
            throw new UserException(SystemErrors.ERROR_INTERNAL, e);
        }
        return htEnvironment;
    }

    private String resolveSearchQuery(String user)
    {
        String escapedUser = JNDIUtil.escapeLDAPSearchFilter(user);
        
        if (_sFilter != null)
            return _sFilter.replaceAll("\\?", escapedUser);
        
        StringBuffer sbQuery = new StringBuffer();
        sbQuery.append("(");
        sbQuery.append(_sDNUser);
        sbQuery.append("=");
        sbQuery.append(escapedUser);
        sbQuery.append(")");
        return sbQuery.toString();
    }
}