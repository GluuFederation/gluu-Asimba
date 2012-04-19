/*
 * Asimba Server
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
package com.alfaariss.oa.util.idmapper.jndi;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.InvalidNameException;
import javax.naming.Name;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.InvalidSearchFilterException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.idmapper.IIDMapper;
import com.alfaariss.oa.util.ldap.JNDIUtil;

/**
 * JNDI id mapper implementation.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.3
 */
public class JNDIMapper implements IIDMapper
{
    private Log _logger;
    private String _sDNBase;
    private String _sIDAttribute;
    private String _sMapperAttribute;
    private Hashtable<String,String> _htJNDIEnvironment;
    
    
    /**
     * Constructor. 
     */
    public JNDIMapper()
    {
        _logger = LogFactory.getLog(JNDIMapper.class);
        _sDNBase = null;
        _sIDAttribute = null;
        _sMapperAttribute = null;
        _htJNDIEnvironment = null;
    }
    
    /**
     * @see com.alfaariss.oa.api.idmapper.IIDMapper#map(java.lang.String)
     */
    public String map(String id) throws OAException
    {
        if (id == null)
            throw new IllegalArgumentException("Could not map: NULL");

        String sReturn = null;
        DirContext oDirContext = null;
        try
        {
            try
            {
                oDirContext = new InitialDirContext(_htJNDIEnvironment);
            }
            catch (NamingException e)
            {
                _logger.error("Could not create the connection: " + _htJNDIEnvironment, e);
                throw new OAException(SystemErrors.ERROR_RESOURCE_CONNECT);
            }
            
            try
            {
                if (_sIDAttribute == null)
                {//must be null, otherwise you can't do the inverse
                    Name nameLdap = new LdapName(id);
                    if (_sMapperAttribute != null)
                        return getAttributes(oDirContext, _sMapperAttribute, nameLdap);
                    
                    _logger.error("Can't map: no mapper attribute name configured");
                    throw new OAException(SystemErrors.ERROR_RESOURCE_CONNECT);
                }
                
                sReturn = searchAttributes(oDirContext, _sIDAttribute, _sMapperAttribute, id);
            }
            catch (InvalidNameException e)
            {
                _logger.debug("Supplied id isn't a valid LdapName: " + id);
            }
            
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not map id: " + id, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            if (oDirContext != null)
            {
                try
                {
                    oDirContext.close();
                }
                catch (NamingException e)
                {
                    _logger.error("Could not close Dir Context after mapping id: " 
                        + id, e);
                }
            }
        }
        return sReturn;
    }

    /**
     * @see com.alfaariss.oa.api.idmapper.IIDMapper#remap(java.lang.String)
     */
    public String remap(String id) throws OAException
    {
        if (id == null)
            throw new IllegalArgumentException("Could not remap: NULL");

        String sReturn = null;
        DirContext oDirContext = null;
        try
        {
            try
            {
                oDirContext = new InitialDirContext(_htJNDIEnvironment);
            }
            catch (NamingException e)
            {
                _logger.error("Could not create the connection: " + _htJNDIEnvironment, e);
                throw new OAException(SystemErrors.ERROR_RESOURCE_CONNECT);
            }
            
            try
            {
                if (_sMapperAttribute == null)
                {//must be null, otherwise you can't do the inverse
                    Name nameLdap = new LdapName(id);
                    if (_sIDAttribute != null)
                        return getAttributes(oDirContext, _sIDAttribute, nameLdap);
                    
                    _logger.error("Can't remap: no id attribute name configured");
                    throw new OAException(SystemErrors.ERROR_RESOURCE_CONNECT);
                }
                
                sReturn = searchAttributes(oDirContext, _sMapperAttribute, _sIDAttribute, id);
            }
            catch (InvalidNameException e)
            {
                _logger.debug("Supplied id isn't a valid LdapName: " + id);
            }
            
            
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not remap id: " + id, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            if (oDirContext != null)
            {
                try
                {
                    oDirContext.close();
                }
                catch (NamingException e)
                {
                    _logger.error("Could not close Dir Context after searching for mapped id: " 
                        + id, e);
                }
            }
        }
        return sReturn;
    }

    /**
     * @see com.alfaariss.oa.api.idmapper.IIDMapper#start(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager configManager, Element config)
        throws OAException
    {
        try
        {
            Element eResource = configManager.getSection(config, "resource");
            if(eResource == null)
            {
                _logger.error("No 'resource' section found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eDN = configManager.getSection(eResource, "dn");
            if(eDN == null)
            {
                _logger.error("No 'dn' section found in 'resource' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _sDNBase = configManager.getParam(eDN, "base");
            if(_sDNBase == null)
            {
                _logger.error("No 'dn' item found in 'base' section in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
                        
            Element eID = configManager.getSection(eDN, "id");
            if(eID == null)
            {
                _logger.warn("No 'id' section found in 'dn' section in configuration");
                _logger.info("Mapping from Distinguished Name (supplied id must be a Distinguished Name)");
                _sIDAttribute = null;
            }
            else
            {
                _sIDAttribute = configManager.getParam(eID, "attribute");
                if(_sIDAttribute == null)
                {
                    _logger.error("No 'attribute' item found in 'id' section in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            Element eMapper = configManager.getSection(eDN, "mapper");
            if(eMapper == null)
            {
                if(_sIDAttribute == null)
                {
                    _logger.error("Invalid id mapper configuration: No 'mapper' section and no 'id' section found in 'dn' section in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                _logger.warn("No 'mapper' section found in 'dn' section in configuration");
                _logger.info("Mapping to Distinguished Name (the Distinguished Name of the searched attribute)");
                _sMapperAttribute = null;
            }
            else
            {
                _sMapperAttribute = configManager.getParam(eMapper, "attribute");
                if(_sMapperAttribute == null)
                {
                    _logger.error("No 'attribute' item found in 'mapper' section in configuration");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            _htJNDIEnvironment = readJNDIContext(configManager, eResource);

            //test connection
            new InitialDirContext(_htJNDIEnvironment);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not initialize object", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * @see com.alfaariss.oa.api.idmapper.IIDMapper#stop()
     */
    public void stop()
    {
        if (_htJNDIEnvironment != null)
            _htJNDIEnvironment.clear();
        _sDNBase = null;
        _sIDAttribute = null;
        _sMapperAttribute = null;
    }

    /**
     * Reads JNDI connection information from the configuration.
     * <br>
     * Creates an <code>Hashtable</code> containing the JNDI environment variables.
     * @param oConfigurationManager The configuration manager
     * @param eConfig the configuration section
     * @return <code>DirContext</code> that contains the JNDI connection
     * @throws OAException if configuration reading fails
     */
    private Hashtable<String,String> readJNDIContext(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws OAException
    {
        Hashtable<String,String> htEnvironment = new Hashtable<String,String>(11);
        
        try
        {
            Element eSecurityPrincipal = oConfigurationManager.getSection(eConfig, "security_principal");
            if (eSecurityPrincipal == null)
            {
                _logger.error("No 'security_principal' section found in 'resource' configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
    
            String sPrincipal = oConfigurationManager.getParam(eSecurityPrincipal, "dn");
            if(sPrincipal == null)
            {
                _logger.error("No item 'dn' item found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
    
            String sPassword = oConfigurationManager.getParam(eSecurityPrincipal, "password");
            if(sPassword == null)
            {
                _logger.error("No 'password' item found in configuration ");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sDriver = oConfigurationManager.getParam(eConfig, "driver");
            if(sDriver == null)
            {
                _logger.error("No 'driver' item found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sUrl = oConfigurationManager.getParam(eConfig, "url");
            if(sUrl == null)
            {
                _logger.error("No valid config item 'url' found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
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
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Could not create a connection", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return htEnvironment;
    }
    
    private String getAttributes(DirContext oDirContext, 
        String sMapperAttribute, Name name) 
        throws OAException
    {
        String sReturn = null;
        try
        {
            if (sMapperAttribute == null)
            {
                _logger.error("No attribute name to map to supplied");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
           
            Attributes attributes = null;
            try
            {
                attributes = oDirContext.getAttributes(name, new String[]{sMapperAttribute});
            }
            catch (InvalidSearchFilterException e)
            {
                StringBuffer sbFailed = new StringBuffer("Could not resolve attribute '");
                sbFailed.append(sMapperAttribute);
                sbFailed.append("' while retrieving attributes for id: ");
                sbFailed.append(name);
                _logger.error(sbFailed.toString(), e);
                throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }
            
            Attribute attrMapping = attributes.get(sMapperAttribute);
            if (attrMapping == null)
            {
                _logger.debug("Attribute not found: " + sMapperAttribute);
            }
            else
            {
                Object oValue = attrMapping.get();
                if (!(oValue instanceof String))
                {
                    StringBuffer sbError = new StringBuffer("Returned value for attribute '");
                    sbError.append(sMapperAttribute);
                    sbError.append("' has a value which is not of type 'String'");
                    _logger.error(sbError.toString());
                    throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
                }
                sReturn = (String)oValue;
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (NamingException e)
        {
            _logger.debug("Failed to fetch mapping attribute for id: " + name);
        }
        catch (Exception e)
        {
            _logger.fatal("Could not retrieve fields for id: " + name, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return sReturn;
    }
    
    private String searchAttributes(DirContext oDirContext, 
        String sIDAttribute, String sMapperAttribute, String id) 
        throws OAException
    {
        String sReturn = null;
        NamingEnumeration oNamingEnumeration = null;
        try
        {
            if (sIDAttribute == null)
            {
                _logger.error("No attribute name to map from supplied");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            StringBuffer sbQuery = new StringBuffer("(");
            sbQuery.append(sIDAttribute);
            sbQuery.append("=");
            sbQuery.append(JNDIUtil.escapeLDAPSearchFilter(id));
            sbQuery.append(")");
            String sSearchQuery = sbQuery.toString();
            
            String sSearchFor = sMapperAttribute;
            if (sSearchFor == null)
                sSearchFor = "*";
            
            SearchControls oScope = new SearchControls();
            oScope.setSearchScope(SearchControls.SUBTREE_SCOPE);
            oScope.setReturningAttributes(new String[]{sSearchFor});
            
            try
            {
                oNamingEnumeration = 
                    oDirContext.search(_sDNBase, sSearchQuery, oScope);
            }
            catch (InvalidSearchFilterException e)
            {
                StringBuffer sbFailed = new StringBuffer("Wrong filter: ");
                sbFailed.append(sSearchQuery);
                sbFailed.append(" while searching for attributes for id: ");
                sbFailed.append(id);
                _logger.error(sbFailed.toString(), e);
                throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }
            
            if (!oNamingEnumeration.hasMore())
            {
                _logger.debug("No result when searching for: " + sSearchQuery);
            }
            else
            {
                SearchResult oSearchResult = (SearchResult)oNamingEnumeration.next();
                
                if (sMapperAttribute == null)
                {
                    sReturn = oSearchResult.getName();
                    sReturn += "," + _sDNBase;
                }
                else
                {
                    Attributes oSearchedAttributes = oSearchResult.getAttributes();
                    Attribute attrMapping = oSearchedAttributes.get(sMapperAttribute);
                    if (attrMapping == null)
                    {
                        _logger.debug("Mapping attribute not found: " + sMapperAttribute);
                    }
                    else
                    {
                        Object oValue = attrMapping.get();
                        if (!(oValue instanceof String))
                        {
                            StringBuffer sbError = new StringBuffer("Returned value for mapping attribute '");
                            sbError.append(_sMapperAttribute);
                            sbError.append("' has a value which is not of type 'String'");
                            _logger.error(sbError.toString());
                            throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
                        }
                        sReturn = (String)oValue;
                    }
                }
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (NamingException e)
        {
            _logger.debug("Failed to fetch mapping attribute for id: " + id, e);
        }
        catch (Exception e)
        {
            _logger.fatal("Could not retrieve fields for id: " + id, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
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
                    _logger.error("Could not close Naming Enumeration after searching for id: " 
                        + id, e);
                }
            }
        }
        return sReturn;
    }
}
