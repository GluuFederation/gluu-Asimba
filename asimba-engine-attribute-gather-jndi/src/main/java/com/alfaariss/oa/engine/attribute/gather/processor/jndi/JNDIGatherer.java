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
package com.alfaariss.oa.engine.attribute.gather.processor.jndi;
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
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.engine.core.attribute.AttributeException;
import com.alfaariss.oa.engine.core.attribute.gather.processor.IProcessor;
import com.alfaariss.oa.util.ldap.JNDIUtil;

/**
 * Attribute gatherer that resolves attributes from JNDI storage.
 *
 * Reads attributes from a JNDI storage.
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class JNDIGatherer implements IProcessor 
{
    private Log _logger;
    private boolean _bEnabled;
    private String _sID;
    private String _sFriendlyName;
    private String _sDNBase;
    private String _sDNUser;
    private String _sFilter;
    private Hashtable<String,String> _htJNDIEnvironment;
    private Hashtable<String, String> _htMapper;
    private List<String> _listGather;
    
	/**
	 * Creates the object.
	 */
	public JNDIGatherer()
    {
        _logger = LogFactory.getLog(JNDIGatherer.class);
        _sID = null;
        _sFriendlyName = null;
        _bEnabled = false;
        _sDNBase = null;
        _sDNUser = null;
        _sFilter = null;
        _htJNDIEnvironment = null;
        _htMapper = new Hashtable<String, String>();
        _listGather = new Vector<String>();
	}

    /**
     * Starts the object.
     * <br>
     * Reads its configuration and tests the JNDI connection.
     * @see IProcessor#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager, Element eConfig) throws AttributeException
    {
        try
        {
            _bEnabled = true;
            String sEnabled = oConfigurationManager.getParam(eConfig, "enabled");
            if (sEnabled != null)
            {
                if (sEnabled.equalsIgnoreCase("FALSE"))
                    _bEnabled = false;
                else if (!sEnabled.equalsIgnoreCase("TRUE"))
                {
                    _logger.error("Unknown value in 'enabled' configuration item: " + sEnabled);
                    throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            if (!_bEnabled)
                return; //object is disabled, so why should I bother to load its configuration?
            
            _sID = oConfigurationManager.getParam(eConfig, "id");
            if (_sID == null)
            {
                _logger.error("No 'id' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            _sFriendlyName = oConfigurationManager.getParam(eConfig, "friendlyname");
            if (_sFriendlyName == null)
            {
                _logger.error("No 'friendlyname' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eResource = oConfigurationManager.getSection(eConfig, "resource");
            if(eResource == null)
            {
                _logger.error("No 'resource' section found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eDN = oConfigurationManager.getSection(eResource, "dn");
            if(eDN == null)
            {
                _logger.error("No 'dn' section found in 'resource' section in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _sDNBase = oConfigurationManager.getParam(eDN, "base");
            if(_sDNBase == null)
            {
                _logger.error("No 'dn' item found in 'base' section in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }

            _sDNUser = oConfigurationManager.getParam(eDN, "user");
            _sFilter = oConfigurationManager.getParam(eDN, "filter");
            if (_sFilter != null && _sDNUser != null)
            {
                _logger.error("Invalid configuration: Both 'user' and 'filter' item found in 'base' section in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
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
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Element eGather = oConfigurationManager.getSection(eConfig, "gather");
            if (eGather == null)
                _logger.info("No optional 'gather' section found in configuration");
            else
            {
                Element eAttribute = oConfigurationManager.getSection(eGather, "attribute");
                while (eAttribute != null)
                {
                    String sName = oConfigurationManager.getParam(eAttribute, "name");
                    if (sName == null)
                    {
                        _logger.error("No 'name' item found in 'attribute' section");
                        throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    if (sName.trim().length() == 0)
                    {
                        _logger.error("Empty 'name' item found in 'attribute' section");
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    if (_listGather.contains(sName))
                    {
                        _logger.error("Attribute name not unique: " + sName);
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    _listGather.add(sName);
                    
                    eAttribute = oConfigurationManager.getNextSection(eAttribute);
                }
                
                _logger.info("Configured to gather only the following subset: " 
                    + _listGather.toString());
            }
            
            _htJNDIEnvironment = readJNDIContext(oConfigurationManager, eResource);
            
            //test connection
            new InitialDirContext(_htJNDIEnvironment);
            
            Element eMapper = oConfigurationManager.getSection(eConfig, "mapper");
            if (eMapper == null)
                _logger.info("No optional 'mapper' section found in configuration");
            else
            {
                Element eMap = oConfigurationManager.getSection(eMapper, "map");
                while (eMap != null)
                {
                    String sExt = oConfigurationManager.getParam(eMap, "ext");
                    if (sExt == null)
                    {
                        _logger.error("No 'ext' item found in 'map' section");
                        throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    String sInt = oConfigurationManager.getParam(eMap, "int");
                    if (sInt == null)
                    {
                        _logger.error("No 'int' item found in 'map' section");
                        throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
                    }
                    
                    if (_htMapper.containsKey(sExt))
                    {
                        _logger.error("Ext name not unique in map with 'ext' value: " + sExt);
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    if (_htMapper.contains(sInt))
                    {
                        _logger.error("Int name not unique in map with 'int' value: " + sInt);
                        throw new AttributeException(SystemErrors.ERROR_INIT);
                    }
                    
                    _htMapper.put(sExt, sInt);
                    
                    eMap = oConfigurationManager.getNextSection(eMap);
                }
            }

            _logger.info("Started: JDNI Attribute Gatherer");
        }
        catch (AttributeException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not initialize object", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Gathers attributes from JNDI storage to the supplied attributes object.
     * @see com.alfaariss.oa.engine.core.attribute.gather.processor.IProcessor#process(java.lang.String, com.alfaariss.oa.api.attribute.IAttributes)
     */
    public void process(String sUserId, IAttributes oAttributes) throws AttributeException
    {
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
                _logger.error("Could not create the connection: " + _htJNDIEnvironment);
                throw new AttributeException(SystemErrors.ERROR_RESOURCE_CONNECT, e);
            }
            
            SearchControls oScope = new SearchControls();
            oScope.setSearchScope(SearchControls.SUBTREE_SCOPE);
            if (_listGather.size() > 0)
            {
                String[] saAttributes = _listGather.toArray(new String[0]);
                oScope.setReturningAttributes(saAttributes);
            }
            
            String searchFilter = resolveSearchQuery(sUserId);
            try
            {
                oNamingEnumeration = oDirContext.search(_sDNBase, 
                    searchFilter, oScope);
            }
            catch (InvalidSearchFilterException e)
            {
                StringBuffer sbFailed = new StringBuffer("Wrong filter: ");
                sbFailed.append(searchFilter);
                sbFailed.append(" while searching for attributes for id: ");
                sbFailed.append(sUserId);
                _logger.error(sbFailed.toString(), e);
                throw new AttributeException(SystemErrors.ERROR_RESOURCE_RETRIEVE, e);
            }
            catch (NamingException e)
            {
                _logger.debug("User unknown: " + sUserId);
                return;
            }
        
            if (oNamingEnumeration.hasMore())
            {
                SearchResult oSearchResult = (SearchResult)oNamingEnumeration.next();
                Attributes oSearchedAttributes = oSearchResult.getAttributes();
                NamingEnumeration neAttributes = oSearchedAttributes.getAll();
                while (neAttributes.hasMore())
                {
                    Attribute oAttribute = (Attribute)neAttributes.next();
                    String sAttributeName = oAttribute.getID();
                    String sMappedName = _htMapper.get(sAttributeName);
                    if (sMappedName != null) 
                        sAttributeName = sMappedName;
                    
                    if (oAttribute.size() > 1)
                    {
                        Vector<Object> vValue = new Vector<Object>();
                        NamingEnumeration neAttribute = oAttribute.getAll();
                        while (neAttribute.hasMore())
                            vValue.add(neAttribute.next());
                        
                        oAttributes.put(sAttributeName, vValue);                                                        
                    }
                    else
                    {                      
                        Object oValue = oAttribute.get();
                        if (oValue == null) oValue = "";
                        oAttributes.put(sAttributeName, oValue);
                    }  
                }
            }
        }
        catch (AttributeException e)
        {
            throw e;
        }
        catch (NamingException e)
        {
            _logger.debug("Failed to fetch attributes for user: " + sUserId, e);
        }
        catch (Exception e)
        {
            _logger.fatal("Could not retrieve fields for user with id: " + sUserId, e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
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
                    _logger.error("Could not close Naming Enumeration after searching for user with id: " 
                        + sUserId, e);
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
                    _logger.error("Could not close Dir Context after searching for user with id: " 
                        + sUserId, e);
                }
            }
        }
    }

    /**
     * Stops the object.
     * @see com.alfaariss.oa.engine.core.attribute.gather.processor.IProcessor#stop()
     */
    public void stop()
    {
        if (_htMapper != null)
            _htMapper.clear();
        if (_htJNDIEnvironment != null)
            _htJNDIEnvironment.clear();
        if (_listGather != null)
            _listGather.clear();
    }

    /**
     * Returns the gatherer id.
     * @see com.alfaariss.oa.api.IManagebleItem#getID()
     */
    public String getID()
    {
        return _sID;
    }

    /**
     * Returns the gatherer friendly name.
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }

    /**
     * Returns TRUE if the gatherer is enabled.
     * @see com.alfaariss.oa.api.IManagebleItem#isEnabled()
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }

    /**
     * Reads JNDI connection information from the configuration.
     * <br>
     * Creates an <code>Hashtable</code> containing the JNDI environment variables.
     * @param oConfigurationManager The configuration manager
     * @param eConfig the configuration section
     * @return <code>DirContext</code> that contains the JNDI connection
     * @throws AttributeException if configuration reading fails
     */
    private Hashtable<String,String> readJNDIContext(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws AttributeException
    {
        Hashtable<String,String> htEnvironment = new Hashtable<String,String>(11);
        
        try
        {
            Element eSecurityPrincipal = oConfigurationManager.getSection(eConfig, "security_principal");
            if (eSecurityPrincipal == null)
            {
                _logger.error("No 'security_principal' section found in 'resource' configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
    
            String sPrincipal = oConfigurationManager.getParam(eSecurityPrincipal, "dn");
            if(sPrincipal == null)
            {
                _logger.error("No item 'dn' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
    
            String sPassword = oConfigurationManager.getParam(eSecurityPrincipal, "password");
            if(sPassword == null)
            {
                _logger.error("No 'password' item found in configuration ");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sDriver = oConfigurationManager.getParam(eConfig, "driver");
            if(sDriver == null)
            {
                _logger.error("No 'driver' item found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            String sUrl = oConfigurationManager.getParam(eConfig, "url");
            if(sUrl == null)
            {
                _logger.error("No valid config item 'url' found in configuration");
                throw new AttributeException(SystemErrors.ERROR_CONFIG_READ);
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
        catch (AttributeException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Could not create a connection", e);
            throw new AttributeException(SystemErrors.ERROR_INTERNAL);
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