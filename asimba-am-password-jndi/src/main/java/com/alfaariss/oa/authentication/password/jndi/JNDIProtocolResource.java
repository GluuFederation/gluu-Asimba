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
package com.alfaariss.oa.authentication.password.jndi;

import java.util.Hashtable;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.password.AbstractResourceHandler;
import com.alfaariss.oa.util.ldap.JNDIUtil;

/**
 * A JNDI protocol resource. For every JNDI resource configured in the
 * Password Authentication Handler section a JNDIProtocolResource will be initialized.
 * 
 * @author JVG
 * @author Alfa & Ariss
 *
 */
public class JNDIProtocolResource extends AbstractResourceHandler
{
    /** The system logger */
    private final Log _logger;

    /** The JNDI URL. */
    protected String _sJNDIUrl;
    /** The JNDI driver. */
    protected String _sDriver;
    /** The base DN. */
    protected String _sBaseDn;
    /** The user DN. */
    protected String _sUserDn;
    /** The filter. */
    protected String _sFilter;
    /** The principal DN */
    protected String _sPrincipalDn;
    /** The principal password. */
    protected String _sPrincipalPwd;
    /** Use SSL. */
    protected boolean _bSSL;

    /**
     * Default constructor of <code>JNDIProtocolResource</code>.
     */
    public JNDIProtocolResource()
    {
        super();
        _logger = LogFactory.getLog(JNDIProtocolResource.class);
    }

    /**
     * @see AbstractResourceHandler#init(IConfigurationManager, org.w3c.dom.Element)
     */
    @Override
    public void init(IConfigurationManager _configurationManager, 
        Element eResourceSection) throws OAException
    {
        super.init(_configurationManager, eResourceSection);

        Element eDNSection = null;
        Element ePrincipalSection = null;

        _sJNDIUrl = _configurationManager.getParam(eResourceSection, "url");
        if ((_sJNDIUrl == null) || _sJNDIUrl.equals(""))
        {
            _logger.error("No url defined for realm: "+_sResourceRealm);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }

        if (_sJNDIUrl.length() >= 5 && 
            _sJNDIUrl.substring(0,5).equalsIgnoreCase("ldaps"))
        {
            // Request SSL transport
            _bSSL = true;
            _logger.info("SSL enabled");
        }
        else
        {
            _bSSL = false;
            _logger.info("SSL disabled");
        }
        
        // Get driver
        _sDriver = _configurationManager.getParam(eResourceSection, "driver");
        if ((_sDriver == null) || _sDriver.equals(""))
        {
            _logger.error("No driver defined for realm: "+_sResourceRealm);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }

        // Get dn section
        eDNSection = _configurationManager.getSection(eResourceSection, "dn");
        if (eDNSection == null)
        {
            _logger.error("No dn section defined for realm: "+_sResourceRealm);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }

        // Get base dn section
        _sBaseDn = _configurationManager.getParam(eDNSection, "base");
        if ((_sBaseDn == null) || _sBaseDn.equals(""))
        {
            _logger.error("No base dn defined for realm: "+_sResourceRealm);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }

        _sFilter = _configurationManager.getParam(eDNSection, "filter");
        
        // Get user_dn
        _sUserDn = _configurationManager.getParam(eDNSection, "user");
        if ((_sUserDn == null || _sUserDn.equals("")) && _sFilter == null)
        {
            _logger.error("No user dn defined for realm: " + _sResourceRealm);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        // Get security_principal section
        ePrincipalSection = _configurationManager.getSection(eResourceSection, "security_principal");
        if (ePrincipalSection == null)
        {
            _sPrincipalDn = ""; // use default
            _sPrincipalPwd = ""; // use default
            _logger.info("No 'security_principal' section configured for realm '" + _sResourceRealm + "', using default");
        }
        else
        {
            // Get security_principal dn
            _sPrincipalDn = _configurationManager.getParam(ePrincipalSection, "dn");
            if (_sPrincipalDn == null)
            {
                _sPrincipalDn = ""; // use default
                _logger.info("No 'dn' item in 'security_principal' section configured for realm '"+_sResourceRealm+"', using default");
            }

            // Get security_principal password
            _sPrincipalPwd = _configurationManager.getParam(ePrincipalSection, "password");
            if (_sPrincipalPwd == null)
            {
                _sPrincipalPwd = ""; // use default
                _logger.info("No 'password' item in 'security_principal' section configured for realm '"+_sResourceRealm+"', using default: empty");
            }
        }
        
        if (_sPrincipalDn.length() <= 0)
        {
            if (_sUserDn == null)
            {
                _logger.error("Invalid configuration: No security principal dn and user dn available; simple bind is not possible");
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            _logger.info("No security principal dn defined for realm '" + _sResourceRealm + "'. Using simple binding");
        }
        else if (_sFilter != null)
        {
            if (_sUserDn != null)
            {
                _logger.error("Invalid configuration: Both user dn and filter are configured");
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            _logger.info("Using configured search filter: " + _sFilter);
        }
    }

    /**
     * Authenticate against the configured resource.
     *
     * @param username The user ID.
     * @param password The provided password.
     * @return true if authenticated.
     * @throws UserException if a user authentication error occurs.
     * @throws OAException if an internal error occurs.
     */
    public boolean authenticate(
        String password, String username) throws UserException, OAException   
    {
        try
        {
            return doBind(constructUsername(username), password);
        }
        catch(UserException e)
        {
            _logger.debug("Could not authenticate user");
            throw e;
        }
        catch(OAException e)
        {
            _logger.error("Error occured during authentication", e);
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Fatal error occured during authentication", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    private boolean doBind(String sUserID, String sPassword)
    throws OAException, UserException
    {
        StringBuffer sbTemp = null;
        DirContext oDirContext = null;
        String sQuery = null;
        String sRelUserDn = null;
        boolean bResult = false;
        NamingEnumeration enumSearchResults = null;

        Hashtable<String, String> htEnvironment = new Hashtable<String, String>();

        htEnvironment.put(Context.PROVIDER_URL, _sJNDIUrl);
        htEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, _sDriver);
        htEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");

        if(_bSSL)
        {
            htEnvironment.put(Context.SECURITY_PROTOCOL, "ssl");
        }

        if (_sPrincipalDn.length() <= 0)
            // If no principal dn is known, we do a simple binding
        {
            String sEscUserID = JNDIUtil.escapeDN(sUserID);
            _logger.debug("Escaped user: " + sEscUserID);
            sbTemp = new StringBuffer(_sUserDn);
            sbTemp.append('=');
            sbTemp.append(sEscUserID);
            sbTemp.append(", ");
            sbTemp.append(_sBaseDn);
            htEnvironment.put(Context.SECURITY_PRINCIPAL, sbTemp.toString());

            htEnvironment.put(Context.SECURITY_CREDENTIALS, sPassword);

            try
            {
                oDirContext = new InitialDirContext(htEnvironment);
                bResult = true;
            }
            catch (AuthenticationException e)
            {
                // If supplied credentials are invalid or when authentication fails
                // while accessing the directory or naming service.
                _logger.debug("Could not authenticate user (invalid password): "+sUserID, e);
            }
            catch (CommunicationException eC)
            {
                // If communication with the directory or naming service fails.
                _logger.warn("A communication error has occured", eC);
                throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }
            catch(NamingException eN)
            {
                // The initial dir context could not be created.
                _logger.warn("A naming error has occured", eN);
                throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }
            finally
            {

                try
                {
                    if(oDirContext != null)
                    {
                        oDirContext.close();
                    }
                }
                catch (Exception e)
                {
                    _logger.warn("Could not close connection with '"+_sJNDIUrl+'\'', e);
                }
            }
        }
        else //search through the subtree
        {
            // 1 - Try to bind to LDAP using the security principal's DN and its password
            htEnvironment.put(Context.SECURITY_PRINCIPAL, _sPrincipalDn);
            htEnvironment.put(Context.SECURITY_CREDENTIALS, _sPrincipalPwd);

            try
            {
                oDirContext = new InitialDirContext(htEnvironment);
            }
            catch (AuthenticationException eA)
            {
                _logger.warn("Could not bind to LDAP server", eA);
                throw new OAException(SystemErrors.ERROR_RESOURCE_CONNECT);
            }
            catch (CommunicationException eC)
            {
                _logger.warn("A communication error has occured", eC);
                throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }
            catch(NamingException eN)
            {
                _logger.warn("A naming error has occured", eN);
                throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }

            // 2 - Search through the context for user's DN relative to the base DN
            sQuery = resolveSearchQuery(sUserID);

            SearchControls oScope = new SearchControls();
            oScope.setSearchScope(SearchControls.SUBTREE_SCOPE);

            try
            {
                enumSearchResults = oDirContext.search(_sBaseDn, sQuery, oScope);
            }
            catch (NamingException eN)
            {
                _logger.warn("User id not found in password backend for user: " + sUserID, eN);
                throw new UserException(UserEvent.AUTHN_METHOD_NOT_SUPPORTED);
            }
            finally
            {
                try
                {

                    oDirContext.close();
                    oDirContext = null;

                }
                catch (Exception e)
                {
                    _logger.warn("Could not close connection with '"+_sJNDIUrl+"'", e);
                }
            }

            try
            {
                if (!enumSearchResults.hasMoreElements())
                {
                    StringBuffer sb = new StringBuffer("User '");
                    sb.append(sUserID);
                    sb.append("' not found during LDAP search. The filter was: '");
                    sb.append(sQuery);
                    sb.append("'");
                    _logger.warn(sb.toString());
                    throw new UserException(UserEvent.AUTHN_METHOD_NOT_SUPPORTED);
                }

                SearchResult searchResult = (SearchResult)enumSearchResults.next();
                sRelUserDn = searchResult.getName();
                if (sRelUserDn == null)
                {
                    _logger.warn("no user dn was returned for '"+sUserID+"'.");
                    throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
                }
            }
            catch (NamingException eN)
            {

                _logger.warn("failed to fetch profile of user '"+sUserID+"'.", eN);
                throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }

            // 3 - Bind user using supplied credentials
            sbTemp = new StringBuffer(sRelUserDn);
            sbTemp.append(",");
            sbTemp.append(_sBaseDn);

            htEnvironment.put(Context.SECURITY_PRINCIPAL, sbTemp.toString());
            htEnvironment.put(Context.SECURITY_CREDENTIALS, sPassword);

            try
            {
                oDirContext = new InitialDirContext(htEnvironment);
                bResult = true;
            }
            catch (AuthenticationException e)
            {
                _logger.debug("Could not authenticate user (invalid password): "+sUserID, e);
            }
            catch (CommunicationException eC)
            {
                _logger.warn("A communication error has occured", eC);
                throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }
            catch(NamingException eN)
            {
                _logger.warn("A naming error has occured", eN);
                throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }
            finally
            {
                try
                {
                    if(oDirContext != null)
                    {
                        oDirContext.close();
                    }
                }
                catch (Exception e)
                {
                    _logger.warn("Could not close connection with '"+_sJNDIUrl+"'.", e);
                }
            }
        }
        return bResult;
    }
    
    private String resolveSearchQuery(String user)
    {
        String escapedUser = JNDIUtil.escapeLDAPSearchFilter(user);
        
        if (_sFilter != null)
            return _sFilter.replaceAll("\\?", escapedUser);
        
        StringBuffer sbQuery = new StringBuffer();
        sbQuery.append("(");
        sbQuery.append(_sUserDn);
        sbQuery.append("=");
        sbQuery.append(escapedUser);
        sbQuery.append(")");
        return sbQuery.toString();
    }
}
