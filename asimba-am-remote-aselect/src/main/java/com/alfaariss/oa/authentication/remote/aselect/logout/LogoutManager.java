/*
 * Asimba - Serious Open Source SSO
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2010 Alfa & Ariss B.V.
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
package com.alfaariss.oa.authentication.remote.aselect.logout;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeSet;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.logging.IAuthority;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.tgt.ITGTListener;
import com.alfaariss.oa.api.tgt.TGTEventError;
import com.alfaariss.oa.api.tgt.TGTListenerEvent;
import com.alfaariss.oa.api.tgt.TGTListenerException;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.authentication.remote.aselect.ASelectRemoteUser;
import com.alfaariss.oa.authentication.remote.aselect.RemoteASelectMethod;
import com.alfaariss.oa.authentication.remote.aselect.idp.storage.ASelectIDP;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.idp.storage.IIDPStorage;
import com.alfaariss.oa.engine.core.server.Server;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.util.logging.UserEventLogItem;

/**
 * TGT event listener used for the complete synchronous logout process.
 * <br>
 * Performs synchronous logouts at a remote IDP when the TGT is removed or 
 * cleaned and stores the remote aselect_credentials (supplied by the IdP) when 
 * a new TGT is created.
 * 
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class LogoutManager implements ITGTListener, IAuthority
{
    /** TGT Alias type for A-Select credentials */
    public final static String ALIAS_TYPE_CREDENTIALS = "aselect_credentials";
    
    private final static String AUTHORITY_NAME = "ASelectAuthNLogoutManager_";
    
    private final static String CHARSET = "UTF-8";
    private final static String REQUEST_LOGOUT = "logout";
    private final static String PARAM_REQUEST = "request";
    private final static String PARAM_ASELECT_CREDENTIALS = "aselect_credentials";
    private final static String PARAM_REQUESTORID = "requestor";
    private final static String PARAM_SIGNATURE = "signature";
    private final static String PARAM_RESULTCODE = "result_code";
    private final static String ERROR_ASELECT_LOGOUT_SUCCESS = "0000";
    private final static String ERROR_ASELECT_LOGOUT_PARTIALLY = "9912";
    private final static String PARAM_REASON = "reason";
    private final static String VALUE_REASON_TIMEOUT = "timeout";
    
    private static Log _logger;
    private static Log _eventLogger;
    
    private CryptoManager _cryptoManager;
    private Server _server;
    private ITGTAliasStore _aliasStoreIDPRole;
    
    private HttpClient _httpClient;
    
    private IIDPStorage _idpStorage;
    private String _sMethodID;
    private boolean _bEnabled;
    
    /**
     * Constructor.
     * @param configurationManager The configuration manager
     * @param config The configuration section
     * @param idpStorage The remote A-Select organization storage.
     * @param sMethodId The method id.
     * @throws OAException If config could not be read or is invalid.
     */
    public LogoutManager(IConfigurationManager configurationManager, 
        Element config, IIDPStorage idpStorage, String sMethodId) 
        throws OAException
    {
        try
        {
            _logger = LogFactory.getLog(LogoutManager.class);
            _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
            
            _idpStorage = idpStorage;
            _sMethodID = sMethodId;
            _bEnabled = true;
            if (config != null)
            {
                Element eLogout = configurationManager.getSection(config, "logout");
                if (eLogout != null)
                {
                    String sEnabled = configurationManager.getParam(eLogout, "enabled");
                    if (sEnabled != null)
                    {
                        if (sEnabled.equalsIgnoreCase("FALSE"))
                            _bEnabled = false;
                        else if (!sEnabled.equalsIgnoreCase("TRUE"))
                        {
                            _logger.error("Unknown value in 'enabled' configuration item: " 
                                + sEnabled);
                            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                        }
                    }
                }
            }
            
            if (!_bEnabled)
            {
                _logger.info("Synchronous logout manager: disabled");
            }
            else
            {
                Engine engine = Engine.getInstance();
                _cryptoManager = engine.getCryptoManager();
                _server = engine.getServer();
                _aliasStoreIDPRole = engine.getTGTFactory().getAliasStoreIDP();
                if (_aliasStoreIDPRole == null)
                {
                    _logger.info("No IDP TGT Alias store available, disabling synchronous logout manager");
                    _bEnabled = false;
                    return;
                }
                
                //Create thread safe HTTP client from parent config
                MultiThreadedHttpConnectionManager connectionManager = 
                    new MultiThreadedHttpConnectionManager();
                _httpClient = new HttpClient(connectionManager);
                
                if (config != null)
                {
                    Element eHTTP = configurationManager.getSection(config, "http");
                    if (eHTTP != null)
                        readHTTPConfig(configurationManager, eHTTP);
                    else
                        _logger.info("No optional 'http' section configured, using default http connection settings");
                }
            }
            
            _logger.info("Synchronous Logout Manager: started");
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not create synchronous logout manager", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Verifies if the logout manager is enabled.
     *  
     * @return TRUE if logout manager is enabled.
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }
    
    /**
     * @see com.alfaariss.oa.api.logging.IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return AUTHORITY_NAME + _sMethodID;
    }

    /**
     * @see com.alfaariss.oa.api.tgt.ITGTListener#processTGTEvent(com.alfaariss.oa.api.tgt.TGTListenerEvent, com.alfaariss.oa.api.tgt.ITGT)
     */
    public void processTGTEvent(TGTListenerEvent event, ITGT tgt)
        throws TGTListenerException
    {
        if (!_bEnabled)
        {
            _logger.warn("Logout manager is disabled");
            return;
        }
        
        switch (event)
        {
            case ON_CREATE:
            {
                processCreate(tgt);
                break;
            }
            case ON_EXPIRE:
            case ON_REMOVE:
            {
                processRemove(tgt, event);
                break;
            }
            default:
            {
                //not process any other events
            }
        }
    }
    
    private void processCreate(ITGT tgt) throws TGTListenerException
    {
        try
        {
            IUser user = tgt.getUser();
            if (user instanceof ASelectRemoteUser)
            {
                String sUserOrganization = user.getOrganization();
                if (_idpStorage.exists(sUserOrganization))
                {
                    _aliasStoreIDPRole.putAlias(ALIAS_TYPE_CREDENTIALS, sUserOrganization, 
                        tgt.getId(), ((ASelectRemoteUser)user).getCredentials());
                }
            }
        }
        catch (TGTListenerException e)
        {
            throw e;
        }
        catch (OAException e)
        {
            throw new TGTListenerException(new TGTEventError(UserEvent.INTERNAL_ERROR));
        }
    }
    
    private void processRemove(ITGT tgt, TGTListenerEvent event) throws TGTListenerException
    {
        ASelectIDP aselectIDP = null;
        try
        {
            IUser user = tgt.getUser();
            if (user instanceof ASelectRemoteUser)
            {
                String sUserOrganization = user.getOrganization();
                aselectIDP = (ASelectIDP)_idpStorage.getIDP(sUserOrganization);
                if (aselectIDP != null)
                {
                    if (aselectIDP.hasSynchronousLogout())
                    {
                        ASelectIDP org = (ASelectIDP)tgt.getAttributes().get(
                            RemoteASelectMethod.class, _sMethodID + RemoteASelectMethod.TGT_LOGOUT_ORGANIZATION);
                        if (org == null || !aselectIDP.equals(org))
                        {
                            String sCredentials = _aliasStoreIDPRole.getAlias(
                                ALIAS_TYPE_CREDENTIALS, aselectIDP.getID(), tgt.getId());
                            if (sCredentials != null)
                            {
                                String sLogout = 
                                    generateSLogout(aselectIDP.getURL(), 
                                        sCredentials, aselectIDP.doSigning(), event);
                                
                                UserEvent userEvent = sendSLogout(sLogout);
                                
                                //DD remove the alias, so the profile.aselect will not send the logout request again
                                _aliasStoreIDPRole.removeAlias(ALIAS_TYPE_CREDENTIALS, aselectIDP.getID(), sCredentials);
                                
                                UserEventLogItem logItem = new UserEventLogItem(
                                    null, tgt.getId(), null, userEvent, 
                                    user.getID(), user.getOrganization(),
                                    null, null, this, null);
                                
                                _eventLogger.info(logItem);
                                
                                if (userEvent != UserEvent.USER_LOGGED_OUT)
                                {   
                                    throw new TGTListenerException(
                                        new TGTEventError(userEvent, aselectIDP.getFriendlyName()));
                                }
                            }
                        }
                    }
                    
                }
            }
        }
        catch (TGTListenerException e)
        {
            throw e;
        }
        catch (OAException e)
        {
            TGTEventError eventError = null;
            if (aselectIDP != null)
                eventError = new TGTEventError(UserEvent.USER_LOGOUT_FAILED, 
                    aselectIDP.getFriendlyName());
            else
                eventError = new TGTEventError(UserEvent.USER_LOGOUT_FAILED);
            
            throw new TGTListenerException(eventError);
        }
    }
    
    private String generateSLogout(String sLogoutURL, String sCredentials, 
        boolean sign, TGTListenerEvent event) throws OAException
    {
        String logoutCall = null;
        try
        {
            Map<String, String> mapRequest = new HashMap<String, String>();
            mapRequest.put(PARAM_REQUESTORID, _server.getOrganization().getID());
            mapRequest.put(PARAM_ASELECT_CREDENTIALS, sCredentials);
            if (event == TGTListenerEvent.ON_EXPIRE)
                mapRequest.put(PARAM_REASON, VALUE_REASON_TIMEOUT);
            
            if (sign)
            {
                String signature = createSignature(mapRequest);
                mapRequest.put(PARAM_SIGNATURE, signature);
            }
            
            mapRequest.put(PARAM_REQUEST, REQUEST_LOGOUT);//not part of signature
            
            StringBuffer sbMessage = new StringBuffer(sLogoutURL);
            if (!sLogoutURL.contains("?"))
                sbMessage.append("?");
    
            for (String key: mapRequest.keySet())
            {
                if (!sbMessage.toString().endsWith("&") 
                    && !sbMessage.toString().endsWith("?"))
                    sbMessage.append("&");
                
                sbMessage.append(key);
                sbMessage.append("=");
                sbMessage.append(URLEncoder.encode(mapRequest.get(key), CHARSET));
            }
            
            logoutCall = sbMessage.toString();
        }
        catch (Exception e)
        {
            _logger.error("Could not generate logout call", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return logoutCall;
    }

    private UserEvent sendSLogout(String logoutCall)
    {
        GetMethod method = null;
        try
        {
            method = new GetMethod(logoutCall);
            
            _logger.debug("Sending message: " + logoutCall);
            int statusCode = _httpClient.executeMethod(method);
            if (statusCode != HttpStatus.SC_OK) 
            {
                StringBuffer sbWarn = new StringBuffer("Received invalid http status '");
                sbWarn.append(method.getStatusLine());
                sbWarn.append("' while sending: ");
                sbWarn.append(logoutCall);
                
                _logger.warn(sbWarn.toString());
                throw new OAException(SystemErrors.ERROR_RESOURCE_CONNECT);
            }
            
            // Read the response body.
            byte[] responseBody = method.getResponseBody();
            if(responseBody != null) 
            {
                String sResponseMessage = new String(responseBody).trim();
                _logger.debug("Received response: " + sResponseMessage);
                
                Hashtable<String, String> htResponse = convertCGI(sResponseMessage);
                String sResultCode = htResponse.get(PARAM_RESULTCODE);
                if (sResultCode == null)
                {
                    _logger.debug("No result code in response, logout failed");
                    return UserEvent.USER_LOGOUT_FAILED;
                }
                else if (!sResultCode.equals(ERROR_ASELECT_LOGOUT_SUCCESS))
                {
                    if (sResultCode.equals(ERROR_ASELECT_LOGOUT_PARTIALLY))
                    {
                        _logger.debug("Logout parially in response from server");
                        return UserEvent.USER_LOGOUT_PARTIALLY;
                    }
                    
                    _logger.debug("Logout failed, result code: " + sResultCode);
                    return UserEvent.USER_LOGOUT_FAILED;
                }
            }
        }
        catch (OAException e)
        {
            return UserEvent.USER_LOGOUT_FAILED;
        }
        catch (Exception e)
        {
            _logger.warn("Could not send synchronous logout", e);
            return UserEvent.INTERNAL_ERROR;
        }
        finally
        {
            try
            {
                // Release the connection.
                if (method != null)
                    method.releaseConnection();
            }
            catch (Exception e)
            {
                _logger.error("Could not close the connection reader", e);
            }
        }
        return UserEvent.USER_LOGGED_OUT;
    }
    
    private void readHTTPConfig(IConfigurationManager configurationManager, 
        Element config) throws OAException
    {
        //connection_timeout
        //The timeout until a connection is established. 
        //A value of zero means the timeout is not used.
        String sConnectionTimeout = configurationManager.getParam(config, "connection_timeout");
        if (sConnectionTimeout == null)
        {
            _logger.info("No 'connection_timeout' parameter found in configuration, using default");
        }
        else
        {
            try
            {
                int iConnectionTimeout = Integer.parseInt(sConnectionTimeout);
                
                _httpClient.getParams().setParameter(
                    HttpConnectionParams.CONNECTION_TIMEOUT, 
                    new Integer(iConnectionTimeout));
            }
            catch(NumberFormatException e)
            {
                _logger.error("Invalid 'connection_timeout' parameter found in configuration, not a number: " 
                    + sConnectionTimeout, e);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
        }
        
        //socket_timeout
        //The parameters below are optional parameters used by the apache <code>HttpClient</code>.
        //Whenever a parameter is left undefined (no value is explicitly set anywhere in the 
        //parameter hierarchy) <code>HttpClient</code> will use its best judgment to pick up a value. 
        //This default behavior is likely to provide the best compatibility with widely used HTTP servers. 
        //The default socket timeout (SO_TIMEOUT) in milliseconds which is 
        //the timeout for waiting for data. A timeout value of zero is interpreted
        //as an infinite timeout. This value is used when no socket timeout is 
        //set in the HTTP method parameters.  
        String sSocketTimeout = configurationManager.getParam(config, "socket_timeout");
        if (sSocketTimeout == null)
        {
            _logger.info("No 'socket_timeout' parameter found in configuration, using an infinite timeout");
        }
        else
        {
            try
            {
                int iSocketTimeout = Integer.parseInt(sSocketTimeout);
                
                _httpClient.getParams().setParameter(
                    HttpConnectionParams.SO_TIMEOUT, 
                    new Integer(iSocketTimeout));
            }
            catch(NumberFormatException e)
            {        
                _logger.error("Invalid 'socket_timeout' parameter found in configuration, not a number: " 
                    + sSocketTimeout, e);
                throw new OAException(SystemErrors.ERROR_INIT);
            }
        }
    }
    
    private String createSignature(Map<String, String> mapRequest)
        throws OAException
    {
        String sSignature = null;
        try
        {
            if (_cryptoManager == null)
            {
                _logger.warn("No crypto manager available");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            Signature signature = _cryptoManager.getSignature();
            if (signature == null)
            {
                _logger.warn("No signature object found");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
    
            StringBuffer sbSignatureData = new StringBuffer();
            TreeSet<String> sortedSet = new TreeSet<String>(mapRequest.keySet());
            for (Iterator<String> iter = sortedSet.iterator(); iter.hasNext();)
            {
                String sKey = iter.next();
                sbSignatureData.append(mapRequest.get(sKey));
            }
    
            PrivateKey keyPrivate = _cryptoManager.getPrivateKey();
            if (keyPrivate == null)
            {
                _logger.error("No private key available");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            signature.initSign(keyPrivate);
            signature.update(sbSignatureData.toString().getBytes(CHARSET));
    
            byte[] baSignature = signature.sign();
    
            byte[] baEncSignature = Base64.encodeBase64(baSignature);
            sSignature = new String(baEncSignature, CHARSET);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not create signature for data: " + mapRequest, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    
        return sSignature;
    }
    
    private Hashtable<String, String> convertCGI(String sMessage) 
        throws OAException
    {
        Hashtable<String, String> htResult = new Hashtable<String, String>();
        try
        {
            if (sMessage.trim().length() == 0)
                return htResult;
            
            String[] saMessage = sMessage.split("&");
            for (int i = 0; i < saMessage.length; i++)
            {
                String sPart = saMessage[i];
                int iIndex = sPart.indexOf('=');
                String sKey = sPart.substring(0, iIndex);
                sKey = sKey.trim();
                String sValue = sPart.substring(iIndex + 1);
                sValue = URLDecoder.decode(sValue.trim(), CHARSET);
    
                if (htResult.containsKey(sKey))
                {
                    _logger.error("Key is not unique in message: " + sKey);
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                
                htResult.put(sKey, sValue);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during conversion of message: " + sMessage, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return htResult;
    }
}
