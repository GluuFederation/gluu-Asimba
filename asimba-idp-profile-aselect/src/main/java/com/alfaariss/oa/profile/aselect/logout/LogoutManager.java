
/*
 * Asimba Server
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
package com.alfaariss.oa.profile.aselect.logout;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.Vector;

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
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.tgt.ITGTListener;
import com.alfaariss.oa.api.tgt.TGTEventError;
import com.alfaariss.oa.api.tgt.TGTListenerEvent;
import com.alfaariss.oa.api.tgt.TGTListenerException;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
import com.alfaariss.oa.engine.core.server.Server;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory;
import com.alfaariss.oa.profile.aselect.ASelectErrors;
import com.alfaariss.oa.profile.aselect.processor.ASelectProcessor;
import com.alfaariss.oa.profile.aselect.processor.handler.BrowserHandler;
import com.alfaariss.oa.util.logging.UserEventLogItem;

/**
 * Logout handler that sends synchronous logout calls to requestors that are in 
 * the SP role.
 * <br>
 * The logout can be triggerd by the ON_CREATE and ON_EXPIRE TGT Listener Events.
 * @author MHO
 * @author Alfa & Ariss
 * @since 1.4
 */
public class LogoutManager implements ITGTListener, IAuthority
{
    private final static String AUTHORITY_NAME = "ASelectProfileLogoutManager_";
    
    private final static String PROPERTY_LOGOUT_TARGET = ".logout.target";
    private final static String PROPERTY_LOGOUT_SIGNING = ".logout.signing";
    
    private static Log _logger;
    private static Log _eventLogger;
    
    private ITGTAliasStore _aliasStoreSPRole;
    private IRequestorPoolFactory _requestorPoolFactory;
    private CryptoManager _cryptoManager;
    private Server _server;
    
    private String _sProfileID;
    private HttpClient _httpClient;
    private boolean _bEnabled;
    
    /**
     * Constructor. 
     * @param profileID The ID of this A-Select Profile.
     * @param configurationManager The configuration manager
     * @param config The configuration section
     * @throws OAException If config could not be read or is invalid.
     */
    public LogoutManager(String profileID, IConfigurationManager configurationManager, 
        Element config) throws OAException
    {
        try
        {
            _logger = LogFactory.getLog(LogoutManager.class);
            _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
            
            _bEnabled = true;
            if (config != null)
            {
                String sEnabled = configurationManager.getParam(config, "enabled");
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
            
            if (!_bEnabled)
            {
                _logger.info("Logout Manager: disabled");
            }
            else
            {
                Engine engine = Engine.getInstance();
                ITGTFactory tgtFactory = engine.getTGTFactory();
                _aliasStoreSPRole = tgtFactory.getAliasStoreSP();
                _requestorPoolFactory = engine.getRequestorPoolFactory();
                _cryptoManager = engine.getCryptoManager();
                _server = engine.getServer();
                _sProfileID = profileID;
                
                //Create thread safe HTTP client
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
                
                _logger.info("Logout Manager: enabled");
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not create logout manager", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * @see com.alfaariss.oa.api.tgt.ITGTListener#processTGTEvent(com.alfaariss.oa.api.tgt.TGTListenerEvent, com.alfaariss.oa.api.tgt.ITGT)
     */
    public void processTGTEvent(TGTListenerEvent event, ITGT tgt)
        throws TGTListenerException
    {
        if (!_bEnabled)
            return;
        
        switch (event)
        {
            case ON_EXPIRE:
            case ON_REMOVE:
            {
                List<TGTEventError> listEventErrors = new Vector<TGTEventError>();
                if (_aliasStoreSPRole != null)
                    listEventErrors.addAll(processRemove(tgt, event));
                
                if (!listEventErrors.isEmpty())
                    throw new TGTListenerException(listEventErrors);
                
                break;
            }
            default:
            {
                //not process any other events
            }
        }
    }
    
    /**
     * @return TRUE if this logout manager is enabled
     */
    public boolean isEnabled()
    {
        return _bEnabled;
    }
    
    /**
     * @see IAuthority#getAuthority()
     */
    public String getAuthority()
    {
        return AUTHORITY_NAME + _sProfileID;
    }
    
    private List<TGTEventError> processRemove(ITGT tgt, TGTListenerEvent event)
    {
        List<TGTEventError> listEventErrors = new Vector<TGTEventError>();
        List<LogoutTarget> listLogoutTargets = new Vector<LogoutTarget>();
        
        Map<String,String> mapTargets = new HashMap<String,String>();
        for (String sRequestor: tgt.getRequestorIDs())
        {
            IRequestor requestor = null;
            try
            {
                if (!mapTargets.containsKey(sRequestor))
                {
                    String sCredentials = _aliasStoreSPRole.getAlias(BrowserHandler.ALIAS_TYPE_CREDENTIALS, sRequestor, tgt.getId());
                    if (sCredentials != null)
                    {
                        requestor = _requestorPoolFactory.getRequestor(sRequestor);
                        String sLogoutURL = (String)requestor.getProperty(_sProfileID + PROPERTY_LOGOUT_TARGET);
                        if (sLogoutURL != null)
                        {
                            String sSigning = (String)requestor.getProperty(_sProfileID + PROPERTY_LOGOUT_SIGNING);

                            new URL(sLogoutURL);
                            String sLocation = generateSLogout(sLogoutURL, 
                                sCredentials, Boolean.valueOf(sSigning), event);
                            
                            LogoutTarget lt = new LogoutTarget(requestor, sLocation, tgt);
                            listLogoutTargets.add(lt);
                        }
                    }
                }
            }
            catch (MalformedURLException e)
            {

                TGTEventError error = null;
                if (requestor != null)
                    error = new TGTEventError(UserEvent.INTERNAL_ERROR, requestor.getFriendlyName());
                else
                    error = new TGTEventError(UserEvent.INTERNAL_ERROR);
                
                listEventErrors.add(error);
                
                UserEventLogItem logItem = new UserEventLogItem(null, 
                    tgt.getId(), null, UserEvent.INTERNAL_ERROR, 
                    tgt.getUser().getID(), 
                    tgt.getUser().getOrganization(), null, 
                    sRequestor, this, null);
                
                _eventLogger.info(logItem);
            }
            catch (OAException e)
            {
                TGTEventError error = null;
                if (requestor != null)
                    error = new TGTEventError(UserEvent.INTERNAL_ERROR, requestor.getFriendlyName());
                else
                    error = new TGTEventError(UserEvent.INTERNAL_ERROR);
                
                listEventErrors.add(error);
                
                UserEventLogItem logItem = new UserEventLogItem(null, 
                    tgt.getId(), null, UserEvent.INTERNAL_ERROR, 
                    tgt.getUser().getID(), 
                    tgt.getUser().getOrganization(), null, 
                    sRequestor, this, null);
                
                _eventLogger.info(logItem);
            }
        }
        
        for (LogoutTarget lt: listLogoutTargets)
        {
            UserEvent result = sendSLogout(lt.getTargetURL());
            if (result != UserEvent.USER_LOGGED_OUT)
            {
                listEventErrors.add(new TGTEventError(
                    result, lt.getRequestor().getFriendlyName()));
            }
            
            UserEventLogItem logItem = new UserEventLogItem(null, lt.getTGTID(), 
                null, result, lt.getUserID(), lt.getUserOrganization(), null, 
                lt.getRequestor().getID(), this, null);
            
            _eventLogger.info(logItem);
        }
        
        return listEventErrors;
    }
    
    private String generateSLogout(String sLogoutURL, String sCredentials, 
        boolean sign, TGTListenerEvent event) throws OAException
    {
        String logoutCall = null;
        try
        {
            Map<String, String> mapRequest = new HashMap<String, String>();
            mapRequest.put(ASelectProcessor.PARAM_LOCAL_IDP, _server.getOrganization().getID());
            mapRequest.put(ASelectProcessor.PARAM_ASELECT_CREDENTIALS, sCredentials);
            if (event == TGTListenerEvent.ON_EXPIRE)
                mapRequest.put(ASelectProcessor.PARAM_REASON, ASelectProcessor.VALUE_REASON_TIMEOUT);
            
            if (sign)
            {
                String signature = createSignature(mapRequest);
                mapRequest.put(ASelectProcessor.PARAM_SIGNATURE, signature);
            }
            
            mapRequest.put("request", "logout");//not part of signature
            
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
                sbMessage.append(URLEncoder.encode(mapRequest.get(key), ASelectProcessor.CHARSET));
            }
            
            logoutCall = sbMessage.toString();
        }
        catch (OAException e)
        {
            throw e;
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
                String sResultCode = htResponse.get(ASelectProcessor.PARAM_RESULT_CODE);
                if (sResultCode == null)
                {
                    _logger.debug("No result code in response, logout failed");
                    return UserEvent.USER_LOGOUT_FAILED;
                }
                else if (!sResultCode.equals(ASelectErrors.ERROR_ASELECT_SUCCESS))
                {
                    if (sResultCode.equals(ASelectErrors.ERROR_LOGOUT_PARTIALLY))
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
            return UserEvent.USER_LOGOUT_FAILED;
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
            signature.update(sbSignatureData.toString().getBytes(ASelectProcessor.CHARSET));
    
            byte[] baSignature = signature.sign();
    
            byte[] baEncSignature = Base64.encodeBase64(baSignature);
            sSignature = new String(baEncSignature, ASelectProcessor.CHARSET);
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
                sValue = URLDecoder.decode(sValue.trim(), ASelectProcessor.CHARSET);
    
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
