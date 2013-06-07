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
package com.alfaariss.oa.authentication.remote;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
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
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.idmapper.IIDMapper;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.user.UserException;
import com.alfaariss.oa.sso.authentication.web.IWebAuthenticationMethod;

/**
 * Abstract class for remote Authentication Methods.
 * 
 * <br><br><i>Partitially based on sources from A-Select (www.a-select.org).</i>
 * 
 * @author MHO
 * @author Alfa & Ariss
 *
 */
abstract public class AbstractRemoteMethod implements IWebAuthenticationMethod
{
    /** UTF-8 */
    public final static String CHARSET = "UTF-8";
    /** Server engine */
    protected Engine _engine;
    /** Configuration manager */
    protected IConfigurationManager _configurationManager;
    /** crypto engine */
    protected CryptoManager _cryptoManager;
    /** event logger */
    protected Log _eventLogger;
    /** system logger */
    protected Log _logger;
    /** id mapper */
    protected IIDMapper _idMapper;
    /** The method friendly name*/
    protected String _sFriendlyName;
    /** The method ID */
    protected String _sMethodId;
    /** HttpClient */
    protected HttpClient _httpClient;
    
    private boolean _bEnabled;
        
    /**
     * Constructor.
     */
    public AbstractRemoteMethod()
    {
        _logger = LogFactory.getLog(AbstractRemoteMethod.class);
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
        _httpClient = null;
    }
    
    /**
     * @see com.alfaariss.oa.api.IManagebleItem#getID()
     */
    public String getID()
    {
        return _sMethodId;
    }
    
	/**
	 * @see com.alfaariss.oa.api.IManagebleItem#isEnabled()
	 */
	public boolean isEnabled() 
    {
		return _bEnabled;
	}
    
    /**
     * @see com.alfaariss.oa.api.IManagebleItem#getFriendlyName()
     */
    public String getFriendlyName()
    {
        return _sFriendlyName;
    }

	/**
	 * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
	 */
	public void restart(Element eConfig) throws OAException 
    {
        synchronized(this)
        {
            stop();
            start(_configurationManager, eConfig);
        }
	}

	/**
	 * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
	 */
	public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws OAException 
    {
        try
        {
            _configurationManager = oConfigurationManager;
            
            _sMethodId = _configurationManager.getParam(eConfig, "id");
            if (_sMethodId == null)
            {
                _logger.error("No 'id' parameter found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _sFriendlyName = _configurationManager.getParam(eConfig, "friendlyname");
            if (_sFriendlyName == null)
            {
                _logger.error("No 'friendlyname' parameter found in configuration");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _bEnabled = true;
            String sEnabled = _configurationManager.getParam(eConfig, "enabled");
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
            
            _engine = Engine.getInstance();
            _cryptoManager = _engine.getCryptoManager();
            
            if (_bEnabled)
            {   
                //Create thread safe HTTP client
                MultiThreadedHttpConnectionManager connectionManager = 
                    new MultiThreadedHttpConnectionManager();
                _httpClient = new HttpClient(connectionManager);
                
                Element eHTTP = _configurationManager.getSection(eConfig, "http");
                if (eHTTP != null)
                    readHTTPConfig(eHTTP);
                else
                    _logger.info("No optional 'http' section configured, using default http connection settings");
                
                Element eIDMapper = _configurationManager.getSection(eConfig, "idmapper");
                if (eIDMapper != null)
                    _idMapper = createMapper(_configurationManager, eIDMapper);
                else
                    _logger.info("No optional 'idmapper' section configured, not using ID Mapper");
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during start", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }   
	}

    /**
	 * @see com.alfaariss.oa.api.IComponent#stop()
	 */
	public void stop() 
    {
        _bEnabled = false;
        _cryptoManager = null;
        _idMapper = null;
	}
    
    /**
     * Sends a CGI request message.
     * 
     * @param sURL The target URL
     * @param htMessage Hashtable containing the message parameters
     * @return A Hashtable containing the CGI response
     * @throws OAException if sending fails
     * @throws IOException if the connection can't be made
     */
    protected Hashtable<String, String> sendRequest(String sURL, 
        Hashtable<String, String> htMessage) throws OAException, IOException
    {
        Hashtable<String, String> htResult = null;
        GetMethod method = null;
        try
        {
            if (_httpClient == null)
            {
                _logger.error("No http client initialized");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            String sMessage = convertHashtable(htMessage);
            if (sMessage == null)
            {
                _logger.error("Can't send empty message to URL: " + sURL);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            StringBuffer sbMessage = new StringBuffer(sURL);
            sbMessage.append("?");
            sbMessage.append(sMessage);
                        
            method = new GetMethod(sbMessage.toString());
            
            _logger.debug("Sending message: " + sbMessage.toString());
            int statusCode = _httpClient.executeMethod(method);
            if (statusCode != HttpStatus.SC_OK) 
            {
                StringBuffer sbWarn = new StringBuffer("Received invalid http status '");
                sbWarn.append(method.getStatusLine());
                sbWarn.append("' while sending: ");
                sbWarn.append(sbMessage.toString());
                
                _logger.warn(sbWarn.toString());
                throw new OAException(SystemErrors.ERROR_RESOURCE_CONNECT);
            }
            
            // Read the response body.
            byte[] responseBody = method.getResponseBody();
            if(responseBody != null) 
            {
                String sResponseMessage = new String(responseBody).trim();
                _logger.debug("Received response: " + sResponseMessage);
                htResult = convertCGI(sResponseMessage);
            }
        }
        catch(IOException e)
        {
            throw e;
        }
        catch(OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            StringBuffer sbError = new StringBuffer("Internal error while sending message (");
            sbError.append(htMessage.toString());
            sbError.append(") to URL: ");
            sbError.append(sURL);
            _logger.error(sbError.toString(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
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
        return htResult;
    }
    
    /**
     * Converts the supplied message String in a Hashtable containing the parameters and values.
     * 
     * @param sMessage The message string.
     * @return Returns a <code>Hashtable</code> containing the message parameters and values.
     * @throws OAException if conversion fails. 
     */
    protected Hashtable<String, String> convertCGI(String sMessage) 
        throws OAException
    {
        Hashtable<String, String> htResult = new Hashtable<String, String>();
        try
        {
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
    
    /**
     * Converts a <code>Hashtable</code> containing message parameters to a message <code>String</code>.
     *
     * @param htMessage The message parameters.
     * @return The message as String.
     * @throws OAException if conversion fails.
     */
    protected String convertHashtable(Hashtable<String, String> htMessage) 
        throws OAException
    {
        StringBuffer sbResult = new StringBuffer();
        try
        {
            Enumeration<String> enumKeys = htMessage.keys();
            while (enumKeys.hasMoreElements())
            {
                String sKey = enumKeys.nextElement();
                String sValue = htMessage.get(sKey);
                if (sKey != null && sValue != null)
                {
                    if (sbResult.length() > 0)
                        sbResult.append("&");
                    
                    sbResult.append(sKey);
                    sbResult.append("=");
                    sbResult.append(URLEncoder.encode(sValue, CHARSET));
                }
            }
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during conversion of message: " + htMessage, e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return sbResult.toString();
    }
    

    
    /**
     * Creates a signature over the supplied attributes in the map.
     * <br>
     * Uses a TreeSet to sort the request parameter names.
     * @param mapRequest A map containing the attributes to be signed.
     * @return The signed request attributes.
     * @throws OAException
     */
    protected String createSignature(Map<String, String> mapRequest) throws OAException
    {
        String sSignature = null;
        try
        {
            Signature oSignature = _cryptoManager.getSignature();
            if (oSignature == null)
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
            oSignature.initSign(keyPrivate);
            oSignature.update(sbSignatureData.toString().getBytes(CHARSET));

            byte[] baSignature = oSignature.sign();
            
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

    private IIDMapper createMapper(IConfigurationManager configManager, 
        Element eConfig) throws OAException
    {
        IIDMapper oMapper = null;
        try
        {
            String sClass = configManager.getParam(eConfig, "class");
            if (sClass == null)
            {
                _logger.error("No 'class' parameter found in 'idmapper' section in configuration");
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Class cMapper = null;
            try
            {
                cMapper = Class.forName(sClass);
            }
            catch (Exception e)
            {
                _logger.error("No 'class' found with name: " + sClass, e);
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            try
            {
                oMapper = (IIDMapper)cMapper.newInstance();
            }
            catch (Exception e)
            {
                _logger.error("Could not create an 'IIDMapper' instance of the configured 'class' found with name: " 
                    + sClass, e);
                throw new UserException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            oMapper.start(configManager, eConfig);
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during creation of id mapper", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        return oMapper;
    }
    
    private void readHTTPConfig(Element eConfig) throws OAException
    {
        //connection_timeout
        //The timeout until a connection is established. 
        //A value of zero means the timeout is not used.
        String sConnectionTimeout = _configurationManager.getParam(eConfig, "connection_timeout");
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
        String sSocketTimeout = _configurationManager.getParam(eConfig, "socket_timeout");
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
}
