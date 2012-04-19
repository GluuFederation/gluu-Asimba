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
package com.alfaariss.oa.authentication.password;

import java.util.Arrays;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.password.digest.CryptoDigest;
import com.alfaariss.oa.authentication.password.digest.IDigest;
import com.alfaariss.oa.authentication.password.digest.PlainTextDigest;
import com.alfaariss.oa.authentication.password.encode.Base64PwdEncoder;
import com.alfaariss.oa.authentication.password.encode.BinaryPwdEncoder;
import com.alfaariss.oa.authentication.password.encode.HexPwdEncoder;
import com.alfaariss.oa.authentication.password.encode.IEncoder;
import com.alfaariss.oa.authentication.password.encode.PasswordType;

/**
 * Abstract Resource Handler with basic digestor and encoder support.
 * 
 * @author BNE
 * @author EVB
 * @author Alfa & Ariss
 * @since 1.0
 */
public abstract class AbstractDigestorResourceHandler 
    extends AbstractResourceHandler
{
    private final Log _logger;

    /**
     * Encoder
     */
    protected IEncoder _encoder;
    /**
     * Digestor
     */
    protected IDigest _digest;
    
    /**
     * Constructor
     */
    public AbstractDigestorResourceHandler ()
    {
        super();
        _logger = LogFactory.getLog(this.getClass());
    }

    /**
     * @see IResourceHandler#init(IConfigurationManager, org.w3c.dom.Element)
     */
    public void init(IConfigurationManager cm, Element eResourceSection)
        throws OAException
    {
        super.init(cm, eResourceSection);
        initDigester(eResourceSection);        
    }

    /**
     * @see IResourceHandler#authenticate(java.lang.String, java.lang.String)
     */
    public boolean authenticate(String password, String username)
        throws UserException, OAException
    {
        // Retrieve stores password from backend.
        // Create digest of user entered password.
        byte[] userEnteredPasswd = _digest.digest(password, _sResourceRealm,
            constructUsername(username));
        byte[] userEncodedPassword = _encoder.getBytes(userEnteredPasswd);

        byte[] storedPassword = getData(_sResourceRealm, 
            constructUsername(username));

        // Compare
        if(_logger.isDebugEnabled())
        {
            _logger.debug("User supplied password: " + new String(userEncodedPassword));        
            _logger.debug("Stored password: " + new String(storedPassword));
        }
        return Arrays.equals(userEncodedPassword, storedPassword);
    }
    
    /**
     * @param realm
     *            The realm to retrieve the data from.
     * @param username
     *            The username.
     * @return The stored password.
     * @throws OAException
     * @throws UserException
     */
    protected abstract byte[] getData(String realm, String username)
        throws OAException, UserException;
    

    //Initialize the encoding and digesting
    private void initDigester(Element eResource) throws OAException
    {        
        Element eDigester = _configurationManager.getSection(
            eResource, "digester");                
        if(eDigester == null)
        {        
            _logger.debug(
                "No 'digester' section found in 'resource' section for realm :"
                    + _sResourceRealm);
               
            //DD If password digester is omitted the default PLAINTEXT is used
            _logger.info(
                "No 'digester' section found in 'resource' section. Using plaintext for realm: "
                + _sResourceRealm);
            //Digest is omitted, so encoding should be plaintext.           
            _digest = new PlainTextDigest(); 
            _digest.init(_configurationManager, eDigester);
            //Binary encoder does not need init()
            _encoder = new BinaryPwdEncoder();               
        }    
        else
        {
            String sDigester = _configurationManager.getParam(eDigester,
            "class"); 
            if(sDigester == null || sDigester.length() <= 0)
            {
                _logger.info(
                    "No 'class' parameter found in 'digester' section for realm: "
                    + _sResourceRealm);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            _digest = createDigester(sDigester, eDigester);
            initEncoder(eResource);    
        }
    }

    /*
     * Create a new digester.
     * 
     * @param name The name of the crypto algorithm.
     * @param eDigester The configuration.
     * @return The digester
     * @throws OAException if no digester could be created
     */
    private IDigest createDigester(
        String name, Element eDigester) throws OAException
    {
        IDigest result = null;
        if (name.equals(PasswordType.PLAINTEXT.name()))
        {
            result = new PlainTextDigest();
        }
        else
        {       
            // Search for crypto names
            for (String element : IDigest.BUILTIN_CRYPTO)
            {
                if (element.equalsIgnoreCase(name))
                {
                    // Found, instantiate
                    result = new CryptoDigest(element);                    
                    break;
                }
            }
        }
        
        if (result == null)
        {
            // No result found. Try to instantiate with a class-for-name
            try
            {
                result = (IDigest)Class.forName(name).newInstance();
            }
            catch (InstantiationException e)
            {
                _logger.error("Cannot instantiate." + name, e);
            }
            catch (IllegalAccessException e)
            {
                _logger.error("IllegalAccess " + name, e);
            }
            catch (ClassNotFoundException e)
            {
                _logger.error("Class not found: " + name, e);
            }
        }
    
        if (result == null)
        {
            _logger.error("No digester created. (" + name + ')');
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        _logger.debug("Using digester: (" + result.getClass() + ')');
        result.init(_configurationManager, eDigester);
        return result;
    }

    private void initEncoder(Element eResource) throws OAException
    {
        //Create encoder
        Element eEncoder = _configurationManager.getSection(
            eResource, "encoder");
        String sEncoder = null;
        if(eEncoder == null)
        {        
            _logger.debug(
                "No 'encoder' section found in 'resource' section for realm :"
                    + _sResourceRealm);
                                 
            //DD If password encoder is omitted binary encoding is used
            _logger.info(
                "No 'encoder' section found in 'resource' section. Using binary encoding for realm: "
                + _sResourceRealm);
            _encoder = new BinaryPwdEncoder();
        }   
        else
        {
            sEncoder = _configurationManager.getParam(eEncoder, "class"); 
            if(sEncoder == null || sEncoder.length() <= 0)
            {
                _logger.info(
                    "No 'class' parameter found in 'encoder' section for realm: "
                    + _sResourceRealm);               
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }  
            _encoder = createEncoder(sEncoder, eEncoder);
        }            
    }

    /*
     * Create an encoder.
     * 
     * @param name
     *            The name of the encoder.
     * @param eEncoder The encoder configuration.
     * @return The instantiated object.
     * @throws OAException if no encoding could be created
     */
    private IEncoder createEncoder(String name, Element eEncoder) throws OAException
    {
        IEncoder result = null;        
        if (name.equals(PasswordType.BASE64.name()))
        {
            result = new Base64PwdEncoder();
        }
        else if (name.equals(PasswordType.BINARY.name()))
        {
            result = new BinaryPwdEncoder();
        }
        else if (name.equals(PasswordType.HEXSTRING.name()))
        {
            result = new HexPwdEncoder();
        }
        else if (name.equals(PasswordType.PLAINTEXT.name()))
        {
            result = new BinaryPwdEncoder();
        }
        
        if(result == null)
        {
            // No result found. Try to instantiate with a class-for-name
            try
            {
                result = (IEncoder)Class.forName(name).newInstance();
            }
            catch (InstantiationException e)
            {
                _logger.error("Cannot instantiate." + name, e);
            }
            catch (IllegalAccessException e)
            {
                _logger.error("IllegalAccess " + name, e);
            }
            catch (ClassNotFoundException e)
            {
                _logger.error("Class not found: " + name, e);
            }
        }
    
        if (result == null)
        {
            _logger.error("No encoder created. (" + name + ')');
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        _logger.debug("Using encoder: (" + result.getClass() + ')');
        result.init(_configurationManager, eEncoder);
    
    
        return result;
    }
}
