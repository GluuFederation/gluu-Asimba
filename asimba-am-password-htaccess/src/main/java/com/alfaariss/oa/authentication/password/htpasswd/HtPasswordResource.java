/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) Alfa & Ariss B.V.
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
package com.alfaariss.oa.authentication.password.htpasswd;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.authentication.password.AbstractResourceHandler;
import com.alfaariss.oa.authentication.password.IResourceHandler;
import com.alfaariss.oa.authentication.password.digest.HtPasswdMD5Digest;
import com.alfaariss.oa.authentication.password.digest.HtPasswdSHA1Digest;
import com.alfaariss.oa.authentication.password.digest.IDigest;
import com.alfaariss.oa.authentication.password.encode.BinaryPwdEncoder;
import com.alfaariss.oa.authentication.password.encode.IEncoder;

/**
 * HtPassword resource. Handles a standard htpasswd file.
 *
 * @author BNE
 * @author Alfa & Ariss
 */
public class HtPasswordResource extends AbstractResourceHandler
{
    private final Log       _logger;
    private String          _sFilename;
    private IDigest         _md5digest;
    private IDigest         _shadigest;
    private IEncoder        _encoder;

    /**
     * Constructor.
     */
    public HtPasswordResource()
    {
        _logger = LogFactory.getLog(this.getClass());
        _encoder = new BinaryPwdEncoder();
    }

    /**
     * @see AbstractResourceHandler#init(IConfigurationManager, 
     * org.w3c.dom.Element)
     */
    @Override
    public void init(IConfigurationManager cm, 
        Element eResourceSection) throws OAException
    {
        super.init(cm, eResourceSection);

        Element eMD5 = cm.getSection(eResourceSection, "md5");
        if (eMD5 != null)
        {
            String sCommand = cm.getParam(eMD5, "command");
            if (sCommand != null)
            {
                _md5digest = new HtPasswdMD5Digest(sCommand);
                _md5digest.init(cm, null);
                
                _logger.info("Using optional configured 'command': " + sCommand);
            }
        }
        
        if (_md5digest == null)
            _md5digest = new HtPasswdMD5Digest();
        
        _shadigest = new HtPasswdSHA1Digest();
        
        String sFile = cm.getParam(eResourceSection, "file");
        if(sFile == null || sFile.length() <= 0)
        {
            _logger.error("No Htpasswd file configured in 'resource' section");
            throw new OAException(SystemErrors.ERROR_INIT);
        }
        
        File fFile = new File(sFile);
        if (!fFile.exists() || !fFile.isFile())
        {
            _logger.info("Configured file not found at: " + sFile);

            String sUserDir = System.getProperty("user.dir");
            StringBuffer sbFile = new StringBuffer(sUserDir);
            if (!sUserDir.endsWith(File.separator))
            {
                sbFile.append(File.separator);
            }
            sbFile.append(sFile);

            fFile = new File(sbFile.toString());
            if (!fFile.exists())
            {
                _logger.error("Can't access file: " + sbFile.toString());
                throw new OAException(SystemErrors.ERROR_INIT);
            }
        }

        _sFilename = fFile.getAbsolutePath();
    }

    /**
     * @see IResourceHandler#authenticate(java.lang.String, java.lang.String)
     */
    public boolean authenticate(String userPassword, String username)
    throws UserException, OAException
    {
        // Create digest of user entered password.

        // Retrieve the data from the htpassword location.
        byte[] comparePw = getData(constructUsername(username));

        if (comparePw!=null) {
            // User was found in file.

            String sComparePassword = new String(comparePw);
            byte[] userPw = null;

            if (sComparePassword.startsWith("$apr1$"))
            {
                // $apr1$saltmax8$password

                String[] spl = sComparePassword.split("\\$");

                // Extract the salt.
                String salt = spl[2];
                userPw = _md5digest.digest(userPassword, salt, 
                    constructUsername(username));
            }
            else if (sComparePassword.startsWith("{SHA}"))
            {
                userPw = _shadigest.digest(userPassword, _sResourceRealm, username);
            }
            else
            {
                _logger.error("Unknown htpasswd digest method");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }

            byte[] pww = _encoder.getBytes(userPw);

            // Compare!
            return Arrays.equals(pww, comparePw);
        }
        return false;
    }

    /*
     * Retrieve the password data
     */
    private byte[] getData(String username) throws OAException
    {
        byte[] result = null;

        try
        {
            BufferedReader in= new BufferedReader(new FileReader(_sFilename));
            String s;

            do
            {
                s = in.readLine();

                if ((s!=null) && s.startsWith(username+':'))
                {
                    // User found!
                    // Split on ":"

                    String[] userhash = s.split(":",2);

                    if (userhash.length==2)
                    {
                        // Take second part.
                        result = userhash[1].getBytes();

                        _logger.debug("Result from file: " + new String(result));
                        break;
                    }
                }
            } while (s!=null);
        }
        catch (FileNotFoundException e)
        {
            _logger.error("File not found" , e);

            throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }
        catch (IOException e)
        {
            _logger.error("Error reading file" , e);

            throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
        }

        return result;
    }
}