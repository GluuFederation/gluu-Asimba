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
package com.alfaariss.oa.authentication.password.digest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * 
 * Digester for using the custom MD5 routine of the APR.
 *
 * @author BNE
 * @author Alfa & Ariss
 * @since 1.0
 */
public class HtPasswdMD5Digest implements IDigest
{

    private final Log _systemLogger;
    private final static String DEFAULT_COMMAND = "openssl passwd -apr1 -salt {salt} {password}";
    
    private String _sCommand;
    /**
     * Constructor.
     * @param sCommand The MD5 command String.
     */
    public HtPasswdMD5Digest(String sCommand)
    {
        super();
        _sCommand = sCommand;
        _systemLogger = LogFactory.getLog(this.getClass());
    }
    
    /**
     * Constructor.
     */
    public HtPasswdMD5Digest()
    {
        super();
        _sCommand = DEFAULT_COMMAND;
        _systemLogger = LogFactory.getLog(this.getClass());
    }
    
    /**
     * @see IDigest#init(IConfigurationManager, org.w3c.dom.Element)
     */
    public void init(IConfigurationManager configurationManager, Element encoder)
        throws OAException
    {
        testCommand();
       //nothing        
    }

    /**
     * DD Instead of realm, the "salt" is given
     * @see IDigest#digest(java.lang.String, java.lang.String, java.lang.String)
     */
    public byte[] digest(String password, String salt, String username)
    throws OAException
    {
        byte[] result = null;
        Runtime r = Runtime.getRuntime();
        Process p = null;
        String[] saCommand = null;
        try
        {
            saCommand = resolveCommand(_sCommand, salt, password);
            p = r.exec(saCommand);

            BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));

            int exitCode = p.waitFor();
            if (exitCode == 0)
            {
                result = in.readLine().getBytes();
                _systemLogger.debug("Result openssl: " + new String(result));
            }
        }
        catch (IOException e)
        {
            _systemLogger.error("IO Error executing command: " 
                + resolveCommand(saCommand), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch (InterruptedException e)
        {
            _systemLogger.error("Error executing command: " 
                + resolveCommand(saCommand), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }

        return result;
    }
    
    private void testCommand() throws OAException
    {
        Runtime r = Runtime.getRuntime();
        Thread t = null;
        
        String[] saCommand = null;
        try
        {
            saCommand = resolveCommand(_sCommand, "salt", "password");
            
            _systemLogger.debug("Executing test command: " 
                + resolveCommand(saCommand));
            final Process p = r.exec(saCommand);
            t = new Thread(
                new Runnable() 
                {
                    public void run()
                    {
                        try
                        {
                            Thread.sleep(3000);
                            p.destroy();
                            _systemLogger.warn("Destroyed process");
                        }
                        catch (InterruptedException e)
                        {
                            _systemLogger.debug("Thread interrupted");
                        }
                    }
                }
            );
            
            t.start();
            int exitCode = p.waitFor();
            if (exitCode != 0)
            {
                StringBuffer sbError = new StringBuffer("Configured command returned exit code '");
                sbError.append(exitCode);
                sbError.append("': ");
                sbError.append(resolveCommand(saCommand));
                _systemLogger.error(sbError.toString());
                throw new OAException(SystemErrors.ERROR_INIT);
            }
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _systemLogger.error("Could not execute command: " 
                + resolveCommand(saCommand), e);
            throw new OAException(SystemErrors.ERROR_INIT);
        }
        finally
        {
            if (t != null)
                t.interrupt();
        }
    }
    
    private String[] resolveCommand(String sCommand, String sSalt, String sPassword)
    {
        String[] saCommand = sCommand.split(" ");
        for (int i=0; i<saCommand.length; i++)
        {
            String sItem = saCommand[i];
            if (sItem.equalsIgnoreCase("{salt}"))
                saCommand[i] = sSalt;
            else if (sItem.equalsIgnoreCase("{password}"))
                saCommand[i] = sPassword;
        }
        return saCommand;
    }
    
    private String resolveCommand(String[] saCommand)
    {
        StringBuffer sbCommand = new StringBuffer();
        for (int i = 0; i < saCommand.length; i++)
        {
            String sItem = saCommand[i];
            if (sItem != null)
            {
                sbCommand.append(sItem);
                if (i < saCommand.length)
                    sbCommand.append(" ");
            }
        }
        return sbCommand.toString();
    }
}
