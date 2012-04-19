/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
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
package org.asimba.auth.smsotp.generator;

import org.asimba.auth.smsotp.OTP;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.user.IUser;

public interface IOTPGenerator {
    /** Charset is UTF-8 */
    public final static String CHARSET = "UTF-8";    
    
    
    /**
     * Generate a new One Time Password instance for the provided User
     * @param oUser User to generate OTP instance for
     * @return Generated OTP instance
     * @throws OAException Thrown when a system exception occurred
     * @throws UserException Thrownb when a user related exception occurred
     */
    public OTP generate(IUser oUser) throws OAException, UserException;
    
    /**
     * Authenticate method. 
     * 
     * DD User not found in password back-end results in {@link UserEvent#AUTHN_METHOD_NOT_SUPPORTED}. 
     * @param sUserName The user name. 
     * @param sPassword The password. 
     * @return true if authenticated. 
     * @throws OAException Thrown when a system exception occurred
     * @throws UserException Thrownb when a user related exception occurred
     *
     */
    public boolean authenticate(
        IUser oUser, OTP oOtp, String sUserName, String sPassword) throws OAException, UserException;

    /**
     * Start the handler.
     * @param oConfigurationManager the configuration manager used to retrieve
     * the config from the supplied <code>Element</code>.
     * @param eConfig The configuration section or <code>null</code> if no 
     * configuration is found.
     * @throws OAException
     */
    public void start(IConfigurationManager oConfigurationManager
        , Element eConfig) throws OAException;
    
    /**
     * Stops the handler.
     */
    public void stop();
}
