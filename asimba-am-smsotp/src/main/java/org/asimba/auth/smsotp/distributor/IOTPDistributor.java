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
/**
 * SMS/OneTimePassword authentication method.
 * 
 * Authenticate a user by checking a one-time-password 
 * The implementation is based on PasswordAuthenticationMethod. 
 * 
 * Can be used as a Web Authentication Method with Asimba SSO server
 *
 * Part of Asimba
 * www.asimba.org
 *
 * @author mdobrinic@cozmanova.com
 * @author Cozmanova (www.cozmanova.com)
 */

package org.asimba.auth.smsotp.distributor;

import org.asimba.auth.smsotp.OTP;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.user.IUser;

public interface IOTPDistributor {

	/**
	 * Distribute the One Time Password oOtp to user oUser 
	 * @param oOtp Instance with OneTimePassword; timestamps and status will be updated
	 * @param oUser User to distribute the OneTimePassword to
	 * @return 0 if all OK; other value for service specific error
	 * @throws OAException when error.
	 */
	public int distribute(OTP oOtp, IUser oUser) throws OAException;
	
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
