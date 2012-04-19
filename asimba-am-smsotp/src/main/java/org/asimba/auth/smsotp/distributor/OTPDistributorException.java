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
package org.asimba.auth.smsotp.distributor;

import com.alfaariss.oa.OAException;

public class OTPDistributorException 
	extends OAException 
{
	/**
	 * Unique version identifier
	 */
	private static final long serialVersionUID = -1179598739949406294L;
	
	
	/**
	 * A numerical code of the exception
	 */
	private int _iCode;

	
    /**
     * Constructor.
     * 
     * @param event The user event.
     * @param iCode The error code.
     */
    public OTPDistributorException(int iCode)
    {
        super(iCode);
        _iCode = iCode;
    }
    
    
    /**
     * Retrieve the exception code.
     *
     * @return code of the exception.
     */
    public int getCode() {
        return _iCode;
    }

}
