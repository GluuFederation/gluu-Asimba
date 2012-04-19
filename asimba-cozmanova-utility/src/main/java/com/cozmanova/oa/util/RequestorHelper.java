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
package com.cozmanova.oa.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class RequestorHelper {
	protected static Log _logger = LogFactory.getLog(RequestorHelper.class);
	
	/**
	 *  Establish the profile-id from a Requestor URL
	 **/
	public static String entityHostFromRequestor(String sRequestorURL)
	{
		String sResult = null;
		String sRegEx;
		sRegEx = "http[sS]?\\://[^/]+:?[\\d]*/[a-z]+/profiles/([^/]*)/.*";
		
		Pattern p = Pattern.compile(sRegEx);
		Matcher m = p.matcher(sRequestorURL);
		
		if (m.matches()) {
			sResult = m.group(1);
		}
		
		_logger.debug("Established entity "+sResult+" from "+sRequestorURL);
		return sResult;
	}
	
}
