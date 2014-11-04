/*
 * Asimba - Serious Open Source SSO
 * 
 * Copyright (C) 2014 Asimba
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
package org.asimba.wa.integrationtest.saml2.idp;

import java.util.HashMap;
import java.util.Map;

public class BasicUserInfoProvider implements IUserInfoProvider {
	
	@Override
	public String getUserId(String format) 
	{
		switch (format)
		{
		case SAML_NAMEIDFORMAT_UNSPECIFIED :
			return "unspecified:userid";
		case SAML_NAMEIDFORMAT_PERSISTENT :
			return "persistent:userid";
		case SAML_NAMEIDFORMAT_TRANSIENT :
			return "transient:userid";
		}
		
		return format+":unknown-nameid-format";
	}

	@Override
	public Map<String, String> getAttributes() 
	{
		Map<String, String> map = new HashMap<>();
		
		map.put("Attribute1", "Value1");
		map.put("Attribute2", "Value2");
		map.put("Attribute3", "Value3");
		map.put("Attribute4", "Value4");
		
		return map;
	}

}
