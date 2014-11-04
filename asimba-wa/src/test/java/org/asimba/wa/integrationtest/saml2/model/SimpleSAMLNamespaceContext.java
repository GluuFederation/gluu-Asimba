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
package org.asimba.wa.integrationtest.saml2.model;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.xml.namespace.NamespaceContext;

/**
 * Defines saml2p and saml2 namespaces, and allows custom map to be added to that
 * 
 * @author mdobrinic
 */
public class SimpleSAMLNamespaceContext implements NamespaceContext {

	private Map<String, String> _nsMap;
	
	public SimpleSAMLNamespaceContext(Map<String, String> map)
	{
		// Always add the SAML namespaces, so this class actually does introduce some context:
		_nsMap = new HashMap<>();
		_nsMap.put("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");
		_nsMap.put("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");
		_nsMap.put("md", "urn:oasis:names:tc:SAML:2.0:metadata");
		
		if (map != null) _nsMap.putAll(map);
	}
	
	@Override
	public String getNamespaceURI(String arg0) {
		return _nsMap.get(arg0);
	}

	@Override
	public String getPrefix(String arg0) {
		for(String k: _nsMap.keySet())
		{
			if (_nsMap.get(k).equals(arg0)) return k;
		}
		
		return null;
	}

	@Override
	public Iterator<?> getPrefixes(String arg0) {
		return _nsMap.keySet().iterator();
	}

}
