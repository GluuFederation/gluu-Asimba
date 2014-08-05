package org.asimba.wa.integrationtest.client.saml;

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
