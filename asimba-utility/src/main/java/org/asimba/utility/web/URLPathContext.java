/*
 * Asimba Server
 * 
 * Copyright (C) 2013 Asimba
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
package org.asimba.utility.web;

import java.io.Serializable;
import java.io.StringWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Pattern;


/**
 * Serializable class that wraps around URLPath context arguments 
 * as they are provided before the querystring of a URL 
 * 
 * Separator is ';'
 * Escape character is '\'
 * 
 * i.e.
 * http://host/a/b=c;d=e would be parsed into { "b"->"c", "d"->"e" }
 * http://host/a/b=c\;;d=e would be parsed into { "b"->"c;", "d"->"e" }
 * http://host/a would be parsed in { a } , which is a key without value
 * 
 * No multivalues are supported
 * 
 * @author mdobrinic
 *
 */
public class URLPathContext implements Serializable {

	public static final String ESCCHAR = "\\";
	
	/** for serialization */
	private static final long serialVersionUID = -3007362015683755696L;
	
	/** local store for parsed key->value entries */
	protected Map<String, String> _mParams;
	
	
	public URLPathContext() {
		_mParams = new HashMap<String, String>();
	}
	
	/**
	 * Parse the provided string into a URLPathContex instance
	 * @param sURLPathContext String to parse
	 * @return initialized URLPathContext instance
	 */
	public static URLPathContext fromValue(String sURLPathContext) {
		URLPathContext oURLPathContext = new URLPathContext();
		
		String delim = ";";
		String regex = "(?<!" + Pattern.quote(ESCCHAR) + ")" + Pattern.quote(delim);

		String[] pairs = sURLPathContext.split(regex);	
		
		for(String pair: pairs) {
    		String[] p = pair.split("=");
    		
    		if (p.length>1) {
    			oURLPathContext._mParams.put(unescape(p[0], ESCCHAR), unescape(p[1], ESCCHAR));
    		} else {
    			oURLPathContext._mParams.put(unescape(p[0], ESCCHAR), null);
    		}
    	}
		
		return oURLPathContext;
	}

	
	public void addParam(String sKey, String sValue) {
		if (sValue != null) {
			_mParams.put(sKey, sValue);
		} else {
			_mParams.put(sKey, null);
		}
	}
	
	
	protected static String escape(String sValue, String sEscapeChar) {
		StringWriter s = new StringWriter();
		
		int l = sValue.length();
        for (int i=0; i<l; i++) {
            char ch = sValue.charAt(i);
            
            if (ch == '\\' || ch == '=' || ch == ';') {
            	s.write(sEscapeChar);
            }
            s.append(ch);
           
        }
		return s.toString();
	}
	
	protected static String unescape(String sValue, String sEscapeChar) {
		StringWriter s = new StringWriter();
		char escapeChar = sEscapeChar.charAt(0);
		
		boolean escaping=false;
		int l = sValue.length();
        for (int i=0; i<l; i++) {
        	char ch = sValue.charAt(i);
        	
        	if (escaping) {
        		s.write(ch);
        	} else {
        		if (escapeChar == ch) {
        			escaping = true;
        		} else {
        			s.write(ch);
        			escaping = false;
        		}
        	}
        }
        
        return s.toString();
	}
	
	
	/**
	 * Write to key=value to string; the values that are passed in, must be un-escaped
	 * @param pair
	 * @param sb
	 */
	protected void pairToStringBuffer(Entry<String, String> pair, StringBuffer sb) {
		sb.append(escape(pair.getKey(), ESCCHAR));
		
		if (pair.getValue() != null) {
			sb.append("=");
			sb.append(escape(pair.getValue(), ESCCHAR));
		}
	}
	
	public String toString() {

		StringBuffer sb = new StringBuffer();
		Iterator<Entry<String, String>> it = _mParams.entrySet().iterator();
		if (it.hasNext()) {
			pairToStringBuffer(it.next(), sb);
			while (it.hasNext()) {
				sb.append(";"); pairToStringBuffer(it.next(), sb);
			}
		}
		
		return sb.toString();
	}
	
	
	public Map<String, String> getParams() {
		return Collections.unmodifiableMap(_mParams);
	}
	
}
