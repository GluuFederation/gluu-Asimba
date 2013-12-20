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

import junit.framework.TestCase;

public class URLPathContextTest extends TestCase {
	
	public void testURLPathContextOnePair() {
		String sURLPathContext = "a=b";
		
		URLPathContext o = URLPathContext.fromValue(sURLPathContext);
		
		assertEquals("Should process one key", 1, o.getParams().size());
		assertEquals("Should get value b for a", "b", o.getParams().get("a"));
	}
	
	
	public void testURLPathContextOnePairEscaped() {
		String sURLPathContext = "a=\\;b"; // a=\;b
		
		URLPathContext o = URLPathContext.fromValue(sURLPathContext);
		
		assertEquals("Should process one key", 1, o.getParams().size());
		assertEquals("Should get value ;b for a", ";b", o.getParams().get("a"));
	}
	
	
	public void testURLPathContextTwoPairsEscaped() {
		String sURLPathContext = "a=\\;b;\\;c=d";
		
		URLPathContext o = URLPathContext.fromValue(sURLPathContext);
		
		assertEquals("Should process two keys", 2, o.getParams().size());
		assertEquals("Should get value ;b for a", ";b", o.getParams().get("a"));
		assertEquals("Should get value d for ;c", "d", o.getParams().get(";c"));
	}
	
	
	public void testURLPathContextDecodeEscaped() {
		URLPathContext o = new URLPathContext();
		o.addParam("a;", "b=");

		String s = o.toString();
		assertEquals("Invalid encoding", "a\\;=b\\=", s);
	}

}
