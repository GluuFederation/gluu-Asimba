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
package org.asimba.wa.integrationtest.dev;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Class that runs a test that waits for user input on the console to
 * continue. Work-around to enable the asimba-wa web-app to run
 * in the dynamically configured context, and manually operate it.
 * 
 * Tests are run in alphabetical order, so this one is named to run last.
 * 
 * @author mdobrinic
 *
 */
public class ZZZKeepServerRunningAfterIntegrationTest {

	
	@Test @Category(DevTests.class)
	public void runUntilInterrupted() throws Exception
	{
		System.out.println("Press CTRL-C to stop Maven.");
		
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        br.readLine();
        
	}
}
