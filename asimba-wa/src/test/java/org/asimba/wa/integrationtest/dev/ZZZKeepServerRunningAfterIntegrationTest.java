package org.asimba.wa.integrationtest.dev;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Class that runs a test that waits for user input on the console to
 * continue. Work-around to enable the asimba-wa web-app to run
 * int the dynamically configured context, and manually operate it.
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
