package org.asimba.utility.filesystem;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class PathTranslatorTest extends TestCase {


	/** 
	 * Default constructor; delegate construction to parent
	 * @param sName
	 */
	public PathTranslatorTest(String sName) {
		super(sName);
	}
	
	
	/**
     * @return The suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite( PathTranslatorTest.class );
    }
    
    
    /**
     * TODO: Create testcase for initializing from DOM
     */
    public void testStart() {
    	assertTrue( true );
    }
    
    
    public void testMap()
    {
    	// Create context
    	PathTranslator o = PathTranslator.getInstance();
    	
    	// Configuration
    	o.addKey("user.home", "/Users/dopey");	// unix style path
    	o.addKey("app.home", "C:\\tomcat7\\webapps\\asimba-wa");
    	
    	// Perform tests:
    	String sNewfile;
    	sNewfile = o.map("${user.home}/testfile");
    	assertEquals("/Users/dopey/testfile", sNewfile);
    	
    	sNewfile = o.map("${app.home}/testwinfile");
    	assertEquals("C:\\tomcat7\\webapps\\asimba-wa/testwinfile", sNewfile);
    	
    	// Remove key and do again (should return unchanged value)
    	o.removeKey("user.home");
    	sNewfile = o.map("${user.home}/testfile");
    	assertEquals("${user.home}/testfile", sNewfile);
    	
    }

    
    
}
