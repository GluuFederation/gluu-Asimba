package org.asimba.wa.integrationtest;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.MalformedURLException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.asimba.wa.integrationtest.server.AsimbaWaDerbyDb;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlDivision;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

public class ServerStatusIntegrationTest {

	/** local logger instance */
	private static final Logger _logger = LoggerFactory.getLogger(ServerStatusIntegrationTest.class);
	
	@Before
	public void setup() throws Exception
	{
	}
	
	
	/**
	 * Test to load the main page; establish whether the server is up and running. 
	 * @throws IOException 
	 * @throws MalformedURLException 
	 * @throws FailingHttpStatusCodeException 
	 */
	@Test
	public void loadMainPageTest() throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		_logger.trace("loadMainPageTest entered.");
		
		WebClient webClient = new WebClient();
		String url = RunConfiguration.getInstance().getProperty("asimbawa.server.url");
		
		HtmlPage htmlPage = webClient.getPage(url);

		// Validation criteria:
		// Must contain a div@id=assertMainPageOK to be OK:
		HtmlDivision div = htmlPage.getHtmlElementById("assertMainPageOK");
		assertNotNull(div);
		
		_logger.info("Asimba-wa main page returned OK.");
		
		webClient.closeAllWindows();
	}
	
	
	@Test
	public void testDataSource()
	{
		_logger.trace("testDataSource entered.");
		
		// Connection con;
		String sql = "SELECT * FROM authn_profile";	// test...
		
		AsimbaWaDerbyDb asimbaWaDB = AsimbaWaDerbyDb.getInstance();
		
		try (Connection con = asimbaWaDB.getConnection();
				Statement stmt = con.createStatement();
				ResultSet rs = stmt.executeQuery(sql)) {
			
			while (rs.next()) {
				String id = rs.getString(1);	// 1-based
				_logger.info("Retrieved record with id {}", id);
			}
			
		} catch (SQLException e) {
			_logger.error("Could not create connection: {}", e.getMessage(), e);
			fail("Could not create connection");
		}
		
		_logger.info("Datasource connection returned values OK");
	}
}
