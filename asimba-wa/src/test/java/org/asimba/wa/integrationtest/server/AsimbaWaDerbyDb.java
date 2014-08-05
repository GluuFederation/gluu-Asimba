package org.asimba.wa.integrationtest.server;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import javax.sql.DataSource;

import org.apache.commons.dbcp.BasicDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AsimbaWaDerbyDb {
	private static Logger _logger = LoggerFactory.getLogger(AsimbaWaDerbyDb.class);

	
	private static AsimbaWaDerbyDb _asimbaWaDerbyDb = null;
	
	public static AsimbaWaDerbyDb getInstance()
	{
		if (_asimbaWaDerbyDb == null) _asimbaWaDerbyDb = new AsimbaWaDerbyDb();
		return _asimbaWaDerbyDb;
	}
	
	private AsimbaWaDerbyDb()
	{
		String driverClassName = "org.apache.derby.jdbc.ClientDriver";
		String url = "jdbc:derby://localhost/memory:asimba-wa-db";
		String username = "username";
		String password = "password";
		
		BasicDataSource ds = null;
        ds = new BasicDataSource();
        ds.setDriverClassName(driverClassName);
        ds.setUrl(url);
        ds.setUsername(username);
        ds.setPassword(password);
        
        _datasource = ds;
	}
	
	private DataSource _datasource;
	
	
	/**
	 * Convenience method to execute an SQL-command in a string; note that 
	 * absolutely no handling, validation whatsoever of the SQL is done here.
	 * @param sql SQL to execute
	 */
	public void executeSql(String sql)
	{
		try (Connection con = _datasource.getConnection();
				PreparedStatement pstmt = con.prepareStatement(sql)
				)
				{
			pstmt.execute();
				} catch (SQLException e) {
					_logger.error("SQL went wrong: {}", e.getMessage(), e);
					e.printStackTrace();
				}
	}
	
	/**
	 * return a connection from the datasource
	 * @return
	 */
	public Connection getConnection() {
		if (_datasource == null) return null;
		try {
			return _datasource.getConnection();
		} catch (SQLException sqle) {
			_logger.error("Could not get connection: {}", sqle.getMessage(), sqle);
			return null;
		}
	}
	
}
