/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2010 Alfa & Ariss B.V.
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
package com.alfaariss.oa.util.logging;

import java.sql.BatchUpdateException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Properties;

import javax.sql.DataSource;

import org.apache.log4j.Appender;
import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.spi.ErrorCode;
import org.apache.log4j.spi.LoggingEvent;

import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.util.database.DatabaseException;
import com.alfaariss.oa.util.database.jdbc.DataSourceFactory;

/**
 * {@link Appender} which writes events into a database via JDBC.
 * <br><br>
 * This Appender only accepts {@link AbstractEventLogItem} objects 
 * as log message.
 * <br><br>
 * The following parameters can be configured:
 * <dl>
 *  <dt>driver</dt>
 *      <dd>Full name of the JDBC driver to be used.</dd>
 *  <dt>url</dt>
 *      <dd>The Database URL database url of the form jdbc:subprotocol:subname</dd>
 *  <dt>username</dt><dd>The database user</dd>
 *  <dt>password</dt><dd>The database password</dd>
 * </dl>
 * 
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class EventJDBCAppender 
    extends AppenderSkeleton implements Appender
{
    //Helper Components
    private boolean _initialized;   
    private DataSource _dataSource;
    /*
     * - environment_context
     * - resource-ref
     * 
     * Or
     * 
     * - database driver.
     * - database url of the form jdbc:subprotocol:subname
     * - database user
     * - database password
     * - etc.
     */
    private Properties _pResource;

    /**
     * Stores the table in which the logging will be done 
     */
    private String _table = null;
    
    /**
     * Defines how many messages will be buffered until they will be updated to
     * the database
     */
    private int _bufferSize = 1;
    
    /**
     * The complete log insert query. 
     */
    private String _query = null;
    
    /** 
     * The buffer 
     */
    private ArrayList<AbstractEventLogItem> _buffer;
    
    /**
     * Helper object for clearing out the buffer
     */
    protected ArrayList<AbstractEventLogItem> _removesBuffer;
  
    /**
     * The insert query pre-fix.
     */
    public static final String INSERT_QUERY_PREFIX = "INSERT INTO ";
    
    /**
     * The insert query post-fix.
     */
    public static final String INSERT_QUERY_POSTFIX = 
        "(session_id, tgt_id, state, logitemtype, event, user_id, organization_id, ip, " + 
        "requestor_id, message, authority) VALUES (?,?,?,?,?,?,?,?,?,?,?)"; 
    
    /**
     * The deafult table name
     */
    public static final String DEFAULT_TABLE = "event_log";
   
    /**
     * Create a new <code>EventJDBCAppender</code>.
     * Performs {@link AppenderSkeleton#AppenderSkeleton()}
     * an creates the buffers.
     * 
     */
    public EventJDBCAppender ()
    {
        super();     
        _buffer = new ArrayList<AbstractEventLogItem>(_bufferSize); 
        _removesBuffer = new ArrayList<AbstractEventLogItem>(_bufferSize);
        _initialized = false;    
        _table = DEFAULT_TABLE;
        _pResource = new Properties();
        
        //Set backup appender
        setErrorHandler(new JDBCErrorHandler());
    }
    
    /**
     * Adds the event to the buffer.  
     * When full the buffer is flushed.
     * @see org.apache.log4j.AppenderSkeleton#append(
     *  org.apache.log4j.spi.LoggingEvent)
     */
    public void append(LoggingEvent event) 
    {
        if (!_initialized) 
        {
            if (!initialize()) 
            {
                errorHandler.error("Could not append log item, not initialized", 
                    null, ErrorCode.WRITE_FAILURE);
                return;
            }
        }
        
        Object message = event.getMessage();
        if(message instanceof AbstractEventLogItem)
        {
            _buffer.add((AbstractEventLogItem)message);
            if (_buffer.size() >= _bufferSize)
                flushBuffer();
        }
        else
        {
            errorHandler.error(
                "Could not append log item, not a valid authentication message: " 
                + message, null, ErrorCode.WRITE_FAILURE); 
        }
    }

    /** closes the connection before disposal */
    public void finalize() 
    {        
        close();
        super.finalize();
    }

    /**
     * Flush the buffer.
     * @see org.apache.log4j.AppenderSkeleton#close()
     */
    public void close()
    {   
        flushBuffer();        
    }

    /**
     * The <code>EventJDBCAppender</code> does not require a layout.
     * @see org.apache.log4j.AppenderSkeleton#requiresLayout()
     */
    public boolean requiresLayout()
    {
        return false;
    }

    /**
     * Set the buffer size.
     * @param bufferSize The new buffer size.
     */
    public void setBufferSize(int bufferSize)
    {
        this._bufferSize = bufferSize;
        _buffer.ensureCapacity(bufferSize);
        _removesBuffer.ensureCapacity(bufferSize);
    }
    
    /**
     * Set a new environment_context.
     * @param environmentContext The environment_context.
     */
    public void setEnvironmentContext(String environmentContext)
    {
        if(environmentContext != null)
            _pResource.put("environment_context", environmentContext);
    }

    /**
     * Set a new resource-ref.
     * @param resourceRef The resource-ref.
     */
    public void setResourceRef(String resourceRef)
    {
        if(resourceRef != null)
            _pResource.put("resource-ref", resourceRef);
    }

    /**
     * Set a new password.
     * @param password The database password.
     */
    public void setPassword(String password)
    {
        if(password != null)
            _pResource.put("password", password);
    }

    /**
     * Set a new database URL.
     * @param url The database URL.
     */
    public void setUrl(String url)
    {
        if(url != null)
            _pResource.put("url", url);
    }

    /**
     * Set a new database username.
     * @param username The database user.
     */
    public void setUsername(String username)
    {
        if(username != null)
            _pResource.put("username", username);
    }

    /**
     * Set a database driver.
     * 
     * @param driver The database driver.
     */
    public void setDriver(String driver)
    {
        if(driver != null)
            _pResource.put("driverClassName", driver);
    }
   
    /**
     * Set a maximum number of active connections.
     *
     * @param maxActive The maximum number of active connections that can be 
     *  allocated from this pool at the same time, or negative for no limit.
     */
    public void setMaxActive(int maxActive)
    {
        _pResource.put("maxActive", maxActive);
    }
    
    /**
     * Set a maximum number of connections that can remain idle
     *
     * @param maxIdle The maximum number of connections that can remain idle in 
     *  the pool, without extra ones being released, or negative for no limit.
     */
    public void setMaxIdle(int maxIdle)
    {
        _pResource.put("maxIdle", maxIdle);
    }
    
    /**
     * Set a maximum number of connections that can remain idle in the pool.
     *
     * @param minIdle The minimum number of active connections that can remain 
     *  idle in the pool, without extra ones being created, or 0 to create none.
     */
    public void setMinIdle(int minIdle)
    {
        _pResource.put("minIdle", minIdle);
    }
    
    /**
     * Set an initial number of connections.
     *
     * @param initialSize The initial number of connections that are created 
     *  when the pool is started.
     */
    public void setInitialSize(int initialSize)
    {
        _pResource.put("initialSize", initialSize);
    }
    
    /**
     * Set a maximum number of milliseconds that the pool will wait.

     * @param maxWait The maximum number of milliseconds that the pool will wait 
     *  (when there are no available connections) for a connection to be 
     *  returned before throwing an exception, or <= 0 to wait indefinitely.
     */
    public void setMaxWait(long  maxWait)
    {
        _pResource.put("maxWait", maxWait);
    }
    
    /**
     * Set a new database table.
     * @param table The new table name.
     */
    public void setTable(String table)
    {
        this._table = table;
    }    

    /**
     * Initialize the <code>EventJDBCAppender</code>
     * 
     * Internal method. Returns true, when the appender is ready to 
     * append messages to the database, else false.
     * @return <code>true</code> if initialized.
     */
    private boolean initialize() 
    {
        if (!_initialized) 
        {           
            try
            {
                _dataSource = DataSourceFactory.createDataSource(_pResource);
                StringBuffer sb = new StringBuffer(INSERT_QUERY_PREFIX);
                sb.append(_table).append(INSERT_QUERY_POSTFIX);
                _query = sb.toString();
                
                _initialized = true;
            }  
            catch (DatabaseException e)
            {
                errorHandler.error(
                    "Error opening JDBC connection", e, 
                    ErrorCode.GENERIC_FAILURE);
            }    
        }
        return _initialized;
    }
    
    /**
     * Write logging using a JDBC batch insert. 
     */
    private void flushBuffer()
    {
        Savepoint sp = null;   
        PreparedStatement statement = null;
        Connection conn = null;
        if (_buffer.size() < 1) 
            return;        
        try
        {
          //Open new connection
            conn = _dataSource.getConnection();
            if(_bufferSize > 1)
            {
                conn.setAutoCommit(false);
                sp = conn.setSavepoint();
            }
            statement = conn.prepareStatement(_query);            
       
               //Log
            for(AbstractEventLogItem logItem : _buffer)
            {
                //session_id, tgt_id, state, event, user_id, ip, 
                //requestor,message, authority
                statement.setString(1, logItem.getSessionId());
                statement.setString(2, logItem.getTgtId());
                SessionState eventType = logItem.getEventType();               
                if(eventType != null)
                    statement.setInt(3, eventType.ordinal());
                else
                    statement.setNull(3, Types.INTEGER);
                
                Integer intLogItemType = logItem.getLogItemType();
                if(intLogItemType != null)
                    statement.setInt(4, intLogItemType.intValue());
                else
                    statement.setNull(4, Types.INTEGER);
                
                if(logItem instanceof UserEventLogItem)
                {
                    UserEvent event = ((UserEventLogItem)logItem).getEvent();
                    if(event != null)
                        statement.setString(5, event.name());
                    else
                        statement.setNull(5, Types.VARCHAR);
                }
                else if(logItem instanceof RequestorEventLogItem)
                {
                    RequestorEvent event = ((RequestorEventLogItem)logItem).getEvent();
                    if(event != null)
                        statement.setString(5, event.name());
                    else
                        statement.setNull(5, Types.VARCHAR);
                }                
                statement.setString(6, logItem.getUserId());
                statement.setString(7, logItem.getOrganizationId());
                statement.setString(8, logItem.getIpAddress()); //TODO IP Object? (Erwin)
                statement.setString(9, logItem.getRequestor());
                statement.setString(10, logItem.getMessage());
                statement.setString(11, logItem.getAuthority());
                statement.addBatch();
                _removesBuffer.add(logItem);
            }
            
            try
            {
                statement.executeBatch();
            }
            catch (BatchUpdateException e) 
            {             
                int[] updateCounts = e.getUpdateCounts();
                
                if(updateCounts.length != _buffer.size()) 
                        //Driver does not continue processing commands
                {
                    //length is index of failed item
                    //Removed failed item
                    _buffer.remove(updateCounts.length);
                }    
                else
                {
                    for (int i = 0; i < updateCounts.length; i++)
                    {
                        if(updateCounts[i] == Statement.EXECUTE_FAILED)
                        {
                            //Removed failed item
                            _buffer.remove(i);
                        }
                    }
                }
                throw e;
            }
            
            if(_bufferSize > 1)
                conn.commit();
            
            //remove any events that were reported from the buffer.
            _buffer.removeAll(_removesBuffer);            
        }
        catch (SQLException e)
        {
            try
            {
                if(_bufferSize > 1)
                    conn.rollback(sp);
            }
            catch (SQLException e1)
            {
               //Ignore
            }
            errorHandler.error(
                "Error executing batch, SQL exception: " + e.getNextException(), 
                e, ErrorCode.FLUSH_FAILURE);
        }    
        finally
        {     
            //clear the buffer of reported events
            _removesBuffer.clear();
            try
            {
                if(statement != null)
                    statement.close();
            }
            catch (SQLException e)
            {
               //Ignore
            }
            try
            {
                if(conn != null)
                    conn.close();
            }
            catch (SQLException e)
            {
               //Ignore
            }
        }
            
    }
}
