/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2008 Alfa & Ariss B.V.
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
package com.alfaariss.oa.util.database.jdbc;

import java.util.Properties;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.dbcp.BasicDataSourceFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.util.database.DatabaseException;

/**
 * DataSource factory.
 * 
 * @author MHO
 * @author Alfa & Ariss
 *
 */
public class DataSourceFactory
{
    private static Log _logger = LogFactory.getLog(DataSourceFactory.class);
    
    /**
     * Creates a DataSource object specified by XML configuration.
     *
     * <ul>
     * <li>password</li>
     * <li>url</li>
     * <li>username</li>
     * <li>driver</li>
     * <li>maxactive <b>(optional)</b></li>
     * <li>maxidle <b>(optional)</b></li>
     * <li>maxwait <b>(optional)</b></li>
     * </ul> 
     * @param configurationManager configuration manager
     * @param eConfig configuration
     * @return DataSource object
     * @throws DatabaseException if creation fails
     */
    public static DataSource createDataSource(
        IConfigurationManager configurationManager, Element eConfig) 
        throws DatabaseException
    {
        DataSource ds = null;
        try
        {
            ds = createByContext(configurationManager, eConfig);
            if (ds != null)
                _logger.info("Created DataSource by reading from context");
            else
            {
                ds = createByConfiguration(configurationManager, eConfig);
                _logger.info("Created DataSource by reading from configuration");
            }
        }
        catch (DatabaseException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not create datasource", e);
            throw new DatabaseException(SystemErrors.ERROR_INTERNAL);
        }
        return ds;
    }
    
    /**
     * Creates a DataSource object specified by the supplied properties:
     * 
     * <ul>
     *  <li>environment_context</li>
     *  <li>resource-ref</li>
     * </ul>
     * 
     * or:
     *
     *<ul>
     * <li>password</li>
     * <li>url</li>
     * <li>username</li>
     * <li>driverClassName</li>
     * <li>maxActive</li>
     * <li>maxIdle</li>
     * <li>maxWait</li>
     * <li>minIdle</li>
     * <li>defaultAutoCommit</li>
     * <li>defaultReadOnly</li>
     * <li>defaultTransactionIsolation</li>
     * <li>defaultCatalog</li>
     * <li>initialSize</li>
     * <li>testOnBorrow</li>
     * <li>testOnReturn</li>
     * <li>timeBetweenEvictionRunsMillis</li>
     * <li>numTestsPerEvictionRun</li>
     * <li>minEvictableIdleTimeMillis</li>
     * <li>testWhileIdle</li>
     * <li>validationQuery</li>
     * <li>accessToUnderlyingConnectionAllowed</li>
     * <li>removeAbandoned</li>
     * <li>removeAbandonedTimeout</li>
     * <li>logAbandoned</li>
     * <li>poolPreparedStatements</li>
     * <li>maxOpenPreparedStatements</li>
     * <li>connectionProperties</li>
     * </ul> 
     * @param pConfig config properties
     * @return DataSource object
     * @throws DatabaseException if creation fails 
     */
    public static DataSource createDataSource(Properties pConfig) 
        throws DatabaseException
    {
        DataSource ds = null;
        try
        {
            if (pConfig.containsKey("environment_context"))
            {
                String sContext = pConfig.getProperty("environment_context");
                
                Context envCtx = null;
                try
                {
                    envCtx = (Context)new InitialContext().lookup(sContext);
                }
                catch (NamingException e)
                {
                    _logger.warn("Could not find context: " + sContext, e);
                    throw new DatabaseException(SystemErrors.ERROR_INIT);
                }
                
                String sResourceRef = pConfig.getProperty("resource-ref");
                try
                {
                    ds = (DataSource)envCtx.lookup(sResourceRef);
                }
                catch (NamingException e)
                {
                    _logger.warn("Could not find resource ref: " + sResourceRef, e);
                    throw new DatabaseException(SystemErrors.ERROR_INIT);
                }
                
                _logger.info("Created DataSource by reading from context");
            }
            else
            {
                ds = BasicDataSourceFactory.createDataSource(pConfig);
                _logger.info("Created DataSource by reading properties object");
            }
        }
        catch(Exception e)
        {
            _logger.fatal("Could not initialize object", e);
            throw new DatabaseException(SystemErrors.ERROR_INTERNAL);
        }
        return ds;
    }
    
    /*
     * Creates a BasicDataSource by retrieving it from the context.
     * 
     * Reads the following config items:
     * <ul>
     *  <li>environment_context</li>
     *  <li>resource-ref</li>
     * </ul>
     */
    private static DataSource createByContext(
        IConfigurationManager configurationManager, Element eConfig) 
        throws DatabaseException
    {
        DataSource dataSource = null;
        try
        {
            String sContext = configurationManager.getParam(eConfig, "environment_context");
            if (sContext == null)
            {
                _logger.info("Could not find the optional 'environment_context' item in config");
            }
            else
            {
                String sResourceRef = configurationManager.getParam(eConfig, "resource-ref");
                if (sResourceRef == null)
                {
                    _logger.warn("Could not find the 'resource-ref' item in config");
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                Context envCtx = null;
                try
                {
                    envCtx = (Context)new InitialContext().lookup(sContext);
                }
                catch (NamingException e)
                {
                    _logger.warn("Could not find context: " + sContext, e);
                    throw new DatabaseException(SystemErrors.ERROR_INIT);
                }
                
                try
                {
                    dataSource = (DataSource)envCtx.lookup(sResourceRef);
                }
                catch (NamingException e)
                {
                    _logger.warn("Could not find resource ref: " + sResourceRef, e);
                    throw new DatabaseException(SystemErrors.ERROR_INIT);
                }
            }
        }
        catch (DatabaseException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.warn("Could not create datasource", e);
            throw new DatabaseException(SystemErrors.ERROR_INTERNAL);
        }
        return dataSource;
    }

    /*
     * Creates a BasicDataSource with configured parameters.
     * 
     * Reads the following config items:
     * <ul>
     *  <li>driver</li>
     *  <li>url</li>
     *  <li>username</li>
     *  <li>password</li>
     * </ul>
     */
    private static DataSource createByConfiguration(
        IConfigurationManager configurationManager, Element eConfig) 
        throws DatabaseException
    {
        BasicDataSource ds = null;
        try
        {
            ds = new BasicDataSource();
            
            String sDriver = configurationManager.getParam(eConfig, "driver");
            if (sDriver == null)
            {
                _logger.warn("No 'driver' item found in configuration");
                throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
            }
            ds.setDriverClassName(sDriver);
            
            String sURL = configurationManager.getParam(eConfig, "url");
            if(sURL == null)
            {
                _logger.warn("No 'url' item found in configuration");
                throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
            }
            ds.setUrl(sURL);
            
            String sUser = configurationManager.getParam(eConfig, "username");
            if(sUser == null)
            {
                _logger.warn("No 'username' item found in configuration");
                throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
            }
            ds.setUsername(sUser);
            
            String sPassword = configurationManager.getParam(eConfig, "password");
            if(sPassword == null)
            {
                _logger.warn("No 'password' item found in configuration");
                throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
            }
            ds.setPassword(sPassword);
            
            addOptionalSettings(configurationManager, eConfig, ds);
        }
        catch (DatabaseException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not initialize object", e);
            throw new DatabaseException(SystemErrors.ERROR_INTERNAL);
        }
        return ds;
    }
    
    /*
     * Reads the following config items:
     * <ul>
     *  <li>maxactive</li>
     *  <li>maxidle</li>
     *  <li>maxwait</li>
     *  <li>testonborrow</li>
     *  <li>testonreturn</li>
     *  <li>timebetweenevictionrunsmillis</li>
     *  <li>numtestsperevictionrun</li>
     *  <li>minevictableidletimemillis</li>
     *  <li>testwhileidle</li>
     *  <li>validationquery</li>
     * </ul>
     */
    private static DataSource addOptionalSettings(
        IConfigurationManager configurationManager, Element eConfig, 
        BasicDataSource dataSource) throws DatabaseException
    {
        try
        {
            String sMaxActive = configurationManager.getParam(eConfig, "maxactive");
            int iMaxActive = -1;
            if(sMaxActive != null)
            {
                try
                {
                    iMaxActive = Integer.parseInt(sMaxActive);
                }
                catch (NumberFormatException e)
                {
                    _logger.error("Wrong 'maxactive' item found in configuration: " + sMaxActive, e);
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            dataSource.setMaxActive(iMaxActive);
            
            String sMaxIdle = configurationManager.getParam(eConfig, "maxidle");
            if(sMaxIdle != null)
            {
                int iMaxIdle = -1;
                try
                {
                    iMaxIdle = Integer.parseInt(sMaxIdle);
                }
                catch (NumberFormatException e)
                {
                    _logger.error("Wrong 'maxidle' item found in configuration: " + sMaxIdle, e);
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
                dataSource.setMaxIdle(iMaxIdle);
            }
            
            String sMaxWait = configurationManager.getParam(eConfig, "maxwait");
            if(sMaxWait != null)
            {
                int iMaxWait = -1;
                try
                {
                    iMaxWait = Integer.parseInt(sMaxWait);
                }
                catch (NumberFormatException e)
                {
                    _logger.error("Wrong 'maxwait' item found in configuration: " + sMaxWait, e);
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
                dataSource.setMaxWait(iMaxWait);
            }
            
            String sTestOnBorrow = configurationManager.getParam(eConfig, "testonborrow");
            if (sTestOnBorrow != null)
            {
                boolean bTestOnBorrow = false;
                if (sTestOnBorrow.equalsIgnoreCase("true"))
                    bTestOnBorrow = true;
                else if (!sTestOnBorrow.equalsIgnoreCase("false"))
                {
                    _logger.error("Wrong 'testonborrow' item found in configuration: " + sTestOnBorrow);
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
                dataSource.setTestOnBorrow(bTestOnBorrow);
            }
            
            String sTestOnReturn = configurationManager.getParam(eConfig, "testonreturn");
            if (sTestOnReturn != null)
            {
                boolean bTestOnReturn = false;
                if (sTestOnReturn.equalsIgnoreCase("true"))
                    bTestOnReturn = true;
                else if (!sTestOnReturn.equalsIgnoreCase("false"))
                {
                    _logger.error("Wrong 'testonreturn' item found in configuration: " + sTestOnReturn);
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
                dataSource.setTestOnReturn(bTestOnReturn);
            }
            
            String sTimeBetweenEvictionRunsMillis = configurationManager.getParam(eConfig, "timebetweenevictionrunsmillis");
            if (sTimeBetweenEvictionRunsMillis != null)
            {
                try
                {
                    long lTimeBetweenEvictionRunsMillis = Long.parseLong(sTimeBetweenEvictionRunsMillis);
                    dataSource.setTimeBetweenEvictionRunsMillis(lTimeBetweenEvictionRunsMillis);
                }
                catch (NumberFormatException e)
                {
                    _logger.error("Wrong 'timebetweenevictionrunsmillis' item found in configuration: " + sTimeBetweenEvictionRunsMillis, e);
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            String sNumTestsPerEvictionRun = configurationManager.getParam(eConfig, "numtestsperevictionrun");
            if(sNumTestsPerEvictionRun != null)
            {
                int iNumTestsPerEvictionRun = -1;
                try
                {
                    iNumTestsPerEvictionRun = Integer.parseInt(sNumTestsPerEvictionRun);
                }
                catch (NumberFormatException e)
                {
                    _logger.error("Wrong 'numtestsperevictionrun' item found in configuration: " + sNumTestsPerEvictionRun, e);
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
                dataSource.setNumTestsPerEvictionRun(iNumTestsPerEvictionRun);
            }
            
            String sMinEvictableIdleTimeMillis = configurationManager.getParam(eConfig, "minevictableidletimemillis");
            if (sMinEvictableIdleTimeMillis != null)
            {
                try
                {
                    long lMinEvictableIdleTimeMillis = Long.parseLong(sMinEvictableIdleTimeMillis);
                    dataSource.setMinEvictableIdleTimeMillis(lMinEvictableIdleTimeMillis);
                }
                catch (NumberFormatException e)
                {
                    _logger.error("Wrong 'minevictableidletimemillis' item found in configuration: " + sMinEvictableIdleTimeMillis, e);
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            String sTestWhileIdle = configurationManager.getParam(eConfig, "testwhileidle");
            if (sTestWhileIdle != null)
            {
                boolean bTestWhileIdle = false;
                if (sTestWhileIdle.equalsIgnoreCase("true"))
                    bTestWhileIdle = true;
                else if (!sTestWhileIdle.equalsIgnoreCase("false"))
                {
                    _logger.error("Wrong 'testwhileidle' item found in configuration: " + sTestWhileIdle);
                    throw new DatabaseException(SystemErrors.ERROR_CONFIG_READ);
                }
                dataSource.setTestWhileIdle(bTestWhileIdle);
            }
            
            String sValidationQuery = configurationManager.getParam(eConfig, "validationquery");
            if (sValidationQuery != null)
            {
                dataSource.setValidationQuery(sValidationQuery);
            }

        }
        catch (DatabaseException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Could not create datasource", e);
            throw new DatabaseException(SystemErrors.ERROR_INTERNAL);
        }
        return dataSource;
    }

    
}
