
/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2009 Alfa & Ariss B.V.
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
package com.alfaariss.oa.profile.aselect.business;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.authentication.factory.IAuthenticationProfileFactory;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
import com.alfaariss.oa.engine.core.server.Server;
import com.alfaariss.oa.engine.core.session.factory.ISessionFactory;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTAliasStore;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory;
import com.alfaariss.oa.profile.aselect.processor.handler.ASelectRequestorPool;

/**
 * Base implementation for service business logic.
 * 
 * Reads the profile configuration and creates handles to engine factories and 
 * other functionality.
 *  
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public abstract class AbstractOAService implements IComponent
{
    /** Configuration manager */    
    protected IConfigurationManager _configurationManager;
    /** oa profile section */
    protected Element _eOASection;
    /** session factory */
    protected ISessionFactory _SessionFactory;
    /** tgt factory */
    protected ITGTFactory _tgtFactory;
    /** requestor pool factory */
    protected IRequestorPoolFactory _requestorPoolFactory;
    /** authentciation factory*/
    protected IAuthenticationProfileFactory _authenticationProfileFactory;
    /** crypto manager */
    protected CryptoManager _cryptoManager;
    /** System logger */
    protected Log _logger; 
    /** Event logger */
    protected Log _eventLogger;
    /** Server object */
    protected Server _OAServer;
    /**  */
    protected ITGTAliasStore _aliasStoreSP;
    
    //TODO profile id should be configurable
    private final static String PROPERTY_SIGN_REQUESTS = "aselect.sign.requests";

    /**
     * Default constructor.
     */
    public AbstractOAService ()
    {
        super();
        _logger = LogFactory.getLog(this.getClass());     
        _eventLogger = LogFactory.getLog(Engine.EVENT_LOGGER);
    }

    /**
     * Start the OA Service.
     * 
     * Reads the profile configuration and creates handles to engine 
     * functionality.
     * 
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager,
        Element eConfig) throws OAException
    {
        _configurationManager = oConfigurationManager;
        
        Element eProfiles = _configurationManager.getSection(eConfig, "profiles");
        if (eProfiles == null)
        {
            _logger.error("No 'profiles' section found in configuration");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        //TODO profile id should be configurable, because the A-Select profile can be configured with a different profile id.
        _eOASection = _configurationManager.getSection(eProfiles, "profile", "id=aselect");
        if (_eOASection == null)
        {
            _logger.info(
                "No 'aselect' section found in 'profiles' section in configuration, profile is disabled");
        }
        else
        {
             Engine oaEngine = Engine.getInstance();
            //Retrieve server object
            _OAServer = oaEngine.getServer();
            
            _SessionFactory = oaEngine.getSessionFactory();
            _tgtFactory = oaEngine.getTGTFactory();
            _requestorPoolFactory = oaEngine.getRequestorPoolFactory();
            _authenticationProfileFactory = oaEngine.getAuthenticationProfileFactory();            
      
            _cryptoManager = oaEngine.getCryptoManager();
            if (_cryptoManager == null)
            {
                _logger.error("No crypto manager available");
                throw new OAException(SystemErrors.ERROR_INIT);
            }
            
            _aliasStoreSP = _tgtFactory.getAliasStoreSP();
         }            
    }
    
    /**
     * Restart the OA Service.
     * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
     */
    public void restart(Element eConfig) throws OAException
    {
        synchronized(this)
        {
            stop();
            start(_configurationManager, eConfig);
        }
    }
   
    /**
     * Stop the OA Service.
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    public void stop()
    {        
        _eOASection = null;
        _OAServer = null;    
        _SessionFactory = null;
        _requestorPoolFactory = null;
        _authenticationProfileFactory = null;
        _tgtFactory = null;
        _logger.info(getClass().getSimpleName() + " Stopped");
    }
    
    //TODO the following method is redundant; merge the ASelect Profile and ws (Erwin, Martijn)
    
    /**
     * Returns TRUE if requests must be signed.
     * 
     * Resolves signing value from ASelectRequestorPool or RequestorPool.
     * @param oRequestorPool OA Requestor pool
     * @param oASRequestorPool A-Select Requestor pool
     * @param oRequestor OA Requestor
     * @return true if requests must be signed
     * @throws OAException
     * @since 1.4
     */
    protected boolean doSigning(RequestorPool oRequestorPool, 
        ASelectRequestorPool oASRequestorPool, IRequestor oRequestor) throws OAException
    {
        String sEnabled = (String)oRequestor.getProperty(PROPERTY_SIGN_REQUESTS);
        if (sEnabled != null)
        {
            if ("TRUE".equalsIgnoreCase(sEnabled))
                return true;
            else if (!"FALSE".equalsIgnoreCase(sEnabled))
            {
                StringBuffer sbError = new StringBuffer("The configured requestor property (");
                sbError.append(PROPERTY_SIGN_REQUESTS);
                sbError.append(") value isn't a boolean: ");
                sbError.append(sEnabled);
                _logger.error(sbError.toString());
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }
        
        if (oASRequestorPool != null && oASRequestorPool.doSigning())
            return true;
        
        sEnabled = (String)oRequestorPool.getProperty(PROPERTY_SIGN_REQUESTS);
        if (sEnabled != null)
        {
            if ("TRUE".equalsIgnoreCase(sEnabled))
                return true;
            else if (!"FALSE".equalsIgnoreCase(sEnabled))
            {
                StringBuffer sbError = new StringBuffer("The configured requestorpool property (");
                sbError.append(PROPERTY_SIGN_REQUESTS);
                sbError.append(") value isn't a boolean: ");
                sbError.append(sEnabled);
                _logger.error(sbError.toString());
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
        }        
        return false;
    }
}