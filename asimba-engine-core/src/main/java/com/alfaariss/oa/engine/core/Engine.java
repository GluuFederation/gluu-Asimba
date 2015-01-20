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
package com.alfaariss.oa.engine.core;
import java.util.List;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.engine.core.cluster.IClusterStorageFactory;
import org.asimba.engine.core.confederation.IConfederationFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.datastorage.IDataStorageFactory;
import com.alfaariss.oa.api.storage.IStorageFactory;
import com.alfaariss.oa.engine.core.attribute.gather.AttributeGatherer;
import com.alfaariss.oa.engine.core.attribute.release.factory.IAttributeReleasePolicyFactory;
import com.alfaariss.oa.engine.core.authentication.factory.IAuthenticationProfileFactory;
import com.alfaariss.oa.engine.core.authorization.AuthorizationProfile;
import com.alfaariss.oa.engine.core.authorization.factory.IAuthorizationFactory;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.idp.IDPStorageManager;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
import com.alfaariss.oa.engine.core.server.Server;
import com.alfaariss.oa.engine.core.session.factory.ISessionFactory;
import com.alfaariss.oa.engine.core.tgt.TGTException;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory;
import com.alfaariss.oa.engine.core.user.factory.IUserFactory;
import com.alfaariss.oa.util.storage.factory.AbstractStorageFactory;

/**
 * The Main engine of the OpenASelect Server (OAS) Core.
 * 
 * @author Alfa & Ariss
 * @author MHO
 * @author EVB
 *
 */
public class Engine implements IComponent 
{
    
    /** The eventlogger name. */
    public static final String EVENT_LOGGER = 
        "com.alfaariss.oa.EventLogger";
    
    //The static logger
    private static Log _logger;
    
    //The static engine
    private static Engine _engine;
    
    private Server _server;
    private boolean _initialized;
    
    //The managers
    private IConfigurationManager _configurationManager;
    private CryptoManager _cryptoManager;
    //Attribute gatherer
    private AttributeGatherer _attributeGatherer;
    private ITGTFactory _tgtFactory;
    private ISessionFactory _sessionFactory;
    //Factories
    private IRequestorPoolFactory _requestorPoolFactory;    
    private IUserFactory _userFactory;
    private IAuthenticationProfileFactory _authenticationProfileFactory;   
    private IAuthorizationFactory _preAuthorizationFactory;
    private IAuthorizationFactory _postAuthorizationFactory;
    private IAttributeReleasePolicyFactory _attributeReleasePolicyFactory;
    private IDataStorageFactory _storageFactory; 
    private IClusterStorageFactory _clusterStorageFactory;
    private IDPStorageManager _idpStorageManager;
    
    /** Manager for confederations */
    protected IConfederationFactory _oConfederationFactory;
    
    private List<IComponent> _lComponents;

    /**
     * Retrieve a static handle to the <code>Engine</code> (Singleton).
     * @return Engine A static handle to the only 
     *  instance of the <code>Engine</code>.
     */
    public static Engine getInstance()
    {
        if (_engine == null)
            _engine = new Engine();
        return _engine;
    }
    
    /**
     * Retrieve the server specific information in a server object.
     * @return the OA Server object
     * @throws OAException
     */
    public Server getServer() throws OAException
    {
        if(_server == null)
        {
            _logger.debug("Server object isn't created"); 
            throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
        }        
        return _server;
    }
    
    /**
     * @return <code>true</code> if server is initialized.
     */
    public boolean isInitialized()
    {
        return _initialized;
    }
    
    /**
     * Retrieve the configuration manager.
     *
     * The returned configuration manager may be uninitialized. 
     * @return ConfigurationManager The configuration manager.
     * @throws OAException 
     */
    public IConfigurationManager getConfigurationManager() throws OAException
    {
        if(_configurationManager == null)
        {
            _logger.debug("Configuration Manager isn't initialized"); 
            throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
        }        
        return _configurationManager;
    }

    /**
     * Retrieve the Crypto Manager.
     *
     * @return The crypto manager.
     */
    public CryptoManager getCryptoManager()
    {
        return _cryptoManager;
    }

    /**
     * Retrieve the RequestorPoolFactory.
     *
     * @return IRequestorPoolFactory The RequestorPoolFactory.
     * @throws OAException If factory is not initialized.
     */
    public IRequestorPoolFactory getRequestorPoolFactory() throws OAException 
    {
        if(_requestorPoolFactory == null)
        {
            _logger.debug("Requestor Pool Factory isn't initialized"); 
            throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
        }
        return _requestorPoolFactory;
    }


    /**
     * Return configured ClusterStorageFactory
     * @return
     */
    public IClusterStorageFactory getClusterStorageFactory()
    {
    	return _clusterStorageFactory;
    }
    
    
    /**
     * Retrieve the TGTFactory.
     *
     * @return ITGTFactory The TGTFactory.
     * @throws OAException If factory is not initialized.
     */
    public ITGTFactory getTGTFactory() throws OAException
    {
        if(_tgtFactory == null)
        {
            _logger.error("TGT Factory is not started yet"); 
            throw new TGTException(SystemErrors.ERROR_NOT_INITIALIZED);
        }
        return _tgtFactory;
    }
    
    /**
     * Retrieve the Session Factory.
     *
     * @return ISessionFactory The Session Factory.
     * @throws OAException If factory is not initialized.
     */
    public ISessionFactory getSessionFactory() throws OAException
    {
        if(_sessionFactory == null)
        {
            _logger.error("Session Factory is not started yet"); 
            throw new TGTException(SystemErrors.ERROR_NOT_INITIALIZED);
        }
        return _sessionFactory;
    }

    /**
     * Retrieve the AuthenticationProfileFactory.
     *
     * @return IAuthenticationProfileFactory The AuthenticationProfileFactory.
     * @throws OAException If factory is not initialized.
     */
    public IAuthenticationProfileFactory getAuthenticationProfileFactory() 
        throws OAException
    {
        if(_authenticationProfileFactory == null)
        {
            _logger.debug("Authentication Profile Factory isn't initialized"); 
            throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
        }
        return _authenticationProfileFactory;
    }

    /**
     * Retrieve the UserFactory.
     *
     * @return IUserFactory user factory, 
     *  or <code>null</code> if not configured
     */
    public IUserFactory getUserFactory()
    {
        //Optional
        return _userFactory;
    }
    
    /**
     * Retrieve the StorageFactory.
     *
     * @return IDataStorageFactory
     * @since 1.1
     */
    public IDataStorageFactory getStorageFactory()
    {
        return _storageFactory;
    }

    /**
     * Retrieve the AttributeReleasePolicyFactory.
     *
     * @return IAttributeReleasePolicyFactory The factory,
     *  or <code>null</code> if not configured
     */
    public IAttributeReleasePolicyFactory getAttributeReleasePolicyFactory() 
    {
        //Optional
        return _attributeReleasePolicyFactory;
    }

    /**
     * Retrieve the IDP Storage Manager.
     * @return The storage manager.
     * @since 1.4
     */
    public IDPStorageManager getIDPStorageManager()
    {
        return _idpStorageManager;
    }
    
    /**
     * Retrieve the PreAuthorizationFactory.
     *
     * @return IAuthorizationFactory The factory, 
     *  or <code>null</code> if not configured
     */
    public IAuthorizationFactory getPreAuthorizationPoolFactory() 
    {
        //Optional
        return _preAuthorizationFactory;
    }
    
    /**
     * Retrieve the post Authorization Factory.
     *
     * @return IAuthorizationFactory The factory, 
     *  or <code>null</code> if not configured
     */
    public IAuthorizationFactory getPostAuthorizationPoolFactory() 
    {
        //Optional
        return _postAuthorizationFactory;
    }
    
    /**
     * Retrieve the AttributeGatherer.
     *
     * @return AttributeGatherer The AttributeGatherer.
     */
    public AttributeGatherer getAttributeGatherer()
    {
        //Optional
        return _attributeGatherer;
    }

    
    /**
     * Retrieve the (optional) ConfederationManager
     * @return
     */
    public IConfederationFactory getConfederationFactory()
    {
    	return _oConfederationFactory;
    }

    /**
     * Add a component dynamically to the engine.
     * 
     * Dynamic components are added as change listeners and 
     *  started, restarted and stopped by the engine.
     * @param oComponent The component to be added.
     */
    public void addComponent(IComponent oComponent)
    {
        _lComponents.add(oComponent);
    }

    /**
     * Remove a component from the engine.
     * @param oComponent The component to be removed.
     */
    public void removeComponent(IComponent oComponent)
    {
        _lComponents.remove(oComponent);
    }

    /**
     * Start all components (Composite method).
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */    
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws OAException
    {
        IComponent oComponent = null;
        try
        {
            if (_initialized)
            {
                _logger.info("Engine already started"); 
                return;
            }
            
            _configurationManager = oConfigurationManager;
            
            //Start Database Factory
            try
            {
                Element eStoragefactory = _configurationManager.getSection(
                    eConfig, "storagefactory");            
                if (eStoragefactory == null)
                {
                    _logger.info("No optional 'storagefactory' configuration section found");
                }
                else
                {
                    oComponent = getComponent(eStoragefactory, (IComponent)_storageFactory);
                    if (oComponent != null)
                        _storageFactory = (IDataStorageFactory)oComponent;
                    
                    ((IComponent)_storageFactory).start(
                        _configurationManager, eStoragefactory);
                }
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'storagefactory' class isn't an IDataStorageFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            //Start Cluster Storage Factory
            try
            {
                Element eClusterStorageFactory = _configurationManager.getSection(
                    eConfig, "clusterstoragefactory");            
                if (eClusterStorageFactory == null)
                {
                    _logger.info("No optional 'clusterstoragefactory' configuration section found");
                }
                else
                {
                	_logger.info("Found 'clusterstoragefactory' configuration.");
                	
                    oComponent = getComponent(eClusterStorageFactory, (IComponent)_clusterStorageFactory);
                    if (oComponent != null)
                    	_clusterStorageFactory = (IClusterStorageFactory)oComponent;
                    
                    ((IComponent)_clusterStorageFactory).start(
                        _configurationManager, eClusterStorageFactory);
                }
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'storagefactory' class isn't an IDataStorageFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            
            
            //Start crypto manager
            Element eCrypto = _configurationManager.getSection(eConfig, "crypto");
            if(eCrypto == null)
            {
                _logger.error("No 'crypto' configuration section found"); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }            
            _cryptoManager.start(_configurationManager, eCrypto);
            
            //Start TGT manager 
            Element eTGTConfig = _configurationManager.getSection(
                eConfig, "tgtfactory");
            if(eTGTConfig == null)
            {
                _logger.error(
                    "'tgtfactory' configuration section not found"); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            IStorageFactory factory = 
                AbstractStorageFactory.createInstance(
                    _configurationManager, eTGTConfig, 
                    _cryptoManager.getSecureRandom());
            try
            {
                _tgtFactory = (ITGTFactory)factory;
            }
            catch(ClassCastException e)
            {
                _logger.error(
                    "Configured TGT factory class isn't of type 'ITGTFactory': " 
                    + factory.getClass().getName(), e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            //Start Session manager 
            Element eSessionConfig = _configurationManager.getSection(
                eConfig, "sessionfactory");
            if(eSessionConfig == null)
            {
                _logger.error(
                    "'sessionfactory' configuration section not found"); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            factory = 
                AbstractStorageFactory.createInstance(
                    _configurationManager, eSessionConfig, 
                    _cryptoManager.getSecureRandom());
            try
            {
                _sessionFactory = (ISessionFactory)factory;
            }
            catch(ClassCastException e)
            {
                _logger.error(
                    "Configured session factory class isn't of type 'ISessionFactory': " 
                    + factory.getClass().getName(), e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
                        
            //Start Attribute gatherer           
            Element eAttributegatherer = _configurationManager.getSection(
                eConfig, "attributegatherer");
            if(eAttributegatherer == null)
            {
                _logger.info("No optional 'attributegatherer' configuration section found");
            }
            else
            {
                _attributeGatherer.start(_configurationManager, eAttributegatherer);
            }
            
            //Start Requestor Pool Factory
            try
            {
                Element eRequestorpoolfactory = _configurationManager.getSection(eConfig, "requestorpoolfactory");            
                if (eRequestorpoolfactory == null)
                {
                    _logger.error("No 'requestorpoolfactory' configuration section found");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                oComponent = getComponent(eRequestorpoolfactory,(IComponent)_requestorPoolFactory);
                if (oComponent != null)
                    _requestorPoolFactory = (IRequestorPoolFactory)oComponent;
                
                ((IComponent)_requestorPoolFactory).start(_configurationManager, eRequestorpoolfactory);
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'requestorpoolfactory' class isn't an IRequestorPoolFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            //Start authentication profile factory   
            try
            {
                Element eAuthentication = _configurationManager.getSection(
                    eConfig, "authentication");            
                if (eAuthentication == null)
                {
                    _logger.error("No 'authentication' configuration section found");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                oComponent = getComponent(eAuthentication, 
                    (IComponent)_authenticationProfileFactory);
                if (oComponent != null)
                    _authenticationProfileFactory = (IAuthenticationProfileFactory)oComponent;
                
                ((IComponent)_authenticationProfileFactory).start(
                    _configurationManager, eAuthentication);
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'authentication' class isn't an IAuthenticationProfileFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            //Start optional Pre authorization pool factory
            try
            {
                Element ePreAuthorization = _configurationManager.getSection(eConfig, "preauthorization");            
                if (ePreAuthorization == null)
                {
                    _logger.info("No optional 'preauthorization' configuration section found");
                }
                else
                {
                    oComponent = getComponent(ePreAuthorization, 
                        (IComponent)_preAuthorizationFactory);
                    if (oComponent != null)
                        _preAuthorizationFactory = (IAuthorizationFactory)oComponent;
                    
                    ((IComponent)_preAuthorizationFactory).start(
                        _configurationManager, ePreAuthorization);
                }
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'preauthorization' class isn't an IAuthorizationFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            //Start optional post authorization pool factory
            try
            {
                Element ePostAuthorization = _configurationManager.getSection(
                    eConfig, "postauthorization");            
                if (ePostAuthorization == null)
                {
                    _logger.info("No optional 'postauthorization' configuration section found");
                }
                else
                {
                    oComponent = getComponent(ePostAuthorization, 
                        (IComponent)_postAuthorizationFactory);
                    if (oComponent != null)
                        _postAuthorizationFactory = (IAuthorizationFactory)oComponent;
                    
                    ((IComponent)_postAuthorizationFactory).start(
                        _configurationManager, ePostAuthorization);
                }
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'postauthorization' class isn't an IAuthorizationFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
                        
            //Start optional attribute release policy factory
            try
            {
                Element eAttributeRelease = _configurationManager.getSection(eConfig, "attributerelease");            
                if (eAttributeRelease == null)
                {
                    _logger.info("No optional 'attributerelease' configuration section found");
                }
                else
                {
                    oComponent = getComponent(eAttributeRelease, 
                        (IComponent)_attributeReleasePolicyFactory);
                    if (oComponent != null)
                        _attributeReleasePolicyFactory = 
                            (IAttributeReleasePolicyFactory)oComponent;
                    
                    ((IComponent)_attributeReleasePolicyFactory).start(
                        _configurationManager, eAttributeRelease);
                }
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'attributerelease' class isn't an IAttributeReleasePolicyFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            // Start the optional Confederation Manager
            try
            {
                Element eConfederationFactory = _configurationManager.getSection(eConfig, "confederations");            
                if (eConfederationFactory == null) {
                    _logger.info("No 'confederations' configuration section found");
                    _oConfederationFactory = null;
                } else {
                
	                oComponent = getComponent(eConfederationFactory,(IComponent)_oConfederationFactory);
	                if (oComponent != null) {
	                	_oConfederationFactory = (IConfederationFactory)oComponent;
	                    ((IComponent)_oConfederationFactory).start(_configurationManager, eConfederationFactory);
	                }
                }
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'confederations' class isn't an IConfederationFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _server = createServer(eConfig);
            
            //Start User Factory
            try
            {
                Element eUserfactory = _configurationManager.getSection(
                    eConfig, "userfactory");            
                if (eUserfactory == null)
                {
                    _logger.info("No optional 'userfactory' configuration section found");
                }
                else
                {
                    oComponent = getComponent(eUserfactory, (IComponent)_userFactory);
                    if (oComponent != null)
                        _userFactory = (IUserFactory)oComponent;
                    
                    ((IComponent)_userFactory).start(
                        _configurationManager, eUserfactory);
                }
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'userfactory' class isn't an IUserFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            //Start IDP Storage manager
            _idpStorageManager = new IDPStorageManager();
            Element eIDPStorageManager = _configurationManager.getSection(
                eConfig, "idpstorage");   
            _idpStorageManager.start(_configurationManager, eIDPStorageManager);
            
            //Start other components
            for(IComponent listenerComponent : _lComponents)
            {
                //retrieve component configuration section (Optional: may be null)
                //Element name = lower case class name
                Element eComponent = _configurationManager.getSection(
                    eConfig, listenerComponent.getClass().getSimpleName().toLowerCase());
                //Start component
                listenerComponent.start(_configurationManager, eComponent);                
            }
            
            _initialized = true;
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Can't start engine", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Restart all components (Composite method).
     * @param eConfig The root configuration section for this engine.
     * @throws OAException 
     */
    public void restart(Element eConfig) throws OAException
    {
        try
        {
            if (!_initialized)
            {
                _logger.warn("Engine not started yet"); 
                throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
            }
            
            _initialized = false;
            
            //Restart optional Database factory
            try
            {
                Element eStoragefactory = _configurationManager.getSection(
                    eConfig, "storagefactory");            
                if (eStoragefactory == null)
                {
                    _logger.info("No optional 'storagefactory' configuration section found");
                    if (_storageFactory != null)
                        ((IComponent)_storageFactory).stop();
                }
                else
                {
                    IComponent oComponent = getComponent(eStoragefactory, 
                        (IComponent)_storageFactory);                                       
                    if (oComponent != null) //Other factory
                    {
                        //Stop current factory if applicable
                        if (_storageFactory != null)
                            ((IComponent)_storageFactory).stop();
                        //Set new factory
                        _storageFactory = (IDataStorageFactory)oComponent;
                        oComponent.start(_configurationManager, eStoragefactory);
                    }
                    else //Same factory
                        ((IComponent)_storageFactory).restart(eStoragefactory);
                }
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'storagefactory' class isn't an IDataStorageFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            //Restart security manager                    
            Element eCrypto = _configurationManager.getSection(eConfig, "crypto");
            if(eCrypto == null)
            {
                _logger.error("No 'crypto' configuration section found"); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            _cryptoManager.restart(eCrypto);                        
            
            //Restart TGT Factory
            IStorageFactory factory = restartFactory(
                eConfig, "tgtfactory", _tgtFactory);
            try
            {
                _tgtFactory = (ITGTFactory)factory;
            }
            catch(ClassCastException e)
            {
                _logger.error(
                    "Configured TGT factory class isn't of type 'ITGTFactory': " 
                    + factory.getClass().getName(), e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            //Restart session Factory      
            factory = restartFactory(
                eConfig, "sessionfactory", _sessionFactory);
             try
            {
                _sessionFactory = (ISessionFactory)factory;
            }
            catch(ClassCastException e)
            {
                _logger.error(
                    "Configured session factory class isn't of type 'ISessionFactory': " 
                    + factory.getClass().getName(), e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }            
            
            //Restart Attribute gatherer            
            Element eAttributeGatherer = _configurationManager.getSection(
                eConfig, "attributegatherer");
            if(eAttributeGatherer != null)
            {
                if (_attributeGatherer.isEnabled())
                    _attributeGatherer.restart(eAttributeGatherer);
                else
                    _attributeGatherer.start(_configurationManager, eAttributeGatherer);
            }
            else //No attribute gatherer configuration
            {
                _logger.info("No optional 'attributegatherer' configured");
                if(_attributeGatherer.isEnabled())
                {
                    //Previously configured
                    _attributeGatherer.stop();                   
                }   
            }
            
            //Restart Requestor Pool Factory
            try
            {
                Element eRequestorpoolfactory = _configurationManager.getSection(
                    eConfig, "requestorpoolfactory");            
                if (eRequestorpoolfactory == null)
                {
                    _logger.error("No 'requestorpoolfactory' configuration section found");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                IComponent oComponent = getComponent(eRequestorpoolfactory, 
                    (IComponent)_requestorPoolFactory);
                if (oComponent != null)
                {
                    ((IComponent)_requestorPoolFactory).stop();
                    _requestorPoolFactory = (IRequestorPoolFactory)oComponent;
                    oComponent.start(_configurationManager, eRequestorpoolfactory);
                }
                else
                    ((IComponent)_requestorPoolFactory).restart(
                        eRequestorpoolfactory);
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'requestorpoolfactory' class isn't an IRequestorPoolFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
                        
            //Restart authentication profile factory   
            try
            {
                Element eAuthentication = _configurationManager.getSection(eConfig, "authentication");            
                if (eAuthentication == null)
                {
                    _logger.error("No 'authentication' configuration section found");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                IComponent oComponent = getComponent(eAuthentication, 
                    (IComponent)_authenticationProfileFactory);
                if (oComponent != null)
                {
                    ((IComponent)_authenticationProfileFactory).stop();
                    _authenticationProfileFactory = (
                        IAuthenticationProfileFactory)oComponent;
                    oComponent.start(_configurationManager, eAuthentication);
                }
                else
                    ((IComponent)_authenticationProfileFactory).restart(
                        eAuthentication);
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'authentication' class isn't an IAuthenticationProfileFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            //Restart optional Pre authorization pool factory
            try
            {
                Element ePreAuthorization = _configurationManager.getSection(
                    eConfig, "preauthorization");            
                if (ePreAuthorization == null)
                {
                    _logger.info("No optional 'preauthorization' configuration section found");
                    if (_preAuthorizationFactory != null)
                    {
                        ((IComponent)_preAuthorizationFactory).stop();
                        _preAuthorizationFactory = null;
                    }
                }
                else
                {
                    IComponent oComponent = getComponent(ePreAuthorization, 
                        (IComponent)_preAuthorizationFactory);
                    if (oComponent != null)
                    {
                        if(_preAuthorizationFactory != null)
                            ((IComponent)_preAuthorizationFactory).stop();
                        _preAuthorizationFactory = (IAuthorizationFactory)oComponent;
                        oComponent.start(_configurationManager, ePreAuthorization);
                    }
                    else
                        ((IComponent)_preAuthorizationFactory).restart(
                            ePreAuthorization);
                }
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'preauthorization' class isn't an IAuthorizationFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            //Restart optional post authorization pool factory
            try
            {
                Element ePostAuthorization = _configurationManager.getSection(
                    eConfig, "postauthorization");            
                if (ePostAuthorization == null)
                {
                    _logger.info("No optional 'postauthorization' configuration section found");
                    if (_postAuthorizationFactory != null)
                    {
                        ((IComponent)_postAuthorizationFactory).stop();
                        _postAuthorizationFactory = null;
                    }
                }
                else
                {
                    IComponent oComponent = getComponent(ePostAuthorization, 
                        (IComponent)_postAuthorizationFactory);
                    if (oComponent != null)
                    {
                        if (_postAuthorizationFactory != null)
                            ((IComponent)_postAuthorizationFactory).stop();
                        _postAuthorizationFactory = (IAuthorizationFactory)oComponent;
                        oComponent.start(_configurationManager, ePostAuthorization);
                    }
                    else
                        ((IComponent)_postAuthorizationFactory).restart(
                            ePostAuthorization);
                }
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'postauthorization' class isn't an IAuthorizationFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            //Restart optional attribute release policy factory
            try
            {
                Element eAttributeRelease = _configurationManager.getSection(eConfig, "attributerelease");            
                if (eAttributeRelease == null)
                {
                    _logger.info("No optional 'attributerelease' configuration section found");
                    if (_attributeReleasePolicyFactory != null)
                    {
                        ((IComponent)_attributeReleasePolicyFactory).stop();
                        _attributeReleasePolicyFactory = null;
                    }
                }
                else
                {
                    IComponent oComponent = getComponent(eAttributeRelease, 
                        (IComponent)_attributeReleasePolicyFactory);
                    if (oComponent != null)
                    {
                        if (_attributeReleasePolicyFactory != null)
                            ((IComponent)_attributeReleasePolicyFactory).stop();
                        _attributeReleasePolicyFactory = (
                            IAttributeReleasePolicyFactory)oComponent;
                        oComponent.start(_configurationManager, eAttributeRelease);
                    }
                    else
                        ((IComponent)_attributeReleasePolicyFactory).restart(
                            eAttributeRelease);
                }
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'attributerelease' class isn't an IAttributeReleasePolicyFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }           
            
            //Restart optional confederation factory
            try
            {
                Element eConfederation = _configurationManager.getSection(eConfig, "confederations");            
                if (eConfederation == null) {
                    _logger.info("No optional 'confederations' configuration section found");
                    if (_oConfederationFactory != null) {
                        ((IComponent)_oConfederationFactory).stop();
                        _oConfederationFactory = null;
                    }
                } else {
                    IComponent oComponent = getComponent(eConfederation, 
                        (IComponent)_oConfederationFactory);
                    if (oComponent != null) {
                        if (_oConfederationFactory != null)
                            ((IComponent)_oConfederationFactory).stop();
                        _oConfederationFactory = (IConfederationFactory)oComponent;
                        oComponent.start(_configurationManager, eConfederation);
                    } else {
                    	((IComponent)_oConfederationFactory).restart(eConfederation);
                    }
                }
            } catch(ClassCastException e) {
                _logger.error("Configured 'confederations' class isn't an IConfederationFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            _server = createServer(eConfig);
            
            //Restart optional user factory
            try
            {
                Element eUserfactory = _configurationManager.getSection(
                    eConfig, "userfactory");            
                if (eUserfactory == null)
                {
                    _logger.info("No optional 'userfactory' configuration section found");
                    if (_userFactory != null)
                        ((IComponent)_userFactory).stop();
                }
                else
                {
                    IComponent oComponent = getComponent(eUserfactory, 
                        (IComponent)_userFactory);                                       
                    if (oComponent != null) //Other factory
                    {
                        //Stop current user factory if applicable
                        if (_userFactory != null)
                            ((IComponent)_userFactory).stop();
                        //Set new user factory
                        _userFactory = (IUserFactory)oComponent;
                        oComponent.start(_configurationManager, eUserfactory);
                    }
                    else //Same factory
                        ((IComponent)_userFactory).restart(eUserfactory);
                }
            }
            catch(ClassCastException e)
            {
                _logger.error("Configured 'userfactory' class isn't an IUserFactory", e); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            //Restart optional IDP storage manager
            Element eIDPStorageManager = _configurationManager.getSection(
                eConfig, "idpstorage");            
            _idpStorageManager.restart(eIDPStorageManager);
            
            //Resestart other components
            for(IComponent listnerComponent : _lComponents)
            {
                //retrieve component configuration section
                //Element name = lowercase class name
                Element eComponent = _configurationManager.getSection(
                    eConfig, listnerComponent.getClass().getSimpleName().toLowerCase());          
                //Restart component
                listnerComponent.restart(eComponent);                
            }
            _initialized = true;
        }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Can't restart engine", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    /**
     * Stop all components (Composite method).
     */
    public void stop()
    {
        _initialized = false;
        //Security
        if(_cryptoManager != null)
            _cryptoManager.stop();
        //TGT manager
        if(_tgtFactory!= null)
            _tgtFactory.stop();
        //Session manager
        if(_sessionFactory!= null)
            _sessionFactory.stop();
        //Attribute gatherer
        if(_attributeGatherer != null)
            _attributeGatherer.stop();
        //Factories
        if(_requestorPoolFactory!= null)
            ((IComponent)_requestorPoolFactory).stop();       
        if(_userFactory!= null)
            ((IComponent)_userFactory).stop();
        if(_authenticationProfileFactory!= null)
            ((IComponent) _authenticationProfileFactory).stop();   
        if(_preAuthorizationFactory!= null)
            ((IComponent) _preAuthorizationFactory).stop();
        if(_postAuthorizationFactory!= null)
            ((IComponent)_postAuthorizationFactory).stop();
        if(_attributeReleasePolicyFactory!= null)
            ((IComponent)_attributeReleasePolicyFactory).stop(); 
        if (_storageFactory != null)
            ((IComponent)_storageFactory).stop(); 
        if (_idpStorageManager != null)
            _idpStorageManager.stop();
        if (_oConfederationFactory!=null)
        	((IComponent)_oConfederationFactory).stop();
        //Stop other components
        for(IComponent listnerComponent : _lComponents)
        {
            listnerComponent.stop();                
        }
    }
    
    //Create Engine, _logger and _configurationManager.
    private Engine()
    {
        _initialized = false;
        _logger = LogFactory.getLog(Engine.class);
        _lComponents = new Vector<IComponent>();
        //Create standard managers
        _cryptoManager = new CryptoManager(); 
        _attributeGatherer = new AttributeGatherer();
    }
    
	//Restart a storage manager
    private IStorageFactory restartFactory(Element eConfig, String sFactoryName, IStorageFactory oFactory) throws OAException
    {
        //Restart TGT Factory                         
        Element eTGTConfig = _configurationManager.getSection(
            eConfig, sFactoryName);            
        if (eTGTConfig == null)
        {                  
            _logger.error("TGT configuration section not found: " + sFactoryName);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);  
        }
        oFactory.stop();
        IStorageFactory factory = 
            AbstractStorageFactory.createInstance(
                _configurationManager, eTGTConfig, 
                _cryptoManager.getSecureRandom());
        return factory;
    }

    /**
     * Creates an instance of the Component.
     * 
     * Returns the new <code>IComponent</code> implementation or 
     * <code>null</code> if the new component implementation is equal to the 
     * current component.
     *
     * @param eConfig the base configuration section where the component 
     *  config can be found
     * @param oOrigionalComponent The origional component
     * @return the component as IComponent
     * @throws OAException if component can't be created
     */
    private IComponent getComponent(Element eConfig, IComponent oOrigionalComponent) 
        throws OAException
    {    
        IComponent component = null;
        try
        {
            String sClass = _configurationManager.getParam(eConfig, "class");
            if (sClass == null)
            {
                _logger.error(eConfig.getNodeName()
                    + " implementation class parameter not found");
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            Class oClass = null;
            try
            {
                oClass = Class.forName(sClass);
            }
            catch (ClassNotFoundException e)
            {
                _logger.error("Configured class doesn't exist: " + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            
            if (oOrigionalComponent != null 
                && oClass.equals(oOrigionalComponent.getClass()))
                return null;

            try
            {
                component = (IComponent)oClass.newInstance();
            }
            catch (InstantiationException e)
            {
                _logger.error("Can't create an instance of the configured class: " 
                    + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            catch (IllegalAccessException e)
            {
                _logger.error("Configured class can't be accessed: " 
                    + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            catch (ClassCastException e)
            {
                _logger.error("Configured class isn't of type 'IComponent': " 
                    + sClass, e);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        catch(OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during the component retrieval: " 
                + eConfig.getNodeName(), e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return component;
    }
    
    //Create server configuration object.
    private Server createServer(Element eConfig) throws OAException
    {
        Server oServer = null;
        try
        {
            Element eServer = _configurationManager.getSection(eConfig, "server");
            if(eServer == null)
            {
                _logger.error("No 'server' configuration section found"); 
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
            oServer = new Server(_configurationManager, eServer);
            
            String sPreAuthProfile = oServer.getPreAuthorizationProfileID();
            if (sPreAuthProfile != null)
            {
                if (_preAuthorizationFactory == null || !_preAuthorizationFactory.isEnabled())
                {
                    _logger.error("There is a pre authorization profile configured for this server, but the pre authorization factory is disabled or not configured"); 
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                AuthorizationProfile oAuthorizationProfile = 
                    _preAuthorizationFactory.getProfile(sPreAuthProfile);
                if (oAuthorizationProfile == null)
                {
                    _logger.error("The configured pre authorization profile for this server doesn't exist"); 
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            String sPostAuthProfile = oServer.getPostAuthorizationProfileID();
            if (sPostAuthProfile != null)
            {
                if (_postAuthorizationFactory == null || !_postAuthorizationFactory.isEnabled())
                {
                    _logger.error("There is a post authorization profile configured for this server, but the post authorization factory is disabled or not configured"); 
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
                
                AuthorizationProfile oAuthorizationProfile = 
                    _postAuthorizationFactory.getProfile(sPostAuthProfile);
                if (oAuthorizationProfile == null)
                {
                    _logger.error("The configured post authorization profile for this server doesn't exist"); 
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
        }
        catch(OAException e)
        {
            throw e;
        }
        catch(Exception e)
        {
            _logger.fatal("Internal error during creation of the Server object", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        
        return oServer;
    }
}