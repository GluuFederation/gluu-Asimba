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
package com.alfaariss.oa.sso;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.asimba.utility.web.URLPathContext;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.UserException;
import com.alfaariss.oa.api.IComponent;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.attribute.ITGTAttributes;
import com.alfaariss.oa.api.authentication.IAuthenticationContexts;
import com.alfaariss.oa.api.authentication.IAuthenticationMethod;
import com.alfaariss.oa.api.authentication.IAuthenticationProfile;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.persistence.PersistenceException;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.attribute.UserAttributes;
import com.alfaariss.oa.engine.core.attribute.gather.AttributeGatherer;
import com.alfaariss.oa.engine.core.attribute.release.IAttributeReleasePolicy;
import com.alfaariss.oa.engine.core.attribute.release.factory.IAttributeReleasePolicyFactory;
import com.alfaariss.oa.engine.core.authentication.AuthenticationContexts;
import com.alfaariss.oa.engine.core.authentication.AuthenticationException;
import com.alfaariss.oa.engine.core.authentication.AuthenticationProfile;
import com.alfaariss.oa.engine.core.authentication.factory.IAuthenticationProfileFactory;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
import com.alfaariss.oa.engine.core.session.factory.ISessionFactory;
import com.alfaariss.oa.engine.core.tgt.factory.ITGTFactory;
import com.alfaariss.oa.util.session.ProxyAttributes;

/**
 * Authentication and SSO Service.
 * 
 * Contains basic functionality that can be called from an SSO system 
 * e.g. WebSSO.
 *  
 * @author mdobrinic 
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class SSOService implements IComponent
{    
	/** 
	 * TGT Attribute name containing the Map<String, String> with the alias->idp.id mapping 
	 * of remote IDPs that were used to authenticate the user in this SSO session 
	 */
	public static final String TGT_ATTR_SHADOWED_IDPS = "shadowed_idps";
	
    private boolean _bSingleSignOn;          
    private Log _systemLogger;
    private IConfigurationManager _configurationManager;
    private ISessionFactory<?> _sessionFactory;
    private ITGTFactory<?> _tgtFactory;
    private IRequestorPoolFactory _requestorPoolFactory;
    private IAuthenticationProfileFactory _authenticationProfileFactory;
    private AttributeGatherer _attributeGatherer;
    private IAttributeReleasePolicyFactory _attributeReleasePolicyFactory;
    
    /**
     * Create a new SSO Service.
     */
    public SSOService()
    {
        _systemLogger = LogFactory.getLog(SSOService.class);
        _bSingleSignOn = true;    
    }

    /**
     * Start the SSO Service.
     * @see IComponent#start(IConfigurationManager, org.w3c.dom.Element)
     */
    public void start(IConfigurationManager oConfigurationManager, 
        Element eConfig) throws OAException
    {              
        if(oConfigurationManager == null)
            throw new IllegalArgumentException(
                "Supplied ConfigurationManager is empty");
        
        Engine engine = Engine.getInstance();
        _configurationManager = oConfigurationManager;
        _sessionFactory = engine.getSessionFactory();
        _tgtFactory = engine.getTGTFactory();
        _requestorPoolFactory = engine.getRequestorPoolFactory();
        _authenticationProfileFactory = 
            engine.getAuthenticationProfileFactory();
        _attributeGatherer = engine.getAttributeGatherer();
        _attributeReleasePolicyFactory = 
            engine.getAttributeReleasePolicyFactory();
        
        //SSO configuration
        readDefaultConfiguration(eConfig); 
        
        _systemLogger.info("SSO Service started");    
    }

    /**
     * Restart the SSO Service.
     * @see com.alfaariss.oa.api.IComponent#restart(org.w3c.dom.Element)
     */
    public void restart(Element eConfig) throws OAException
    {
        synchronized(this)
        {
            //Get new components
            Engine engine = Engine.getInstance();
            _sessionFactory = engine.getSessionFactory();
            _tgtFactory = engine.getTGTFactory();
            _requestorPoolFactory = engine.getRequestorPoolFactory();
            _authenticationProfileFactory = 
                engine.getAuthenticationProfileFactory();       
            
            //SSO
            readDefaultConfiguration(eConfig); 
            _systemLogger.info("SSO Service restarted");
        }        
    }
    
    /**
     * Stop the SSO Service.
     * @see com.alfaariss.oa.api.IComponent#stop()
     */
    public void stop()
    {    
        _systemLogger.info("SSO Service stopped");        
    }

    /**
     * Retrieve an authentication session.
     * @param sId The session ID.
     * @return The session, or null if not found.
     * @throws SSOException If retrieval fails.
     */
    public ISession getSession(String sId) throws SSOException
    {
        try
        {
            return _sessionFactory.retrieve(sId);
        }
        catch (OAException e)
        {
            _systemLogger.warn("Could not retrieve session",e);
            //wrap exception
            throw new SSOException(e.getCode(), e);
        }       
    }
    
    /**
     * Retrieve TGT.
     * @param sTGTId The TGT ID.
     * @return The TGT, or null if not found.
     * @throws SSOException If retrieval fails.
     */
    public ITGT getTGT(String sTGTId) throws SSOException
    {
        try
        {
            return _tgtFactory.retrieve(sTGTId);  
        }
        catch (OAException e)
        {
            _systemLogger.warn("Could not retrieve TGT",e);
            //wrap exception
            throw new SSOException(e.getCode(), e);
        }  
    }
    
    /**
     * Retrieve requestor pool for this authentication session.
     * @param oSession The authentication session
     * @return The requestor pool
     * @throws SSOException if retrieval fails
     */
    public RequestorPool getRequestorPool(ISession oSession) throws SSOException
    {
        try
        {
            return _requestorPoolFactory.getRequestorPool(
                oSession.getRequestorId());
        }
        catch (OAException e)
        {
            _systemLogger.warn("Could not retrieve requestor pool",e);
            //wrap exception
            throw new SSOException(e.getCode(), e);
        }  
    }
    
    /**
     * Retrieve requestor for this authentication session.
     * @param sID The requestor id
     * @return The requestor
     * @throws SSOException if retrieval fails
     * @since 1.0
     */
    public IRequestor getRequestor(String sID) throws SSOException
    {
        try
        {
            return _requestorPoolFactory.getRequestor(sID);
        }
        catch (OAException e)
        {
            _systemLogger.warn("Could not retrieve requestor: " + sID, e);
            //wrap exception
            throw new SSOException(e.getCode());
        }  
    }
    
    /**
     * Retrieve requestor for this authentication session.
     * @param oSession The authentication session
     * @return The requestor
     * @throws SSOException if retrieval fails
     */
    public IRequestor getRequestor(ISession oSession) throws SSOException
    {
        try
        {
            return _requestorPoolFactory.getRequestor(
                oSession.getRequestorId());
        }
        catch (OAException e)
        {
            _systemLogger.warn("Could not retrieve requestor ",e);
            //wrap exception
            throw new SSOException(e.getCode(), e);
        }  
    }

    /**
     * Retrieve all required authentication profiles for the supplied 
     * requestor pool.
     * 
     * @param oRequestorPool the requestor pool
     * @return List&lt;AuthenticationProfile&gt; containing the profiles 
     * @throws SSOException If retrieval fails
     */
    public List<IAuthenticationProfile> getAllAuthNProfiles(
        RequestorPool oRequestorPool) throws SSOException
    {     
        try
        {
            List<IAuthenticationProfile> listProfiles = new Vector<IAuthenticationProfile>();
            for (String sProfile: oRequestorPool.getAuthenticationProfileIDs())
            {
                IAuthenticationProfile oAuthNProfile = 
                    _authenticationProfileFactory.getProfile(sProfile);
                if(oAuthNProfile == null)
                {
                    _systemLogger.warn(
                        "AuthN Profile not found: " + sProfile);
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                if (oAuthNProfile.isEnabled())
                    listProfiles.add(oAuthNProfile);
            }
            return listProfiles;    
        }
        catch (OAException e)
        {
            _systemLogger.warn("Could not retrieve AuthN profiles",e);
            //wrap exception
            throw new SSOException(e.getCode(), e);
        }  
    }
    
    /**
     * Returns the authentication profile id.
     * @param sID The ID of the Authentication Profile
     * @return the specified IAuthenticationProfile
     * @throws SSOException If authentication profile could not be retrieved.
     * @since 1.0
     */
    public IAuthenticationProfile getAuthNProfile(String sID) 
        throws SSOException
    {
        IAuthenticationProfile authenticationProfile = null;
        try
        {
            authenticationProfile = 
                _authenticationProfileFactory.getProfile(sID);
        }
        catch (AuthenticationException e)
        {
            _systemLogger.warn("Could not retrieve AuthN profile: " + sID, e);
            //wrap exception
            throw new SSOException(e.getCode());
        }
        return authenticationProfile;
    }
    
    /**
     * Retrieve selected profile.
     *
     * @param oSession The authentication session.
     * @param sSelectedProfile The profile chosen by user
     * @param bShowAllways Is the selection mandatory? 
     * @return Selected AuthenticationProfile or <code>null</code>
     * @throws UserException If selection fails
     * @throws SSOException If selection fails, due to internal error
     */
    public IAuthenticationProfile getSelectedAuthNProfile(ISession oSession, 
        String sSelectedProfile, boolean bShowAllways) 
        throws UserException, SSOException
    {
        IAuthenticationProfile oSelectedProfile = null;
        try
        {
            if (sSelectedProfile != null && oSession.getState() != SessionState.AUTHN_NOT_SUPPORTED)
            {
                List<IAuthenticationProfile> listRequiredProfiles = oSession.getAuthNProfiles();
                oSelectedProfile = _authenticationProfileFactory.getProfile(sSelectedProfile);
                if (oSelectedProfile == null)
                {
                    _systemLogger.debug("Selected profile is not available: " + sSelectedProfile);
                    throw new UserException(UserEvent.AUTHN_PROFILE_NOT_AVAILABLE);
                }
                if (!oSelectedProfile.isEnabled())
                {
                    _systemLogger.debug("Selected profile is disabled: " + sSelectedProfile);
                    throw new UserException(UserEvent.AUTHN_PROFILE_DISABLED);
                }
                
                if (!listRequiredProfiles.contains(oSelectedProfile))
                {
                    _systemLogger.debug("Selected profile is not required: " + sSelectedProfile);
                    throw new UserException(UserEvent.AUTHN_PROFILE_INVALID);
                }
                oSession.setSelectedAuthNProfile(oSelectedProfile);
            }
            else 
            {
                List<IAuthenticationProfile> listFilteredProfiles = filterRegisteredProfiles(oSession);
                oSession.setAuthNProfiles(listFilteredProfiles);
                
                if (oSession.getAuthNProfiles().size() == 1 && !bShowAllways)
                {
                    oSelectedProfile = oSession.getAuthNProfiles().get(0);
                    oSession.setSelectedAuthNProfile(oSelectedProfile);                
                }
            }
        }
        catch (UserException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _systemLogger.error("Internal error during retrieval the selected profile: " 
                + sSelectedProfile, e); 
            throw new SSOException(SystemErrors.ERROR_INTERNAL);
        }
        
        return oSelectedProfile;
    }

    /**
     * Handle the SSO process.
     * 
     * Create or update a TGT, add all new methods to it, and persist TGT.
     * @param oSession The authentication session.
     * @return The created or updated TGT.
     * @throws SSOException If creation fails.
     */
    public ITGT handleSingleSignon(ISession oSession) throws SSOException
    {        
        ITGT oTgt = null;       
        if(_bSingleSignOn) //SSO enabled 
        {
            try
            {
                IAuthenticationProfile selectedAuthNProfile = oSession.getSelectedAuthNProfile();
                //create or update TGT
                String sTGT = oSession.getTGTId();
                
                if(sTGT == null) //New TGT
                {
                    oTgt = _tgtFactory.createTGT(oSession.getUser());
                }
                else //Update TGT
                {
                    oTgt = _tgtFactory.retrieve(sTGT);
                    if (oTgt == null)
                    {
                        _systemLogger.warn("Could not retrieve TGT with id: " + sTGT);
                        throw new SSOException(SystemErrors.ERROR_INTERNAL);
                    }
                }
                
                //Add all new methods to TGT
                List<IAuthenticationMethod> newMethods = selectedAuthNProfile.getAuthenticationMethods();
                IAuthenticationProfile tgtProfile = oTgt.getAuthenticationProfile(); 
                for(IAuthenticationMethod method : newMethods)
                {
                   //DD Do not add duplicate authN methods in TGT profile
                   if(!tgtProfile.containsMethod(method))
                   {
                	   // See whether there exists a method-specific disable sso override
                	   if (! disableSSOForMethod(oSession, method.getID())) {
                		   _systemLogger.debug("Adding "+method.getID()+" to TGT SSO methods");
                		   tgtProfile.addAuthenticationMethod(method);
                		   
                		   registerAuthenticationContext(oTgt, oSession, method);
                	   } else {
                		   _systemLogger.debug("Disabling SSO for method "+method.getID());
                	   }
                   }
                        
                }
                oTgt.setAuthenticationProfile(tgtProfile);  
                
                //Add current profile
                List<String> tgtProfileIds = oTgt.getAuthNProfileIDs();
                if (!tgtProfileIds.contains(selectedAuthNProfile.getID()))
                {
                    //DD Do not add duplicate AuthN profile id in TGT
                    oTgt.addAuthNProfileID(selectedAuthNProfile.getID());
                }
                
                //update TGT with requestor id
                addRequestorID(oTgt, oSession.getRequestorId());
                
                //Keep track of a Shadowed IDP.id => real IDP.id mapping from the Session context
                processShadowIDP(oTgt, oSession);
                
                //Persist TGT
                oTgt.persist();
                
                oSession.setTGTId(oTgt.getId());
            }
            catch(SSOException e)
            {
                throw e;
            }
            catch(OAException e)
            {
                _systemLogger.warn("Could not update TGT", e);
                //Wrap exception
                throw new SSOException(e.getCode(), e);
            }
            catch (Exception e)
            {
                _systemLogger.error("Internal error during sso handling", e);
                throw new SSOException(SystemErrors.ERROR_INTERNAL);
            }
        }
        return oTgt;
    }

    /**
     * Check the SSO session that might be present.
     * 
     * Check the SSO session existence, expiration, and sufficiency.
     * @param oSession The authentication session.
     * @param sTGTId The TGT ID.
     * @param oRequestorPool The requestor pool.
     * @return <code>true</code> if TGT if sufficient.
     * @throws SSOException If retrieval or persisting TGT fails
     * @throws UserException If TGT user is invalid.
     */
    public boolean checkSingleSignon(ISession oSession, String sTGTId,
        RequestorPool oRequestorPool) 
        throws SSOException, UserException
    {
        boolean bTGTSufficient = false;
        
        if(!_bSingleSignOn) //SSO enabled
        {
            _systemLogger.debug("SSO disabled");
        }
        else
        {
            if (sTGTId == null) // Check TGT Cookie
            {
                _systemLogger.debug("No valid TGT Cookie found");
            }
            else
            {
                // TGT Cookie found
                try
                {
                    //Retrieve TGT
                    ITGT oTgt = _tgtFactory.retrieve(sTGTId);
                    
                    //Check tgt existence and expiration
                    if(oTgt == null || oTgt.isExpired()) //TGT valid
                    {   
                        _systemLogger.debug("TGT expired and ignored");
                    }
                    else
                    {
                        //Check if a previous request was done for an other user-id
                        String forcedUserID = oSession.getForcedUserID();
                        IUser tgtUser = oTgt.getUser();
                        if(forcedUserID != null && tgtUser != null && 
                            !forcedUserID.equalsIgnoreCase(tgtUser.getID()))
                            //Forced user does not match TGT user
                        {
                            //Remove TGT itself
                            removeTGT(oTgt);
                            _systemLogger.warn("User in TGT and forced user do not correspond");
                            
                            throw new UserException(UserEvent.TGT_USER_INVALID);
                        } 
                                             
                        //Set previous TGT id and user in session  
                        oSession.setTGTId(sTGTId);
                        oSession.setUser(oTgt.getUser());
                        //check ForcedAuthenticate
                        if(oSession.isForcedAuthentication()) //Forced authenticate
                        {  
                            _systemLogger.debug("Forced authentication");
                        }
                        else
                        {
                            //Check if TGT profile is sufficient 
                            IAuthenticationProfile tgtProfile = oTgt.getAuthenticationProfile();                   
                            List<String> oRequiredAuthenticationProfileIDs = oRequestorPool.getAuthenticationProfileIDs();                           
                            Iterator<String> iter = oRequiredAuthenticationProfileIDs.iterator();
                            while(iter.hasNext() && !bTGTSufficient)
                            {
                               //Retrieve next profile
                               AuthenticationProfile requiredProfile = 
                                   _authenticationProfileFactory.getProfile(iter.next());
                               if(requiredProfile != null && requiredProfile.isEnabled())
                               {                                  
                                   bTGTSufficient = 
                                       tgtProfile.compareTo(requiredProfile) >= 0;
                               }
                            }
                            
                            // bTGTSufficient represents whether the executed authentication methods of a TGT
                            // are good enough for the profiles that are allowed for the requesting Requestor
                            
                            // If this is the case, check if the Requestor has explicitly requested one or more
                            // specific AuthenticationProfiles, and if so, whether these are already performed
                            if (bTGTSufficient) {
	                            @SuppressWarnings("unchecked")
	                    		List<String> requestedAuthnProfiles = (List<String>) 
	                            		oSession.getAttributes().get(ProxyAttributes.class, ProxyAttributes.REQUESTED_AUTHNPROFILES);
	                            if (requestedAuthnProfiles != null) {
	                            	iter = requestedAuthnProfiles.iterator();
	                            	boolean tgtProfileSatisfiesRequestedProfile = false;
	                            	while(iter.hasNext() && !tgtProfileSatisfiesRequestedProfile) {
	                            		AuthenticationProfile requestedAuthnProfile = 
	                                            _authenticationProfileFactory.getProfile(iter.next());
	                            		if (requestedAuthnProfile != null) {
	                            			tgtProfileSatisfiesRequestedProfile =
	                            					tgtProfile.compareTo(requestedAuthnProfile) >= 0;
	                            					
	                            			_systemLogger.debug("tgtProfile ("+tgtProfile.getAuthenticationMethods().toString()+") "+
	                            					(tgtProfileSatisfiesRequestedProfile ? "DOES" : "does NOT")+
	                            					" satisfy authentication profile '"+
	                            					requestedAuthnProfile.getID()+
	                            					"' ("+requestedAuthnProfile.getAuthenticationMethods().toString() + ")");
	                            		}
	                            	}
	                            	if (!tgtProfileSatisfiesRequestedProfile) {
	                            		_systemLogger.info("Do not resume SSO, as Requested AuthenticationProfile requires "+
	                            				"extra authentication methods to be performed.");
	                            		bTGTSufficient = false;
	                            	} else {
	                            		_systemLogger.info("Allow SSO, as TGT satisfies Requested AuthenticationProfile.");
	                            	}
	                            }
                            }
                        }  
                        
                        if (bTGTSufficient)
                        {
                        	// Is the request for a shadowed IDP, then see if this IDP was
                        	// used before to authenticate the user. If not, do not resume session, but
                        	// if so, set the shadowed IDP.id in the session
                        	if (! matchShadowIDP(oTgt, oSession)) {

                        		//Remove TGT itself
                                _systemLogger.warn("IDP in TGT and IDP-alias do not correspond; do not resume SSO session.");
                                
                                bTGTSufficient = false;
                        	}
                        	
                        }
                        
                        if (bTGTSufficient)
                        {//update TGT with requestor id
                            addRequestorID(oTgt, oSession.getRequestorId());
                            
                            // handle ShadowIDP feature
                            
                            oTgt.persist();
                        }
                    }
                }
                catch(SSOException e)
                {
                    throw e;
                }
                catch(OAException e)
                {
                    _systemLogger.warn("Could not retrieve or update TGT", e);
                    //Wrap exception
                    throw new SSOException(e.getCode());
                }  
                
            }
        }
        
        return bTGTSufficient;
    }
    
    /**
     * Remove the TGT. 
     * @param oTgt The TGT to be removed.
     * @throws SSOException If TGT persistance fails.
     */
    public void removeTGT(ITGT oTgt) throws SSOException
    {
        //Remove TGT        
        oTgt.expire();
        try
        {
            oTgt.persist();
        }
        catch (PersistenceException e)
        {
            _systemLogger.warn("Could not remove TGT", e);
            //Wrap exception
            throw new SSOException(e.getCode(), e);
        }
    }
    
    /**
     * Gathers attributes to the user object in the supplied session.
     * 
     * @param oSession
     * @throws OAException
     * @since 1.4
     */
    public void gatherAttributes(ISession oSession) throws OAException
    {
        if (_attributeGatherer != null && 
            _attributeGatherer.isEnabled())
        {
            IUser oUser = oSession.getUser();
            if (oUser != null)
                _attributeGatherer.process(oUser.getID(), oUser.getAttributes());
        }
    }
    
    /**
     * Applies the attribute release policy over the userattributes available 
     * in the session.
     *  
     * @param session The authentication session.
     * @param sAttributeReleasePolicyID The release policy to be applied.
     * @throws OAException If an internal error occurs.
     * @since 1.4
     */
    public void performAttributeReleasePolicy(ISession session, 
        String sAttributeReleasePolicyID) throws OAException
    {
        try
        {
            IAttributes oReleaseAttributes = new UserAttributes();
            
            if (_attributeReleasePolicyFactory != null 
                && _attributeReleasePolicyFactory.isEnabled()
                && sAttributeReleasePolicyID != null)
            {
                IAttributeReleasePolicy oAttributeReleasePolicy = 
                    _attributeReleasePolicyFactory.getPolicy(sAttributeReleasePolicyID);
                if (oAttributeReleasePolicy != null 
                    && oAttributeReleasePolicy.isEnabled())
                {
                    _systemLogger.debug("applying attribute releasepolicy: " + sAttributeReleasePolicyID);
                    oReleaseAttributes = 
                        oAttributeReleasePolicy.apply(session.getUser().getAttributes());
                    
                    session.getUser().setAttributes(oReleaseAttributes);
                }
            }
            
            //DD empty attributes object so only the attributes were the release policy is applied are available
            IAttributes userAttributes = session.getUser().getAttributes();
            Enumeration enumAttributes = userAttributes.getNames();
            while (enumAttributes.hasMoreElements())
            {
                userAttributes.remove((String)enumAttributes.nextElement());
            }
            
            session.getUser().setAttributes(oReleaseAttributes);
        }
        catch(OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _systemLogger.fatal("Internal error during applying the attribute release policy", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    //Read standard configuration    
    private void readDefaultConfiguration(Element eConfig) throws OAException
    {
        assert eConfig != null : "Supplied config == null";
        
        //SSO
        _bSingleSignOn = true;
        String sSingleSignOn = _configurationManager.getParam(eConfig, "single_sign_on");
        if (sSingleSignOn != null)
        {
            if("false".equalsIgnoreCase(sSingleSignOn))
                _bSingleSignOn = false;
            else if (!"true".equalsIgnoreCase(sSingleSignOn))
            {
                _systemLogger.error("Invalid value for 'single_sign_on' item found in configuration: " 
                    + sSingleSignOn);
                throw new OAException(SystemErrors.ERROR_CONFIG_READ);
            }
        }
        
        _systemLogger.info("SSO enabled: " + _bSingleSignOn);
    }

    private List<IAuthenticationProfile> filterRegisteredProfiles(ISession oSession)
    {        
        List<IAuthenticationProfile> listFilteredProfiles = new Vector<IAuthenticationProfile>();
        
        IUser oUser = oSession.getUser();
        if (oUser != null)
        {
            //AuthN Fallback: filter authN profiles with not registered methods if a user exists in session
            for (IAuthenticationProfile oProfile: oSession.getAuthNProfiles())
            {
                boolean isRegistered = true;
                for(IAuthenticationMethod oMethod : oProfile.getAuthenticationMethods())
                {
                    if(!oUser.isAuthenticationRegistered(oMethod.getID()))
                    {
                        isRegistered = false;
                        break;//stop looping, check finished
                    }
                }
                
                if (isRegistered)
                    listFilteredProfiles.add(oProfile);
            }
            // At this point, listFilteredProfiles only contains the authentication profiles that contain all the 
            // authentication methods that are registered for the authenticated user
        }
        else 
        {
        	// Allow all profiles as set the session, if there was no user authenticated
        	listFilteredProfiles = oSession.getAuthNProfiles();
        }
        
        // Now apply requested authnprofiles filtering, when applicable 
        // Filtering here means: only allow profiles from requestedAuthnProfiles
        @SuppressWarnings("unchecked")
		List<String> requestedAuthnProfiles = (List<String>) 
        		oSession.getAttributes().get(ProxyAttributes.class, ProxyAttributes.REQUESTED_AUTHNPROFILES);
        if (requestedAuthnProfiles != null) {
        	IAuthenticationProfile authnProfile;
        	Iterator<IAuthenticationProfile> authnProfileIterator = listFilteredProfiles.iterator();
        	while (authnProfileIterator.hasNext()) {
        		authnProfile = authnProfileIterator.next();
        		
            	if (! requestedAuthnProfiles.contains(authnProfile.getID())) {
            		authnProfileIterator.remove();
            		_systemLogger.info("Removing "+authnProfile.getID()+" from allowed authnprofiles for the user: "+
            				"doesn't match the requested authn profiles");
            		
            	}
        	}
        }
        
        return listFilteredProfiles;
    }
    
    //add requestor id to the end of the list
    private void addRequestorID(ITGT tgt, String requestorID) 
    {
        List<String> listRequestorIDs = tgt.getRequestorIDs();
        if (!listRequestorIDs.isEmpty() && listRequestorIDs.contains(requestorID))
            tgt.removeRequestorID(requestorID);
        
        //add to end of list
        tgt.addRequestorID(requestorID);
    }
    
    
    /**
     * Find out whether SSO should be disabled for this performed method. Decision
     * is based on a Session attribute 
     * @param oSession
     * @param sMethodId
     * @return
     */
    protected boolean disableSSOForMethod(ISession oSession, String sMethodId) {
    	ISessionAttributes oAttributes = oSession.getAttributes();
    	String sSessionKey = sMethodId + "." + "disable_sso";
    	if (oAttributes.contains(SSOService.class, sSessionKey)) {
    		String sSessionValue = (String) oAttributes.get(SSOService.class, sSessionKey);
    		if ("true".equalsIgnoreCase(sSessionValue)) {
    			return true;
    		}
    	}
    	
    	return false;
    }
    
    
    /**
     * Ensure that when a Shadowed IDP was used in Remote Authentication, that the alias->IDP.id
     * is kept in a TGT attribute, so to be able to make the same mapping later again when an SSO-session
     * is resumed.
     *   
     * @param oTGT TGT to add the alias->IDP.id mapping to
     * @param oSession Session where the IDP.id can be taken from
     */
    protected void processShadowIDP(ITGT oTGT, ISession oSession)
    {
    	ISessionAttributes oAttributes = oSession.getAttributes();
    	String sShadowedIDPId = (String) 
    			oAttributes.get(ProxyAttributes.class, ProxyAttributes.PROXY_SHADOWED_IDPID);
    	
    	if (sShadowedIDPId != null) {
    		URLPathContext oURLPathContext = (URLPathContext) 
    				oAttributes.get(ProxyAttributes.class, ProxyAttributes.PROXY_URLPATH_CONTEXT);
    		
    		String sIDPAlias = null;
    		if (oURLPathContext != null) sIDPAlias = oURLPathContext.getParams().get("i"); 
    		
    		// Integrity check:
    		if (sIDPAlias == null) {
    			_systemLogger.warn("Found '"+ProxyAttributes.PROXY_SHADOWED_IDPID+"' in session but there was no '"+
    					ProxyAttributes.PROXY_URLPATH_CONTEXT+"' in session or no 'i'-value in URLPathContext; ignoring.");
    			return;
    		}

    		// Add the alias->idp.id to the map:
    		ITGTAttributes oTGTAttributes = oTGT.getAttributes();
    		
    		@SuppressWarnings("unchecked")
			Map<String, String> mShadowedIDPs = (Map<String, String>) 
    				oTGTAttributes.get(SSOService.class, TGT_ATTR_SHADOWED_IDPS);
    		
    		if (mShadowedIDPs == null) mShadowedIDPs = new HashMap<String, String>();
    		
    		mShadowedIDPs.put(sIDPAlias, sShadowedIDPId);

    		_systemLogger.info("Adding "+sIDPAlias+"->"+sShadowedIDPId+" to TGT attribute '"+TGT_ATTR_SHADOWED_IDPS+"'");
    		oTGTAttributes.put(SSOService.class, TGT_ATTR_SHADOWED_IDPS, mShadowedIDPs);
    		
    		return;
    	}
    	
    	_systemLogger.debug("No '"+ProxyAttributes.PROXY_SHADOWED_IDPID+"' found in session attributes.");
    }

    
    /**
     * Returns false when there is no match, or true when match was made or no match had to be made because 
     * not answering on behalf of a shadowed IDP  
     * @param oTGT
     * @param oSession
     */
    protected boolean matchShadowIDP(ITGT oTGT, ISession oSession)
    {
    	ISessionAttributes oAttributes = oSession.getAttributes();
    	URLPathContext oURLContext = (URLPathContext) oAttributes.get(ProxyAttributes.class, ProxyAttributes.PROXY_URLPATH_CONTEXT);
    	
    	if (oURLContext != null && oURLContext.getParams().containsKey("i")) {
    		String sIValue = oURLContext.getParams().get("i");	// contains the IDP alias
    		ITGTAttributes oTGTAttributes = oTGT.getAttributes();
    		
    		@SuppressWarnings("unchecked")
			Map<String, String> mShadowedIDPs = (Map<String, String>) 
    				oTGTAttributes.get(SSOService.class, TGT_ATTR_SHADOWED_IDPS);
    		
    		if (mShadowedIDPs == null) {
    			_systemLogger.warn("Found '"+ProxyAttributes.PROXY_URLPATH_CONTEXT+"' in session, but there is no" +
    					"record of a '"+TGT_ATTR_SHADOWED_IDPS+"' in the TGT attributes");
    			return false;
    		}
    		
    		String sShadowedIDPId = (String) mShadowedIDPs.get(sIValue);
    		if (sShadowedIDPId == null) {
    			_systemLogger.warn("Did not find alias '"+sIValue+"' in map in TGT attributes");
    			return false;
    		}
    		
    		// Put the shadowed IDP.id in the session
    		oAttributes.put(ProxyAttributes.class, ProxyAttributes.PROXY_SHADOWED_IDPID, sShadowedIDPId);
    		
    		return true;
    		
    	} else {
    		_systemLogger.debug("No '"+ProxyAttributes.PROXY_URLPATH_CONTEXT+"' or no \"i\"-value found in session attributes.");
    		return true;
    	}
    }
    
    
    /**
     * If the session registered an AuthenticationContext, make sure that it is copied over to the
     * TGT so it can later be reused.
     * 
     * The TGT registers a Map: {String(AuthnMethod.id)->IAuthenticationContext, ...}
     * 
     * @param oTgt TGT to store the AuthenticationContext in
     * @param oSession Session to resolve the AuthenticationContext from
     * @param oAuthnMethod AuthenticationMethod of which to find the AuthenticationContext
     */
    private void registerAuthenticationContext(ITGT oTgt, ISession oSession, IAuthenticationMethod oAuthnMethod)
    {
    	ISessionAttributes oSessionAttributes = oSession.getAttributes();
    	if (! oSessionAttributes.contains(AuthenticationContexts.class, AuthenticationContexts.ATTR_AUTHCONTEXTS)) {
    		_systemLogger.debug("The ISession did not contain AuthenticationContexts; skipping.");
    		return;
    	}
    	
    	IAuthenticationContexts oSessionAuthenticationContexts = 
    			(IAuthenticationContexts) oSessionAttributes.get(AuthenticationContexts.class, AuthenticationContexts.ATTR_AUTHCONTEXTS);
    	
    	if (! oSessionAuthenticationContexts.contains(oAuthnMethod.getID())) {
    		_systemLogger.debug("The Session's AuthenticationContexts did not contain context for "
    				+oAuthnMethod.getID()+"; skipping.");
    		return;
    	}
    	
    	IAuthenticationContexts oTGTAuthenticationContexts;
    	ITGTAttributes oTGTAttributes = oTgt.getAttributes();
    	
    	if (! oTGTAttributes.contains(AuthenticationContexts.class, AuthenticationContexts.ATTR_AUTHCONTEXTS)) {
    		oTGTAuthenticationContexts = new AuthenticationContexts();
    	} else {
    		oTGTAuthenticationContexts =
    				(IAuthenticationContexts) oTGTAttributes.get(AuthenticationContexts.class, AuthenticationContexts.ATTR_AUTHCONTEXTS);
    	}
    	
    	//Store Method's AuthenticationContext from Session into TGT: 
    	oTGTAuthenticationContexts.setAuthenticationContext(
    			oAuthnMethod.getID(), oSessionAuthenticationContexts.getAuthenticationContext(oAuthnMethod.getID()));;

    	//Update the AuthenticationContexts in the TGT attributes:
    	oTGTAttributes.put(AuthenticationContexts.class, AuthenticationContexts.ATTR_AUTHCONTEXTS, oTGTAuthenticationContexts);
    	_systemLogger.debug("TGT AuthenticationContexts registered for "+oTGTAuthenticationContexts.getStoredAuthenticationMethods());
    }

}