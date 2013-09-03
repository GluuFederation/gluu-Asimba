/*
 * Asimba - Serious Open Source SSO
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
package com.alfaariss.oa.authentication.remote.saml2.profile.re;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004Builder;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.Base64;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.session.SessionState;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.authentication.remote.saml2.SAML2AuthNConstants;
import com.alfaariss.oa.authentication.remote.saml2.profile.re.metadata.SPSSODescriptorBuilder;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.idp.IDPStorageManager;
import com.alfaariss.oa.engine.core.idp.storage.IIDP;
import com.alfaariss.oa.util.logging.RequestorEventLogItem;
import com.alfaariss.oa.util.saml2.SAML2Exchange;
import com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow;
import com.alfaariss.oa.util.saml2.SAML2Requestors;
import com.alfaariss.oa.util.saml2.SAML2SecurityException;
import com.alfaariss.oa.util.saml2.binding.AbstractDecodingFactory;
import com.alfaariss.oa.util.saml2.binding.BindingProperties;
import com.alfaariss.oa.util.saml2.idp.SAML2IDP;
import com.alfaariss.oa.util.saml2.profile.AbstractSAML2Profile;
import com.alfaariss.oa.util.validation.SessionValidator;

/**
 * SAMLProfile handler to serve as a SAML <code>&lt;Response&gt;</code> endpoint in the 
 * WebSSO browser profile.
 * 
 * SAML <code>&lt;Response&gt;</code>s cannot be handled by the WebSSO solely,
 * because of restrictions on the form of the URL the response must be sent to. No
 * variable session ID can be put in, since a URL of this form cannot be published
 * in the metadata.
 * 
 * This profile is usually used in combination with the SAML Authentication Method,
 * so make sure that the requestor pool associated with this requestor includes the
 * SAML Authentication Method to ensure proper handling of SAML 
 * <code>&lt;Response&gt;</code>s.
 * 
 * @author jre
 * @author Alfa & Ariss
 */
public class ResponseEndpoint extends AbstractSAML2Profile
{
    private Log _logger = LogFactory.getLog(ResponseEndpoint.class);
    private final static String REDIRECTER = "redirect";
    private final static String DEFAULT_UR_REQUESTOR_ID = "saml_ur";
    private final static String SSO_LOGOUT_URI = "logout";
    
    private SPSSODescriptor _spSsoDescriptor = null;
    private BindingProperties _bindingProperties = null;
    private IDPStorageManager _idpStorageManager;
    private boolean _bAuthNRequestSigned;
    private boolean _bWantAssertionsSigned;
    
    /**
     * @see com.alfaariss.oa.util.saml2.profile.AbstractSAML2Profile#init(com.alfaariss.oa.api.configuration.IConfigurationManager, org.w3c.dom.Element, org.opensaml.saml2.metadata.EntityDescriptor, java.lang.String, java.lang.String, com.alfaariss.oa.util.saml2.SAML2Requestors, com.alfaariss.oa.util.saml2.SAML2IssueInstantWindow, java.lang.String)
     */
    public void init(IConfigurationManager oConfigurationManager,
        Element eConfig, EntityDescriptor entityDescriptor, String sBaseUrl, 
        String sWebSSOPath, SAML2Requestors requestors, 
        SAML2IssueInstantWindow issueInstantWindow, String sProfileID) 
        throws OAException
    {
        super.init(oConfigurationManager, eConfig, entityDescriptor, sBaseUrl, 
            sWebSSOPath, requestors, issueInstantWindow, sProfileID);

        //read bindings config
        Element eBindings = oConfigurationManager.getSection(eConfig, "bindings");
        if (eBindings == null)
        {
            _logger.error("No 'bindings' section found in 'profile' section in configuration");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        _bindingProperties = new BindingProperties(oConfigurationManager, eBindings);
        _bAuthNRequestSigned = true;
        _bWantAssertionsSigned = true;
        
        Element eSigning = oConfigurationManager.getSection(eConfig, "signing");
        if (eSigning == null)
        {
            _logger.debug("No 'signing' section found, using signing defaults");
        }
        else
        {
            String sARSigned = oConfigurationManager.getParam(eSigning, "authnRequestsSigned");
            if (sARSigned == null)
            {
                _logger.debug("No 'authnRequestsSigned' option in 'signing' section found, using signing default");
            }
            else
            {
                if (Boolean.FALSE.toString().equalsIgnoreCase(sARSigned))
                {
                    _bAuthNRequestSigned = false;
                }
                else if (!Boolean.TRUE.toString().equalsIgnoreCase(sARSigned))
                {
                    _logger.error("'authnRequestsSigned' option in 'signing' section found, but with illegal value.");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            String sWAS = oConfigurationManager.getParam(eSigning, "wantAssertionsSigned");
            if (sWAS == null)
            {
                _logger.debug("No 'wantAssertionsSigned' option in 'signing' section found, using signing default");
            }
            else
            {
                if (Boolean.FALSE.toString().equalsIgnoreCase(sWAS))
                {
                    _bWantAssertionsSigned = false;
                }
                else if (!Boolean.TRUE.toString().equalsIgnoreCase(sWAS))
                {
                    _logger.error("'wantAssertionsSigned' option in 'signing' section found, but with illegal value.");
                    throw new OAException(SystemErrors.ERROR_CONFIG_READ);
                }
            }
            
            StringBuffer sbInfo = new StringBuffer("SPSSO role using signing parameters: 'authnRequestsSigned' = ");
            sbInfo.append(_bAuthNRequestSigned);
            sbInfo.append(", 'wantAssertionsSigned' = ");
            sbInfo.append(_bWantAssertionsSigned);
            _logger.info(sbInfo.toString());
        }
        
        updateEntityDescriptor(oConfigurationManager, eConfig, 
            Engine.getInstance().getCryptoManager(), entityDescriptor, _sProfileURL,
            _bindingProperties);
        
        SAML2Exchange.setEntityDescriptor(sProfileID, entityDescriptor);
        SAML2Exchange.setSPSSOBindingProperties(sProfileID, _bindingProperties);
        
        _idpStorageManager = Engine.getInstance().getIDPStorageManager();
	}

    /**
     * @see com.alfaariss.oa.util.saml2.profile.ISAML2Profile#process(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    public void process(HttpServletRequest servletRequest,
        HttpServletResponse servletResponse) throws OAException
    {	    
	    String sURL = servletRequest.getRequestURL().toString();
	    
	    if (sURL.endsWith("/")) sURL = sURL.substring(0, sURL.length()-1);
	    _logger.debug("Servicing response: " + sURL);

	    
	    try
	    {
	        if (sURL.endsWith(REDIRECTER))
	        {
	            processRedirect(servletRequest, servletResponse);
	        }
	        else
	        {
                AbstractDecodingFactory decFactory = 
                    AbstractDecodingFactory.resolveInstance(servletRequest, 
                        servletResponse, _bindingProperties);
                
                if (decFactory == null)
                {
                    _logger.error("No decode factory available for request");
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                
                SAMLMessageDecoder decoder = decFactory.getDecoder();
        
                //check all supported bindings
                String sBindingURI = decoder.getBindingURI();
                if (!_bindingProperties.isSupported(sBindingURI))
                {
                    _logger.error("The binding is not supported by this protocol: " 
                        + sBindingURI);
                    throw new OAException(SystemErrors.ERROR_INTERNAL);
                }
                
                //decode request
                SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> 
                    context = decFactory.getContext();
                
                //use metadata from requestors to set chainedMetadataProvider for current
                //issuer
                
                String val = servletRequest.getParameter("SAMLart");
                if (val != null)
                {
                    //SAML artifact received, requestor metadata and IssuerID must be added
                    //in order to enable the decoder to decode artifact
                    
                    byte[] bb = Base64.decode(val);
                    SAML2ArtifactType0004 b = null;
                    SAML2ArtifactType0004Builder bf = new SAML2ArtifactType0004Builder();
                    b = bf.buildArtifact(bb);
                    
                    IIDP org = _idpStorageManager.getIDP(b.getSourceID(), SAML2IDP.TYPE_SOURCEID);
                    if (org != null && org instanceof SAML2IDP)
                    {
                        SAML2IDP saml2IDP = (SAML2IDP)org;
                        context.setMetadataProvider(saml2IDP.getMetadataProvider());
                        context.setInboundMessageIssuer(saml2IDP.getID());
                        context.setOutboundMessageIssuer(_sEntityID);
                    }
                    else
                    {
                        StringBuffer sbDebug = new StringBuffer("Unknown organization specified with with SourceID '");
                        sbDebug.append(Arrays.toString(b.getSourceID()));
                        sbDebug.append("' in artifact: ");
                        sbDebug.append(val);
                        _logger.debug(sbDebug.toString());
                        throw new MessageDecodingException("Could not find metadata for decoding artifact");
                    }
                }
                
                //decode context
                decoder.decode(context);
                
                processResponse(servletRequest, servletResponse, context);
	        }
	    }
	    catch (MessageDecodingException e)
	    {
	        _logger.debug("Could not decode XML in SAML request message", e);
            try
            {
                if (!servletResponse.isCommitted())
                    servletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
            }
            catch (IOException e1)
            {
                _logger.warn("Could not send response", e1);
            }
	    }
	    catch (SecurityException e)
	    {
	        _logger.debug("the decoded message does not meet the required security constraints", e);
            try
            {
                if (!servletResponse.isCommitted())
                    servletResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
            catch (IOException e1)
            {
                _logger.warn("Could not send response", e1);
            }
	    }
        catch (OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Could not process SAML request message", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
	
	private void processResponse(HttpServletRequest servletRequest, 
	    HttpServletResponse servletResponse,
        SAMLMessageContext<SignableSAMLObject, SignableSAMLObject, SAMLObject> 
        context) throws OAException
    {   
	    String sRequestorId = null;
	    try
	    {
	        sRequestorId = context.getInboundMessageIssuer();
            if (sRequestorId != null)
                _logger.debug("issuer: "  + sRequestorId);
            
            if (_idpStorageManager.getIDP(sRequestorId) == null)
            {
                _logger.debug("Processing of SAML2 message failed because issuer is not known: " + sRequestorId);
                throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
            }
            
            SignableSAMLObject obj = context.getInboundSAMLMessage();
            if (obj == null)
            {
                _logger.debug("No SAML message object in request from issuer: " + sRequestorId);
                throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
            }
            
            if (_logger.isDebugEnabled())
                logXML(obj);

            //DD: Session ID is extracted from InResponseTo. If null, relaystate or target are used for Unsolicited Response.
            String sSessionID = null;
            String sRequestIDPrefix = null;
            if (obj instanceof StatusResponseType)
            {
                String irt = ((StatusResponseType)obj).getInResponseTo();
                if (irt != null)
                {
                    if (irt.length() <= SAML2AuthNConstants.REQUEST_ID_LENGTH)
                    {
                        StringBuffer sbWarn = new StringBuffer("Invalid InResponseTo ID supplied (");
                        sbWarn.append(irt);
                        sbWarn.append(") is must have a length that is at least bigger then: ");
                        sbWarn.append(SAML2AuthNConstants.REQUEST_ID_LENGTH);
                        _logger.warn(sbWarn.toString());
                        
                        throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
                    }
                    
                    sRequestIDPrefix = irt.substring(0, SAML2AuthNConstants.REQUEST_ID_LENGTH);
                    sSessionID = irt.substring(SAML2AuthNConstants.REQUEST_ID_LENGTH); // '_' was added preceding the session ID, so remove.
                }
            }
            else
            {
                _logger.debug("Incoming SAML object is not a valid SAML response");
                throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
            }
            
            ISession session = null;
            if (sSessionID != null)
            {
                //sessionID found
                if(!SessionValidator.validateDefaultSessionId(sSessionID))
                {
                    StringBuffer sbError = new StringBuffer("Invalid '");
                    sbError.append(ISession.ID_NAME);
                    sbError.append("' in request: ");
                    sbError.append(sSessionID);
                    _logger.debug(sbError.toString());
                    throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
                } 
                
                session = _sessionFactory.retrieve(sSessionID);
                
                if (session == null || session.isExpired())
                {
                    _logger.debug("Could not process SAML response; Session expired");
                    throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
                }
                
                if (session.getAttributes().contains(SAML2AuthNConstants.class, 
                    SAML2AuthNConstants.AUTHNREQUEST_ID_PREFIX))
                {
                    String sSessionRequestIDPrefix = 
                        (String)session.getAttributes().get(SAML2AuthNConstants.class, 
                        SAML2AuthNConstants.AUTHNREQUEST_ID_PREFIX);
                    
                    if (sSessionRequestIDPrefix != null 
                        && sRequestIDPrefix != null
                        && !sSessionRequestIDPrefix.equals(sRequestIDPrefix))
                    {
                        StringBuffer sbError = new StringBuffer("Invalid InResponseTo session ID prefix in request: expected '");
                        sbError.append(sSessionRequestIDPrefix);
                        sbError.append("' but recieved: ");
                        sbError.append(sRequestIDPrefix);
                        _logger.debug(sbError.toString());
                        throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
                    }
                }
                
                //verify that the response is sent in response to a request sent by the right
                //SAML profile.
            }
            else
            {
                //Create session: probably an unsolicited response
                session = _sessionFactory.createSession(DEFAULT_UR_REQUESTOR_ID);
                
                String sTarget = null;
                String sRelayState = context.getRelayState();
                if (sRelayState == null)
                {
                    //try SAML 1.1 TARGET parameter:
                    sTarget = servletRequest.getParameter("TARGET");
                    if (sTarget == null)
                    {
                        //No relaystate and no target: Error!
                        _logger.debug("No session ID and no target found in SAML response");
                        throw new SAML2SecurityException(RequestorEvent.REQUEST_INVALID);
                    }
                }
                else
                {
                    
                    sTarget = sRelayState;
                }
                
                session.getAttributes().put(ResponseEndpoint.class, 
                    SAML2AuthNConstants.ATTR_TARGET, sTarget);
            }
            
            servletRequest.setAttribute(SAML2AuthNConstants.SESSION_ATTRIBUTE_NAME, context);
            servletRequest.setAttribute(SAML2AuthNConstants.RESPONSE_ENDPOINT_PARAM, new Boolean(true));
            
            switch (session.getState())
            {
                case SESSION_CREATED:
                {
                    processUnsolicitedResponse(servletRequest, servletResponse, session);
                    break;
                }
                case USER_LOGOUT_IN_PROGRESS:
                {
                    processLogoutResponse(servletRequest, servletResponse, session);
                    break;
                }
                default:
                {
                    processAuthNResponse(servletRequest, servletResponse, session);
                }
            }
	    }
        catch (SAML2SecurityException e)
        {
            _logger.debug("Error processing SAML message for: " + sRequestorId, e);
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                e.getEvent(), null, servletRequest.getRemoteAddr(), 
                null, this, "Error processing SAML message for: " + sRequestorId));
            try
            {
                if (!servletResponse.isCommitted())
                    servletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
            }
            catch (IOException e1)
            {
                _logger.warn("Could not send response", e1);
            }
        }
        catch (OAException e)
        {
            _logger.error("Could not process Response", e);
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                RequestorEvent.REQUEST_INVALID, null, servletRequest.getRemoteAddr(), 
                null, this, null));
            throw e;
        }
        catch (Exception e)
        {
            _logger.error("Could not process Response", e);
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                RequestorEvent.INTERNAL_ERROR, null, servletRequest.getRemoteAddr(), 
                null, this, null));
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
	
    private void processRedirect(HttpServletRequest servletRequest, 
         HttpServletResponse servletResponse) throws OAException
    {
        ISession session = null;
        
        String sSessionID = servletRequest.getParameter(ISession.ID_NAME);
        
        try
        {
            if (sSessionID == null)
            {
                _logger.debug(
                    "Could not redirect to webapp; Parameter 'asid' missing");
                if (!servletResponse.isCommitted())
                    servletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
                
                return;
            }
            
            if(!SessionValidator.validateDefaultSessionId(sSessionID))
            {
                StringBuffer sbError = new StringBuffer("Invalid '");
                sbError.append(ISession.ID_NAME);
                sbError.append("' in request: ");
                sbError.append(sSessionID);
                _logger.debug(sbError.toString());
                if (!servletResponse.isCommitted())
                    servletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
                
                return;
            } 
            
            session = _sessionFactory.retrieve(sSessionID);
            if (session == null)
            {
                _logger.debug(
                    "Could not redirect to webapp; Could not retrieve session");
                if (!servletResponse.isCommitted())
                    servletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST);
                
                return;
            }
            
            if (session.isExpired())
            {
                _logger.debug("Could not redirect to webapp; Session expired");
                if (!servletResponse.isCommitted())
                    servletResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
                
                return;
            }
            
            if (session.getState() != SessionState.AUTHN_OK)
            {
                IUser user = session.getUser();
                String uid = null;
                if (user != null) uid = user.getID();
                if (uid == null) uid = "<not found>";
                _logger.debug("Could not redirect to webapp; AuthN failed (uid: " + uid + ")");
                if (!servletResponse.isCommitted())
                    servletResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
                
                return;
            }
        
            String returnTo = (String)session.getAttributes().get(ResponseEndpoint.class, 
                SAML2AuthNConstants.ATTR_TARGET);
            if (returnTo == null)
            {
                _logger.debug("Could not redirect to webapp; Cannot retrieve target");
                throw new OAException(SystemErrors.ERROR_RESOURCE_RETRIEVE);
            }
            
            if (!servletResponse.isCommitted())
                servletResponse.sendRedirect(returnTo);
        }
        catch (ClassCastException cce)
        {
            _logger.error("Could not redirect to webapp; Target in wrong format", cce);
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                RequestorEvent.SESSION_INVALID, null, servletRequest.getRemoteAddr(), 
                null, this, null));
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        catch (IOException e)
        {
            _logger.error("Could not redirect to webapp; I/O error", e);
            _eventLogger.info(new RequestorEventLogItem(null, null, null, 
                RequestorEvent.INTERNAL_ERROR, null, servletRequest.getRemoteAddr(), 
                null, this, null));
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
        finally
        {
            //authn session no longer necessary
            if (session != null)
            {
                session.expire();
                session.persist();
            }
        }
    }
    
    //TODO -MG: until the metadata framework is set up properly, this method should be updated
    //for every authN method role (e.g. authN query).
    //TODO -FO: SP metadata in separate file.
    private void updateEntityDescriptor(
        IConfigurationManager configurationManager, Element config, CryptoManager crypto,
        EntityDescriptor entityDescriptor, String profileURL, BindingProperties props)
        throws OAException
    {        
        _spSsoDescriptor = 
            entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        
        SPSSODescriptorBuilder builder = new SPSSODescriptorBuilder(
            configurationManager, config, _spSsoDescriptor);
        
        builder.buildNameIDFormats();
        builder.buildAuthnRequestsSigned(_bAuthNRequestSigned);
        builder.buildWantAssertionsSigned(_bWantAssertionsSigned);
        builder.buildAssertionConsumerServices(profileURL, props);

        builder.buildProtocolSupportEnumeration();

        
        //DD: Artifact resolution service mode is determined from IdP role.
        //ARS metadata should be inserted by AR profile, and therefore the available roles
        //should be known before SAML profiles are initialized.
        List<ArtifactResolutionService> artResSvs = entityDescriptor
            .getIDPSSODescriptor(SAMLConstants.SAML20P_NS)
            .getArtifactResolutionServices();
        
        if(artResSvs != null && artResSvs.size() > 0)
        {
            for(ArtifactResolutionService artSrvs : artResSvs)
            {
                builder.buildArtifactResolutionService(artSrvs.getLocation());
            }
        }
        else
        {
            //could be a configuration mistake.
            _logger.debug("No artifact resolution service found while configuring SP role. If this is incorrect, please place ResponseEndpoint configuration below the AR config.");
        }
        
        //DD If no private key is supplied (signing not configured) signing is omitted
        if(crypto.getPrivateKey() != null)
        {         
            builder.buildSigningKeyDescriptor(crypto, 
                entityDescriptor.getEntityID());
        }
        RoleDescriptor roleDescriptor = builder.getResult();
        List<RoleDescriptor> roles = entityDescriptor.getRoleDescriptors();
        //TODO Does this help solve the metadata read issues with the MO federation?
        //Was: roles.add(roleDescriptor);
        roles.add(0, roleDescriptor);
    }
    
    private void processUnsolicitedResponse(HttpServletRequest request, 
        HttpServletResponse response, ISession session) throws OAException
    {
        //TODO set chosen organization to avoid selector screen?
        //TODO make UR issuer unavailable for selection
        
        session.persist();
        
        //if no profile URL is specified (= Unsolicited response) make sure the redirect
        //part of the ResponseEndpoint is addressed as well.
        String sURL = request.getRequestURL().toString();
        
        StringBuffer sbURL = new StringBuffer(sURL);
        
        if (!sURL.endsWith("/"))
            sbURL.append("/");
        
        sbURL.append(REDIRECTER);
        sbURL.append("?");
        sbURL.append(ISession.ID_NAME);
        sbURL.append("=");
        sbURL.append(session.getId());
        
        session.setProfileURL(sbURL.toString());
        
        forwardToSSOWeb(request, response, session);
    }
    
    private void processLogoutResponse(HttpServletRequest request, 
        HttpServletResponse response, ISession session) throws OAException
    {
        forwardToSSOLogout(request, response, session);
    }
    
    private void processAuthNResponse(HttpServletRequest request, 
        HttpServletResponse response, ISession session) throws OAException
    {
        forwardToSSOWeb(request, response, session);
    }
    
    private void forwardToSSOWeb(HttpServletRequest request, 
        HttpServletResponse response, ISession session) throws OAException
    {
        try
        {
            request.setAttribute(ISession.ID_NAME, session);
            
            RequestDispatcher oDispatcher = request.getRequestDispatcher(
                _sWebSSOPath);
            if(oDispatcher == null)
            {
                _logger.warn(
                    "There is no requestor dispatcher supported with name: " 
                    + _sWebSSOPath);
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            oDispatcher.forward(request, response);
        }
        catch(OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during forward to sso web", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
    
    private void forwardToSSOLogout(HttpServletRequest request, 
        HttpServletResponse response, ISession session) throws OAException
    {
        try
        {
            request.setAttribute(ISession.ID_NAME, session);
            
            StringBuffer sbForward = new StringBuffer(_sWebSSOPath);
            if (!_sWebSSOPath.endsWith("/"))
                sbForward.append("/");
            sbForward.append(SSO_LOGOUT_URI);
            
            RequestDispatcher oDispatcher = request.getRequestDispatcher(
                sbForward.toString());
            if(oDispatcher == null)
            {
                _logger.warn(
                    "There is no requestor dispatcher supported with name: " 
                    + sbForward.toString());
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            oDispatcher.forward(request, response);
        }
        catch(OAException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during forward to sso logout", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }
}
