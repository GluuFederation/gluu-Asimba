
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
package com.alfaariss.oa.profile.aselect.ws;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rampart.RampartException;
import org.apache.rampart.RampartMessageData;
import org.apache.rampart.policy.RampartPolicyData;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.profile.aselect.business.BusinessRuleException;
import com.alfaariss.oa.profile.aselect.business.beans.TGTInfo;
import com.alfaariss.oa.profile.aselect.business.requestor.RequestorService;
import com.alfaariss.oa.profile.aselect.processor.ASelectProcessor;

/**
 * The A-Select webservice main class.
 * 
 * This webservice uses the {@link RequestorService} to perform initiation and 
 * verification of an OpenASelect authentication. It is a end point for 
 * registrated requestors (applications). The authentication itself is 
 * delegated to the ASelect profile and the WebSSO.
 * 
 * The A-Select webservice is part of the A-Select Profile and therefore shares
 * its configuration.
 * 
 * This class is marked as a Web Service using the <code>@WebService</code> 
 * annotation.
 * 
 * @author EVB
 * @author Alfa & Ariss
 *
 * @see ASelectProcessor
 */
public class ASelectProfileWS
{
    /** The A-Select webservice target webspace. */
    public static final String TARGET_NAMESPACE = 
        "http://aselectws.openaselect.org/";
    /** The authenticateResponse */
    public static final String AUTHENTICATE_RESPONSE = 
        "authenticateResponse";
    /** The verify_credentialsResponse */
    public static final String VERIFY_CREDENTIALS_RESPONSE = 
        "verifyCredentialsResponse"; 
    /** The initLogoutResponse */
    public static final String INIT_LOGOUT_RESPONSE = 
        "sloResponse";
    /** The logoutResponse */
    public static final String LOGOUT_RESPONSE = 
        "logoutResponse";
    //DD The verifyCredentials request and response are named "java style"
    //DD The authenticate response is simplified by returning the constructed redirect URL as one parameter
    
    private RequestorService _service;
    private Log _logger;
    private Engine _engine;

    /**
     * Default constructor.
     * 
     * Initializes the <code>RequestorService</code> and adds the service to the 
     * engine as observer.
     * @throws OAException If initialization fails.
     */
    public ASelectProfileWS () throws OAException
    {
        try
        {
            _logger = LogFactory.getLog(ASelectProfileWS.class);
            _logger.info("Starting: aselect ws profile");

            _service = new RequestorService();
            _engine = Engine.getInstance();

            //Initialize service
            _service.start(_engine.getConfigurationManager(), null);

            //Add the service as observer
            _engine.addComponent(_service);

            if (!_service.isInitialized())
                _logger.info("Disabled: aselect ws profile");
            else
                _logger.info("Started: aselect ws profile");
        }
        catch(OAException e)
        {
            _logger.fatal("Initialization failed", e);
            throw e;
        }
        catch (Exception e)
        {
            _logger.fatal(
                "Initialization failed, due to internal error", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

   
    /**
     * Initialize the authentication process.    
     * 
     * @param request The OA authenticate request object model.
     * @return The authenticationResponse.
     * @throws AxisFault If processing fails.     
     */    
    public OMElement authenticate(OMElement request) throws AxisFault
    {
        String remoteAddr = null;
        try
        {
            if (!_service.isInitialized())
            {
                _logger.warn("Service not initialized or disabled");
                //TODO server busy error (Erwin)
               throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
               
            }
            //Retrieve message context
            MessageContext context = MessageContext.getCurrentMessageContext();
            if(context == null)
            {           
                _logger.warn("Could not retrieve message context");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            //Debug incoming envelope
            if(_logger.isDebugEnabled())
            {
                SOAPEnvelope envelope = context.getEnvelope();
                _logger.debug(envelope);
            }
            
            //Retrieve remote address 
            remoteAddr = (String)context.getProperty(MessageContext.REMOTE_ADDR);
            
            //Retrieve parameters
            String oaID = null;
            OMElement om = request.getFirstChildWithName(new QName(
                ASelectProfileWS.TARGET_NAMESPACE,
                ASelectProcessor.PARAM_ASELECTSERVER));
            if (om != null)
            {
                oaID = om.getText();
            }
            else
            {
                om = request.getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_ASELECTSERVER_ALTERATIVE));
                
                if (om != null)
                {
                    oaID = om.getText();
                }
            }
            
            String requestorID = null;
            om = request
                .getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_APPID));
            if (om != null)
            {
                requestorID = om.getText();
            }
            
            String requestorURL = null;
            om = request
                .getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_APPURL));
            if (om != null)
            {
                requestorURL = om.getText();

            }
            
            String remoteOrganization = null;
            om = request
                .getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_REMOTE_ORGANIZATION));
            if (om != null)
            {
                remoteOrganization = om.getText();

            }
            
            String sForcedLogon = null; // default false
            om = request
                .getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_FORCED_LOGON));
            if (om != null)
            {
                sForcedLogon = om.getText();               
            }
            
            String sPassive = null; // default false
            om = request
                .getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_PASSIVE));
            if (om != null)
            {
                sPassive = om.getText();               
            }
            
            String uid = null;
            om = request
                .getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_UID));
            if (om != null)
            {
                uid = om.getText();

            }
            String country = null;
            om = request
                .getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_COUNTRY));
            if (om != null)
            {
                country = om.getText();

            }
            String language = null;
            om = request
                .getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_LANGUAGE));
            if (om != null)
            {
                language = om.getText();

            }
                                    
            //Bussiness processing
            ISession session =  _service.initiateAuthentication(oaID, 
                requestorID, requestorURL, remoteOrganization, sForcedLogon, 
                uid, remoteAddr, country, language, isSigned(context), sPassive);
            
            //Create redirect URL
            StringBuffer sbAsUrl = new StringBuffer(
                _service.getRedirectURLBase());            
            sbAsUrl.append("?request=login1&");
            sbAsUrl.append(ASelectProcessor.PARAM_ASELECTSERVER);
            sbAsUrl.append("=");
            sbAsUrl.append(oaID);
            sbAsUrl.append("&rid=").append(session.getId());
            
            //Create response                      
            OMFactory fac = context.getEnvelope().getOMFactory();
            OMNamespace omNs = fac.createOMNamespace(
                    ASelectProfileWS.TARGET_NAMESPACE, "oa");
            OMNamespace omNs1 = fac.createOMNamespace(
                "http://www.w3.org/2001/XMLSchema-instance", "xsi");
            OMNamespace omNs2 = fac.createOMNamespace(
                "http://www.w3.org/2001/XMLSchema", "xsd");
            OMElement authnResponse = fac.createOMElement(
                AUTHENTICATE_RESPONSE, omNs);
            authnResponse.declareNamespace(omNs1);
            authnResponse.declareNamespace(omNs2);           
            authnResponse.addChild(createParam(fac, 
                ASelectProcessor.PARAM_ASELECT_URL, sbAsUrl.toString(), 
                omNs, "xsd:string", omNs1));           
            
            //Debug outgoing envelope
            if(_logger.isDebugEnabled())
            {               
                _logger.debug(authnResponse);
            }
            
            return authnResponse;
            
        }       
        catch (BusinessRuleException e)
        {
            throw new WSFault(e);
        }
        catch (OAException e)
        {
            _logger.error("Error while processing authenticate request", e);
            throw new WSFault(e);

        }
        catch (Exception e)
        {
            _logger.fatal(
                "Internal error while processing authenticate request", e);
            throw new WSFault(new OAException(SystemErrors.ERROR_INTERNAL));
        }
    }
    
    /**
     * Verification of the authentication process.
     * 
     * @param request The authenticate request 
     * @return The verify_credentialsResponse.
     * @throws AxisFault If processing fails.
     */    
    public OMElement verifyCredentials(OMElement request) throws AxisFault
    {
        String remoteAddr = null;
        try
        {
            if (!_service.isInitialized())
            {
                _logger.warn("Service not initialized or disabled");                
                //TODO server busy error (Erwin)
                throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
            }
            
            //Retrieve message context
            MessageContext context = MessageContext.getCurrentMessageContext();
            if(context == null)
            {           
                _logger.warn("Could not retrieve message context");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            
            //Debug incoming envelope
            if(_logger.isDebugEnabled())
            {
                SOAPEnvelope envelope = context.getEnvelope();
                _logger.debug(envelope);
            }
            
            //Retrieve remote address 
            remoteAddr = (String)context.getProperty(MessageContext.REMOTE_ADDR);
            
            String sASelectServerResponseParam = ASelectProcessor.PARAM_ASELECTSERVER;
            
            //Retrieve parameters
            String oaID = null;
            OMElement om = request.getFirstChildWithName(new QName(
                ASelectProfileWS.TARGET_NAMESPACE,
                ASelectProcessor.PARAM_ASELECTSERVER));
            if (om != null)
            {
                oaID = om.getText();
            }
            else
            {
                om = request.getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_ASELECTSERVER_ALTERATIVE));
                if (om != null)
                {
                    oaID = om.getText();
                    sASelectServerResponseParam = ASelectProcessor.PARAM_ASELECTSERVER_ALTERATIVE;
                }
            }
            
            String requestorID = null;
            om = request
                .getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_APPID));
            if (om != null)
            {
                requestorID = om.getText();

            }
            String rid = null;
            om = request.getFirstChildWithName(new QName(
                ASelectProfileWS.TARGET_NAMESPACE,
                ASelectProcessor.PARAM_RID));
            if (om != null)
            {
                rid = om.getText();
    
            }
            String credentials = null;
            om = request.getFirstChildWithName(new QName(
                ASelectProfileWS.TARGET_NAMESPACE,
                ASelectProcessor.PARAM_ASELECT_CREDENTIALS));
            if (om != null)
            {
                credentials = om.getText();
    
            }            
            
            //Business processing
            TGTInfo info =  _service.verifyAuthentication(oaID, requestorID, 
                rid, credentials, remoteAddr, isSigned(context));
            
            //Create response
            SOAPEnvelope envelope = context. getEnvelope();
            OMFactory fac = envelope.getOMFactory();            
            OMNamespace omNs = fac.createOMNamespace(
                    ASelectProfileWS.TARGET_NAMESPACE, "oa");
            OMNamespace omNs1 = fac.createOMNamespace(
                "http://www.w3.org/2001/XMLSchema-instance", "xsi");
            OMNamespace omNs2 = fac.createOMNamespace(
                "http://www.w3.org/2001/XMLSchema", "xsd");
            
            OMElement response = fac.createOMElement(
                VERIFY_CREDENTIALS_RESPONSE, omNs);
            response.declareNamespace(omNs1);
            response.declareNamespace(omNs2);
            response.addChild(createParam(fac, 
                ASelectProcessor.PARAM_RESULT_CODE, info.getResultCode(), 
                omNs, "xsd:string", omNs1));
            response.addChild(createParam(fac, 
                sASelectServerResponseParam, oaID, omNs, "xsd:string", omNs1));
            String organization = info.getOrganization();
            if(organization != null)
            {
                response.addChild(createParam(fac, 
                    ASelectProcessor.PARAM_ORGANIZATION,organization, 
                    omNs, "xsd:string", omNs1));
            }
            int iAppLevel = info.getAppLevel();
            if(iAppLevel > 0)
            {
                response.addChild(createParam(fac, 
                    ASelectProcessor.PARAM_APP_LEVEL, 
                    Integer.toString(iAppLevel), omNs, "xsd:integer", omNs1));
            }
            int iAuthSPLevel = info.getAuthspLevel();
            if(iAppLevel > 0)
            {
                response.addChild(createParam(fac, 
                    ASelectProcessor.PARAM_AUTHSP_LEVEL, 
                    Integer.toString(iAuthSPLevel), omNs, "xsd:integer", omNs1));
            }
            String authsp = info.getAuthsp();
            if(authsp != null)
            {
                response.addChild(createParam(fac, 
                    ASelectProcessor.PARAM_AUTHSP, authsp, 
                    omNs, "xsd:string", omNs1));
            }
            String uid = info.getUid();
            if(uid != null)
            {
                response.addChild(createParam(fac, 
                    ASelectProcessor.PARAM_UID,uid, omNs, "xsd:string", omNs1));
            }
            long lExpiration = info.getExpiration();
            if(lExpiration > 0)
            {
                response.addChild(createParam(fac, 
                    ASelectProcessor.PARAM_TGT_EXP_TIME, 
                    Long.toString(lExpiration), omNs, "xsd:long", omNs1));
            }
            String sAttributes = info.getAttributes();
            if(sAttributes != null)
            {
                response.addChild(createParam(fac, 
                    ASelectProcessor.PARAM_ATTRIBUTES, sAttributes, 
                    omNs, "xsd:string", omNs1));
            }
            int iASPLevel = info.getAuthspLevel();
            if(iASPLevel > 0)
            {
                response.addChild(createParam(fac, 
                    ASelectProcessor.PARAM_ASP_LEVEL, 
                    Integer.toString(iASPLevel), omNs, "xsd:integer", omNs1));
            }            
            String asp = info.getAsp();
            if(asp != null)
            {
                response.addChild(createParam(fac, 
                    ASelectProcessor.PARAM_ASP, asp, omNs, "xsd:string", omNs1));
            }
            
            //Debug outgoing envelope
            if(_logger.isDebugEnabled())
            {               
                _logger.debug(response);
            }
            return response;
            
            
        }      
        catch (BusinessRuleException e)
        {
            throw new WSFault(e);
        }
        catch (OAException e)
        {
            _logger
                .error("Error while processing verifyCredentials request", e);
            throw new WSFault(e);
        }
        catch (Exception e)
        {
            _logger.fatal(
                "Internal error while processing verifyCredentials request", e);
            throw new WSFault(new OAException(SystemErrors.ERROR_INTERNAL));
        }
    }

    /**
     * Initialize the asynchronous logout process.    
     * 
     * @param request The OA logout request object model.
     * @return The initLogoutResponse.
     * @throws AxisFault If processing fails.     
     */    
    public OMElement slo(OMElement request) throws AxisFault
    {
        String remoteAddr = null;
        try
        {
            if (!_service.isInitialized())
            {
                _logger.warn("Service not initialized or disabled");
                //TODO server busy error (Erwin)
               throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
               
            }
            //Retrieve message context
            MessageContext context = MessageContext.getCurrentMessageContext();
            if(context == null)
            {           
                _logger.warn("Could not retrieve message context");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            //Debug incoming envelope
            if(_logger.isDebugEnabled())
            {
                SOAPEnvelope envelope = context.getEnvelope();
                _logger.debug(envelope);
            }
            
            //Retrieve remote address 
            remoteAddr = (String)context.getProperty(MessageContext.REMOTE_ADDR);
            
            //Retrieve parameters
            String oaID = null;
            OMElement om = request.getFirstChildWithName(new QName(
                ASelectProfileWS.TARGET_NAMESPACE,
                ASelectProcessor.PARAM_ASELECTSERVER));
            if (om != null)
            {
                oaID = om.getText();
            }
            else
            {
                om = request.getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_ASELECTSERVER_ALTERATIVE));
                
                if (om != null)
                {
                    oaID = om.getText();
                }
            }
            
            String requestorID = null;
            om = request
                .getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_APPID));
            if (om != null)
            {
                requestorID = om.getText();
    
            }
            
            String credentials = null;
            om = request
                .getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_ASELECT_CREDENTIALS));
            if (om != null)
            {
                credentials = om.getText();    
            }
            
            String requestorURL = null;
            om = request
                .getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_APPURL));
            if (om != null)
            {
                requestorURL = om.getText();
    
            }
                 
            //Bussiness processing
            ISession logoutSession =  _service.slo(oaID, requestorID, 
                credentials, requestorURL, remoteAddr, isSigned(context));
            
            //Create redirect URL
            StringBuffer sbAsUrl = new StringBuffer(
                _service.getRedirectURLBase());            
            sbAsUrl.append("?request=logout&");
            sbAsUrl.append(ASelectProcessor.PARAM_ASELECTSERVER);
            sbAsUrl.append("=");
            sbAsUrl.append(oaID);
            sbAsUrl.append("&rid=").append(logoutSession.getId());
            
            //Create response                      
            OMFactory fac = context.getEnvelope().getOMFactory();
            OMNamespace omNs = fac.createOMNamespace(
                    ASelectProfileWS.TARGET_NAMESPACE, "oa");
            OMNamespace omNs1 = fac.createOMNamespace(
                "http://www.w3.org/2001/XMLSchema-instance", "xsi");
            OMNamespace omNs2 = fac.createOMNamespace(
                "http://www.w3.org/2001/XMLSchema", "xsd");
            OMElement logoutResponse = fac.createOMElement(
                INIT_LOGOUT_RESPONSE, omNs);
            logoutResponse.declareNamespace(omNs1);
            logoutResponse.declareNamespace(omNs2);           
            logoutResponse.addChild(createParam(fac, 
                ASelectProcessor.PARAM_ASELECT_URL, sbAsUrl.toString(), 
                omNs, "xsd:string", omNs1));           
            
            //Debug outgoing envelope
            if(_logger.isDebugEnabled())
            {               
                _logger.debug(logoutResponse);
            }
            
            return logoutResponse;
            
        }       
        catch (BusinessRuleException e)
        {
            throw new WSFault(e);
        }
        catch (OAException e)
        {
            _logger.error(
                "Error while processing logout initiation request", e);
            throw new WSFault(e);
    
        }
        catch (Exception e)
        {
            _logger.fatal(
                "Internal error while processing logout initiation request", e);
            throw new WSFault(new OAException(SystemErrors.ERROR_INTERNAL));
        }
    }
    
    /**
     * Perform synchronous logout.    
     * 
     * @param request The OA logout request object model.
     * @return The logoutResponse.
     * @throws AxisFault If processing fails.     
     */    
    public OMElement logout(OMElement request) throws AxisFault
    {
        String remoteAddr = null;
        try
        {
            if (!_service.isInitialized())
            {
                _logger.warn("Service not initialized or disabled");
                //TODO server busy error (Erwin)
               throw new OAException(SystemErrors.ERROR_NOT_INITIALIZED);
               
            }
            //Retrieve message context
            MessageContext context = MessageContext.getCurrentMessageContext();
            if(context == null)
            {           
                _logger.warn("Could not retrieve message context");
                throw new OAException(SystemErrors.ERROR_INTERNAL);
            }
            //Debug incoming envelope
            if(_logger.isDebugEnabled())
            {
                SOAPEnvelope envelope = context.getEnvelope();
                _logger.debug(envelope);
            }
            
            //Retrieve remote address 
            remoteAddr = (String)context.getProperty(MessageContext.REMOTE_ADDR);
            
            //Retrieve parameters
            String requestorID = null;
            OMElement om = request
                .getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_APPID));
            if (om != null)
            {
                requestorID = om.getText();
    
            }
            String credentials = null;
            om = request
                .getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_ASELECT_CREDENTIALS));
            if (om != null)
            {
                credentials = om.getText();
    
            }
            
            String reason = null;
            om = request.getFirstChildWithName(new QName(
                    ASelectProfileWS.TARGET_NAMESPACE,
                    ASelectProcessor.PARAM_REASON));
            if (om != null)
            {
                reason = om.getText();
    
            }
                 
            //Bussiness processing
            String result =  _service.logout(requestorID, 
                credentials, remoteAddr, isSigned(context), reason);
           
            //Create response                      
            OMFactory fac = context.getEnvelope().getOMFactory();
            OMNamespace omNs = fac.createOMNamespace(
                    ASelectProfileWS.TARGET_NAMESPACE, "oa");
            OMNamespace omNs1 = fac.createOMNamespace(
                "http://www.w3.org/2001/XMLSchema-instance", "xsi");
            OMNamespace omNs2 = fac.createOMNamespace(
                "http://www.w3.org/2001/XMLSchema", "xsd");
            OMElement logoutResponse = fac.createOMElement(
                LOGOUT_RESPONSE, omNs);
            logoutResponse.declareNamespace(omNs1);
            logoutResponse.declareNamespace(omNs2);           
            logoutResponse.addChild(createParam(fac, 
                ASelectProcessor.PARAM_RESULT_CODE, result, omNs, 
                "xsd:string", omNs1));           
            
            //Debug outgoing envelope
            if(_logger.isDebugEnabled())
            {               
                _logger.debug(logoutResponse);
            }
            
            return logoutResponse;
            
        }       
        catch (BusinessRuleException e)
        {
            throw new WSFault(e);
        }
        catch (OAException e)
        {
            _logger.error("Error while processing logout request", e);
            throw new WSFault(e);
    
        }
        catch (Exception e)
        {
            _logger.fatal(
                "Internal error while processing logout request", e);
            throw new WSFault(new OAException(SystemErrors.ERROR_INTERNAL));
        }
    }
    
    /**
     * Clean up the service.
     * @see java.lang.Object#finalize()
     */
    protected void finalize() throws Throwable
    {
        try
        {
            _service.stop();
            _engine.removeComponent(_service);
            _logger.info("Stopped: aselect ws profile");

            super.finalize();
        }
        catch (Exception e)
        {
            _logger.fatal("Could not stop aselect ws profile properly", e);
        }
    }
    
    //Create reponse param
    private OMElement createParam(OMFactory fac, String name, String value, 
        OMNamespace omNs, String type, OMNamespace typeNs)
    {
        OMElement param = fac.createOMElement(name, omNs);
        param.addAttribute("type", type, typeNs);       
        param.addChild(fac.createOMText(param, value));
        return param;
    }


    //determine request signed state
    private boolean isSigned(MessageContext context)
    {
        boolean signed = false;       
        try
        {
            RampartMessageData rmd = new RampartMessageData(context, true);
            if(rmd != null)
            {
                RampartPolicyData rpd = rmd.getPolicyData(); 
                if(rpd != null)
                {
                    signed = rpd.isSignBody();
                }                    
            }
        }
        catch (RampartException e)
        {
            // signed  = false
            _logger.warn(
                "Could not determine signing, presuming message not signed", e);
        } 
        _logger.debug("request was signed: " + signed);
        return signed;
    }
}
