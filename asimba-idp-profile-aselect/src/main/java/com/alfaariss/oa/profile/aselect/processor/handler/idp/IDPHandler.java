
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
package com.alfaariss.oa.profile.aselect.processor.handler.idp;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;

import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.attribute.ISessionAttributes;
import com.alfaariss.oa.api.authentication.IAuthenticationProfile;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.requestor.RequestorPool;
import com.alfaariss.oa.profile.aselect.ASelectErrors;
import com.alfaariss.oa.profile.aselect.ASelectException;
import com.alfaariss.oa.profile.aselect.binding.IBinding;
import com.alfaariss.oa.profile.aselect.binding.IRequest;
import com.alfaariss.oa.profile.aselect.binding.IResponse;
import com.alfaariss.oa.profile.aselect.processor.ASelectProcessor;
import com.alfaariss.oa.profile.aselect.processor.handler.ASelectRequestorPool;
import com.alfaariss.oa.profile.aselect.processor.handler.AbstractAPIHandler;
import com.alfaariss.oa.profile.aselect.processor.handler.BrowserHandler;
import com.alfaariss.oa.util.logging.AbstractEventLogItem;
import com.alfaariss.oa.util.logging.RequestorEventLogItem;
import com.alfaariss.oa.util.session.ProxyAttributes;
import com.alfaariss.oa.util.validation.LocaleValidator;
import com.alfaariss.oa.util.validation.SessionValidator;

/**
 * A-Select Local IDP Request Handler
 *
 * @author MME
 * @author Alfa & Ariss
 *
 */
public class IDPHandler extends AbstractAPIHandler
{   
    /**
     * IDPHandler Constructor
     *
     * @param oConfigurationManager The Configuration Manager
     * @param eConfig The config section containing the configuration of this object
     * @param sRedirectURL The full URL to this profile or <code>null</code> 
     *  (for loadbalanced environments)
     * @param htAuthSPLevels Hashtable containing authsp_levels per 
     *  authentication profile
     * @param iDefaultAuthSPLevel Default authsp_level
     * @param sProfileID The ID of the OA profile
     * @throws OAException If the creation fails
     */
    public IDPHandler (IConfigurationManager oConfigurationManager, 
        Element eConfig, String sRedirectURL, 
        Hashtable<String, Integer> htAuthSPLevels, int iDefaultAuthSPLevel,
        String sProfileID) throws OAException
    {
        super(oConfigurationManager, eConfig, sRedirectURL, htAuthSPLevels, 
            iDefaultAuthSPLevel, sProfileID);
        try
        {
            if (!_bEnabled)
            {
                _logger.info("IDP handler: disabled");
                return;
            }

            _logger.info("Started: IDP Handler");
        }
        catch (Exception e)
        {
            _logger.fatal("Internal error during object creation", e);
            throw new OAException(SystemErrors.ERROR_INTERNAL);
        }
    }

    /**
     * Processes the <code>request=authenticate</code> API call.
     *
     * The request parameters that are supported:
     * <table border='1'>
     * <tr><th><i>parameter</i></th><th><i>value</i></th><th><i>optional?</i></th></tr>
     * <tr><td>request</td><td>authenticate</td><td>false</td></tr>
     * <tr><td>a-select-server</td><td>[a-select-server]</td><td>false</td></tr>
     * <tr><td>local_organization</td><td>[local_organization]</td><td>true</td></tr>
     * <tr><td>remote_organization</td><td>[remote_organization]</td><td>true</td></tr>
     * <tr><td>local_as_url</td><td>[local_as_url]</td><td>true</td></tr>
     * <tr><td>required_level</td><td>[required_level]</td><td>true</td></tr>
     * <tr><td>signature</td><td>[signature]</td><td>true</td></tr>
     * <tr><td>country</td><td>[country]</td><td>true</td></tr>
     * <tr><td>language</td><td>[language]</td><td>true</td></tr>
     * <tr><td>forced_logon</td><td>[forced_logon]</td><td>true</td></tr>
     * </table>
     * <br>
     * If authentication succeeds, the response will contain the following parameters:
     * <table border='1'>
     * <tr><th><i>parameter</i></th><th><i>value</i></th><th><i>optional?</i></th></tr>
     * <tr><td>as_url</td><td>[as_url]</td><td>false</td></tr>
     * <tr><td>rid</td><td>[rid]</td><td>false</td></tr>
     * <tr><td>result_code</td><td>[result_code]</td><td>false</td></tr>
     * <tr><td>a-select-server</td><td>[a-select-server]</td><td>false</td></tr>
     * </table>
     * <br>
     * If authentication fails, the response will contain the following parameters:
     * <table border='1'>
     * <tr><th><i>parameter</i></th><th><i>value</i></th><th><i>optional?</i></th></tr>
     * <tr><td>result_code</td><td>[result_code]</td><td>false</td></tr>
     * <tr><td>a-select-server</td><td>[a-select-server]</td><td>false</td></tr>
     * </table>
     * @param oServletRequest HTTP servlet request object
     * @param oBinding The binding object
     * @throws ASelectException if request handling failed or request is invalid
     */
    public void authenticate(HttpServletRequest oServletRequest, 
        IBinding oBinding) throws ASelectException
    {
        ISession oSession = null;
        AbstractEventLogItem oLogItem = null;
        try
        {
            IRequest oRequest = oBinding.getRequest();
            
            String sASelectServer = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_ASELECTSERVER);
            if (sASelectServer == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_ASELECTSERVER);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            String sLocalIdp = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_LOCAL_IDP);
            if (sLocalIdp == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_LOCAL_IDP);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            String sLocalIdpUrl = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_LOCAL_IDP_URL);
            if (sLocalIdpUrl == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_LOCAL_IDP_URL);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            int iRequiredLevel = -1;
            String sRequiredLevel = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_REQUIRED_LEVEL);
            if (sRequiredLevel == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_REQUIRED_LEVEL);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            try
            {
                iRequiredLevel = Integer.parseInt(sRequiredLevel);
            }
            catch (NumberFormatException e)
            {
                StringBuffer sbError = new StringBuffer("Invalid '");
                sbError.append(ASelectProcessor.PARAM_REQUIRED_LEVEL);
                sbError.append("' found in request: ");
                sbError.append(sRequiredLevel);
                _logger.debug(sbError.toString(), e);
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            String sUid = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_UID);
            if (sUid != null)
            {
                StringBuffer sbError = new StringBuffer("Optional '");
                sbError.append(ASelectProcessor.PARAM_UID);
                sbError.append("' found in request: ");
                sbError.append(sUid);
                _logger.debug(sbError.toString());
            }
            
            String sCountry = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_COUNTRY);
            if (sCountry == null)
            {
                StringBuffer sbError = new StringBuffer("No optional '");
                sbError.append(ASelectProcessor.PARAM_COUNTRY);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
            }
            else if (!LocaleValidator.validateCountry(sCountry))
            {
                StringBuffer sbError = new StringBuffer("Invalid '");
                sbError.append(ASelectProcessor.PARAM_COUNTRY);
                sbError.append("' found in request: ");
                sbError.append(sCountry);
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            else
            {
                StringBuffer sbError = new StringBuffer("Optional '");
                sbError.append(ASelectProcessor.PARAM_COUNTRY);
                sbError.append("' found in request: ");
                sbError.append(sCountry);
                _logger.debug(sbError.toString());
            }
            
            String sLanguage = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_LANGUAGE);
            if (sLanguage == null)
            {
                StringBuffer sbError = new StringBuffer("No optional '");
                sbError.append(ASelectProcessor.PARAM_LANGUAGE);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
            }
            else if (!LocaleValidator.validateLanguage(sLanguage))
            {
                StringBuffer sbError = new StringBuffer("Invalid '");
                sbError.append(ASelectProcessor.PARAM_LANGUAGE);
                sbError.append("' found in request: ");
                sbError.append(sLanguage);
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            else
            {
                StringBuffer sbError = new StringBuffer("Optional '");
                sbError.append(ASelectProcessor.PARAM_LANGUAGE);
                sbError.append("' found in request: ");
                sbError.append(sLanguage);
                _logger.debug(sbError.toString());
            }
            
            boolean bForcedLogon = false;
            String sForcedLogon = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_FORCED_LOGON);
            if (sForcedLogon == null)
            {
                StringBuffer sbError = new StringBuffer("No optional '");
                sbError.append(ASelectProcessor.PARAM_FORCED_LOGON);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
            }
            else if (sForcedLogon.equalsIgnoreCase("true"))
                bForcedLogon = true;
            else if (!sForcedLogon.equalsIgnoreCase("false"))
            {
                StringBuffer sbError = new StringBuffer("Invalid '");
                sbError.append(ASelectProcessor.PARAM_FORCED_LOGON);
                sbError.append(
                    "' found in request; the value must be TRUE or FALSE, but is: ");
                sbError.append(sForcedLogon);
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            else
            {
                StringBuffer sbError = new StringBuffer("Optional '");
                sbError.append(ASelectProcessor.PARAM_FORCED_LOGON);
                sbError.append("' found in request: ");
                sbError.append(sForcedLogon);
                _logger.debug(sbError.toString());
            }
            
            boolean bPassive = false;
            String sPassive = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_PASSIVE);
            if (sPassive == null)
            {
                StringBuffer sbError = new StringBuffer("No optional '");
                sbError.append(ASelectProcessor.PARAM_PASSIVE);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
            }
            else if (sPassive.equalsIgnoreCase("true"))
                bPassive = true;
            else if (!sPassive.equalsIgnoreCase("false"))
            {
                StringBuffer sbError = new StringBuffer("Invalid '");
                sbError.append(ASelectProcessor.PARAM_PASSIVE);
                sbError.append(
                    "' found in request; the value must be TRUE or FALSE, but is: ");
                sbError.append(sPassive);
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            else
            {
                StringBuffer sbDebug = new StringBuffer("Optional '");
                sbDebug.append(ASelectProcessor.PARAM_PASSIVE);
                sbDebug.append("' found in request: ");
                sbDebug.append(sPassive);
                _logger.debug(sbDebug.toString());
            }
            
            String sRemoteOrganization = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_REMOTE_ORGANIZATION);
            if (sRemoteOrganization != null)
            {
                StringBuffer sbError = new StringBuffer("Optional '");
                sbError.append(ASelectProcessor.PARAM_REMOTE_ORGANIZATION);
                sbError.append("' found in request: ");
                sbError.append(sRemoteOrganization);
                _logger.debug(sbError.toString());
            }
            
            IResponse oResponse = oBinding.getResponse();
            if (oResponse == null)
            {
                _logger.error("No response for request");
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
            }
            
            String sResultCode = ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR;
            try
            {
                if (!_OAServer.getID().equals(sASelectServer))
                {
                    StringBuffer sbError = new StringBuffer(
                        "The server ID doesn't correspond to the supplied '");
                    sbError.append(ASelectProcessor.PARAM_ASELECTSERVER);
                    sbError.append("' parameter: ");
                    sbError.append(sASelectServer);
                    _logger.debug(sbError.toString());
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                }
                
                IRequestor oRequestor = _requestorPoolFactory.getRequestor(sLocalIdp);
                if (oRequestor == null)
                {
                    StringBuffer sbError = new StringBuffer("Unknown '");
                    sbError.append(ASelectProcessor.PARAM_LOCAL_IDP);
                    sbError.append("' found in request: ");
                    sbError.append(sLocalIdp);
                    _logger.debug(sbError.toString());
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
                }
                
                if (!oRequestor.isEnabled())
                {
                    StringBuffer sbError = new StringBuffer("Disabled '");
                    sbError.append(ASelectProcessor.PARAM_LOCAL_IDP);
                    sbError.append("' found in request: ");
                    sbError.append(sLocalIdp);
                    _logger.debug(sbError.toString());
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
                }
                
                RequestorPool oRequestorPool = 
                    _requestorPoolFactory.getRequestorPool(oRequestor.getID());
                if (oRequestorPool == null)
                {
                    _logger.warn("Requestor not available in a pool: " 
                        + oRequestor.getID());
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                }
                
                if (!oRequestorPool.isEnabled())
                {
                    StringBuffer sbError = new StringBuffer("Requestor '");
                    sbError.append(sLocalIdp);
                    sbError.append("' is found in a disabled requestor pool: ");
                    sbError.append(oRequestorPool.getID());
                    _logger.warn(sbError.toString());
                    throw new ASelectException(ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                }
                
                ASelectRequestorPool oASRequestorPool = 
                    _htASelectRequestorPools.get(oRequestorPool.getID());
                if (doSigning(oRequestorPool, oASRequestorPool, oRequestor))
                {
                    String sSignature = (String)oRequest.getParameter(
                        ASelectProcessor.PARAM_SIGNATURE);
                    if (sSignature == null)
                    {
                        StringBuffer sbError = new StringBuffer("No '");
                        sbError.append(ASelectProcessor.PARAM_SIGNATURE);
                        sbError.append("' found in request");
                        _logger.debug(sbError.toString());
                        
                        throw new ASelectException(
                            ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                    }
                    
                    StringBuffer sbSignature = new StringBuffer(sASelectServer);
                    if (sCountry != null)
                        sbSignature.append(sCountry);
                    if (sForcedLogon != null)
                        sbSignature.append(sForcedLogon);
                    if (sLanguage != null)
                        sbSignature.append(sLanguage);
                   
                    sbSignature.append(sLocalIdpUrl).append(sLocalIdp);
                    
                    if (sPassive != null)
                        sbSignature.append(sPassive);
                    if (sRemoteOrganization != null)
                        sbSignature.append(sRemoteOrganization);
                    
                    sbSignature.append(sRequiredLevel);
                    
                    if (sUid != null)
                        sbSignature.append(sUid);
    
                    if (!verifySignature(sSignature, oRequestor.getID(), 
                        sbSignature.toString()))
                    {
                        _logger.error("Invalid signature for request from requestor with id: " 
                            + oRequestor.getID());
                        throw new ASelectException(
                            ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                    }
                }
            
                try
                {
                    new URL(sLocalIdpUrl);
                }
                catch (MalformedURLException e)
                {
                    StringBuffer sbError = new StringBuffer("The supplied '");
                    sbError.append(ASelectProcessor.PARAM_LOCAL_IDP_URL);
                    sbError.append("' parameter isn't a URL: ");
                    sbError.append(sLocalIdpUrl);
                    _logger.debug(sbError.toString(), e);
                    
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_SERVER_INVALID_APP_URL);
                }
            
                oSession = _sessionFactory.createSession(sLocalIdp);
                oSession.setForcedAuthentication(bForcedLogon);
                oSession.setPassive(bPassive);
                
                ISessionAttributes oAttributes = oSession.getAttributes();
                oAttributes.put(ASelectProcessor.class, 
                    ASelectProcessor.SESSION_REQUESTOR_URL, sLocalIdpUrl);
                
                //check required level value
                int iConfiguredAppLevel = _iDefaultAppLevel;
                if (oASRequestorPool != null)
                {
                    int iAppLevel = oASRequestorPool.getAppLevel();
                    if (iAppLevel > 0)
                        iConfiguredAppLevel = iAppLevel;
                }
                if (iRequiredLevel > iConfiguredAppLevel)
                {
                    //DD AuthNProfile filtering can be supported by adding a preauthZ method that changes the authNprofile subset
                    
                    StringBuffer sbWarn = new StringBuffer("Not supported required level (");
                    sbWarn.append(iRequiredLevel);
                    sbWarn.append(") from requestor with id: ");
                    sbWarn.append(oRequestor.getID());
                    _logger.warn(sbWarn.toString());
                    throw new ASelectException(ASelectErrors.ERROR_ASELECT_SERVER_INVALID_APP_LEVEL);
                }
                oAttributes.put(ProxyAttributes.class, ASelectProcessor.SESSION_REQUIRED_LEVEL, sRequiredLevel);
                
                //set supplied uid as forced user id
                if (sUid != null)
                    oSession.setForcedUserID(sUid);
                            
                if (sRemoteOrganization != null)
                {
                    //set supplied organization as forced organization
                    Collection<String> cOrganizations = new Vector<String>();
                    cOrganizations.add(sRemoteOrganization);
                    oAttributes.put(ProxyAttributes.class, 
                        ProxyAttributes.FORCED_ORGANIZATIONS, cOrganizations);
                }
                
                Locale oLocale = null;
                if (sLanguage != null)
                {
                    if(sCountry != null)
                        oLocale = new Locale(sLanguage, sCountry);
                    else
                        oLocale = new Locale(sLanguage);
                }
                else if (sCountry != null)
                    oLocale = new Locale(Locale.getDefault().getLanguage(), 
                        sCountry);

                //DD if the locale is specified by the requestor then force this locale
                oSession.setLocale(oLocale);
                
                String sAsUrl = _sRedirectURL;
                if (sAsUrl == null)
                    sAsUrl = oRequest.getRequestedURL();
                
                StringBuffer sbAsUrl = new StringBuffer(sAsUrl);
                sbAsUrl.append("?request=login1");
                
                oSession.persist();
    
                oResponse.setParameter(ASelectProcessor.PARAM_ASELECT_URL, 
                    sbAsUrl.toString());
                oResponse.setParameter(ASelectProcessor.PARAM_RID, 
                    oSession.getId());
                
                sResultCode = ASelectErrors.ERROR_ASELECT_SUCCESS;
            }
            catch (ASelectException e)
            {
                sResultCode = e.getMessage();
                
                if (sResultCode.equals(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST))
                    throw e;

                oLogItem = new RequestorEventLogItem(null, null, null, 
                    RequestorEvent.REQUEST_INVALID, null, 
                    oServletRequest.getRemoteAddr(), sLocalIdp, this, 
                    "request=authenticate: " + sResultCode);
            }
            
            oResponse.setParameter(ASelectProcessor.PARAM_RESULT_CODE, 
                sResultCode);
            oResponse.setParameter(ASelectProcessor.PARAM_ASELECTSERVER, 
                _OAServer.getID());

            if (oLogItem == null)
                oLogItem = new RequestorEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(), 
                    RequestorEvent.AUTHN_INITIATION_SUCCESSFUL, 
                    this, "request=authenticate: IDP");
            
            _eventLogger.info(oLogItem);
            
            oResponse.send();
        }
        catch (ASelectException e)
        {
            oLogItem = new RequestorEventLogItem(null, null, 
                null, RequestorEvent.REQUEST_INVALID, null, 
                oServletRequest.getRemoteAddr(), null, this, 
                "request=authenticate: " + e.getMessage());
            
            _eventLogger.info(oLogItem);
            throw e;
        }
        catch (OAException e)
        {
            if (oSession != null)
                oLogItem = new RequestorEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(), 
                    RequestorEvent.REQUEST_INVALID, this, 
                    "request=authenticate: " + e.getMessage());
            else
                oLogItem = new RequestorEventLogItem(null, null, 
                    null, RequestorEvent.REQUEST_INVALID, null, 
                    oServletRequest.getRemoteAddr(), null, this, 
                    "request=authenticate: " + e.getMessage());
            
            _eventLogger.info(oLogItem);
            throw new ASelectException(e.getMessage());
        }
        catch (Exception e)
        {
            if (oSession != null)
                oLogItem = new RequestorEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(), RequestorEvent.INTERNAL_ERROR, 
                    this, "request=authenticate");
            else
                oLogItem = new RequestorEventLogItem(null, null, 
                    null, RequestorEvent.INTERNAL_ERROR, null, 
                    oServletRequest.getRemoteAddr(), null, this, 
                    "request=authenticate");
            
            _eventLogger.info(oLogItem);
            _logger.fatal("Internal error during 'authenticate' process", e);
            throw new ASelectException(ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
        }
    }

    /**
     * Processes the <code>request=verify_credentials</code> API call.
     *
     * The request parameters that are supported:
     * <table border='1'>
     * <tr><th><i>parameter</i></th><th><i>value</i></th><th><i>optional?</i></th></tr>
     * <tr><td>request</td><td>verify_credentials</td><td>false</td></tr>
     * <tr><td>a-select-server</td><td>[a-select-server]</td><td>false</td></tr>
     * <tr><td>rid</td><td>[rid]</td><td>false</td></tr>
     * <tr><td>aselect_credentials</td><td>[aselect_credentials]</td><td>false</td></tr>
     * </table>
     * <br>
     * If the verify credentials succeeds, the response will contain the following parameters:
     * <table border='1'>
     * <tr><th><i>parameter</i></th><th><i>value</i></th><th><i>optional?</i></th></tr>
     * <tr><td>organization</td><td>[organization]</td><td>false</td></tr>
     * <tr><td>uid</td><td>[uid]</td><td>false</td></tr>
     * <tr><td>tgt_exp_time</td><td>[tgt_exp_time]</td><td>false</td></tr>
     * <tr><td>app_id</td><td>[app_id]</td><td>false</td></tr>
     * <tr><td>app_level</td><td>[app_level]</td><td>false</td></tr>
     * <tr><td>authsp</td><td>[authsp]</td><td>false</td></tr>
     * <tr><td>authsp_level</td><td>[authsp_level]</td><td>false</td></tr>
     * <tr><td>asp</td><td>[asp]</td><td>false</td></tr>
     * <tr><td>asp_level</td><td>[asp_level]</td><td>false</td></tr>
     * <tr><td>attributes</td><td>[attributes]</td><td>true</td></tr>
     * <tr><td>result_code</td><td>0000</td><td>false</td></tr>
     * <tr><td>local_organization</td><td>[local_organization]</td><td>true</td></tr>
     * <tr><td>a-select-server</td><td>[a-select-server]</td><td>false</td></tr>
     * </table>
     * <br>
     * If the verify credentials fails, the response will contain the following parameters:
     * <table border='1'>
     * <tr><th><i>parameter</i></th><th><i>value</i></th><th><i>optional?</i></th></tr>
     * <tr><td>result_code</td><td>[result_code]</td><td>false</td></tr>
     * <tr><td>a-select-server</td><td>[a-select-server]</td><td>false</td></tr>
     * </table>
     * @param oServletRequest HTTP servlet request object
     * @param oBinding The binding object
     * @throws ASelectException if request handling failed
     */
    public void verifyCredentials(HttpServletRequest oServletRequest, 
        IBinding oBinding) throws ASelectException
    {
        ISession oSession = null;
        AbstractEventLogItem oLogItem = null;
        
        try
        {
            IRequest oRequest = oBinding.getRequest();
            
            String sASelectServer = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_ASELECTSERVER);
            if (sASelectServer == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_ASELECTSERVER);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            String sRID = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_RID);
            if (sRID == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_RID);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            if(!SessionValidator.validateDefaultSessionId(sRID))
            {
                StringBuffer sbError = new StringBuffer("Invalid '");
                sbError.append(ASelectProcessor.PARAM_RID);
                sbError.append("' in request: ");
                sbError.append(sRID);
                _logger.warn(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            String sCredentials = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_ASELECT_CREDENTIALS);
            if (sCredentials == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_ASELECT_CREDENTIALS);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            if (!_OAServer.getID().equals(sASelectServer))
            {
                StringBuffer sbError = new StringBuffer(
                    "The server ID doesn't correspond to the supplied '");
                sbError.append(ASelectProcessor.PARAM_ASELECTSERVER);
                sbError.append("' parameter: ");
                sbError.append(sASelectServer);
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_ID_MISMATCH);
            }
            
            oSession = _sessionFactory.retrieve(sRID);
            if (oSession == null)
            {
                _logger.debug("No session found with id: " + sRID);
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            if (oSession.isExpired())
            {
                StringBuffer sbError = new StringBuffer("Expired session with id '");
                sbError.append(sRID);
                sbError.append("' found in request sent from IP: ");
                sbError.append(oServletRequest.getRemoteAddr());
                _logger.warn(sbError.toString());
                
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_SESSION_EXPIRED);
            }
            
            ISessionAttributes oAttributes = oSession.getAttributes();
            
            String sSessionCredentials = (String)oAttributes.get(
                ASelectProcessor.class, ASelectProcessor.SESSION_CREDENTIALS);
            if (sSessionCredentials == null)
            {
                _logger.debug("No session attribute found with with name: " + 
                    ASelectProcessor.SESSION_CREDENTIALS);
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
            }
            
            if (!sSessionCredentials.equals(sCredentials))
            {
                StringBuffer sbWarn = new StringBuffer("Credentials in session (");
                sbWarn.append(sSessionCredentials);
                sbWarn.append(") doesn't correspond to credentials in request: ");
                sbWarn.append(sCredentials);
                _logger.debug(sbWarn.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_TGT);
            }
            
            IResponse oResponse = oBinding.getResponse();
            String sResultCode = ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR;
            try
            {
                switch (oSession.getState())
                {
                    case AUTHN_OK:
                    {
                        IUser oUser = oSession.getUser();
                        if (oUser == null)
                        {
                            _logger.debug("No User found in session");
                            throw new ASelectException(
                                ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                        }
                        
                        RequestorPool oRequestorPool = 
                            _requestorPoolFactory.getRequestorPool(oSession.getRequestorId());
                        if (oRequestorPool == null)
                        {
                            _logger.debug("No Requestor Pool found for requestor id: " 
                                + oSession.getRequestorId());
                            throw new ASelectException(
                                ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                        }
                        
                        IRequestor oRequestor = _requestorPoolFactory.getRequestor(oSession.getRequestorId());
                        if (oRequestor == null)
                        {
                            _logger.debug("No Requestor found with id: " 
                                + oSession.getRequestorId());
                            throw new ASelectException(
                                ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                        }
                        
                        ASelectRequestorPool oASRequestorPool = 
                            _htASelectRequestorPools.get(oRequestorPool.getID());
                        
                        String sAppLevel = getAppLevel(oRequestorPool, 
                            oASRequestorPool, oRequestor);
 
                        if (doSigning(oRequestorPool, oASRequestorPool, oRequestor))
                        {
                            String sSignature = (String)oRequest.getParameter(
                                ASelectProcessor.PARAM_SIGNATURE);
                            String sLocalIdp = oRequestor.getID();
                            if (sSignature == null)
                            {
                                StringBuffer sbError = new StringBuffer("No '");
                                sbError.append(ASelectProcessor.PARAM_SIGNATURE);
                                sbError.append("' found in request");
                                _logger.debug(sbError.toString());
                                
                                throw new ASelectException(
                                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                            }
                                
                            StringBuffer sbSignature = new StringBuffer(
                                sASelectServer);
                            sbSignature.append(sCredentials);
                            sbSignature.append(sLocalIdp);
                            sbSignature.append(sRID);
                                
                            if (!verifySignature(sSignature, 
                                sLocalIdp, sbSignature.toString()))
                            {
                                _logger.error(
                                    "Invalid signature for request from requestor with id: " 
                                    + oRequestor.getID());
                                throw new ASelectException(
                                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                            }
                        }
                        
                        String sAuthNProfile = null;
                        
                        long lTGTExpireTime = 0; //DD TGT Expiration time is 0 when single sign-on disabled
                        ITGT oTGT = null;
                        String sTGTID = oSession.getTGTId();
                        if (sTGTID != null)
                        {
                            oTGT = _tgtFactory.retrieve(sTGTID);
                            if (oTGT == null)
                            {
                                _logger.warn("No TGT ID found in session");
                                throw new ASelectException(
                                    ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                            }
                            
                            lTGTExpireTime = oTGT.getTgtExpTime().getTime();
                            
                            sAuthNProfile = getHighestAuthNProfile(
                                oTGT.getAuthNProfileIDs());
                            
                            if (sAuthNProfile == null)
                            {
                                IAuthenticationProfile oAuthNProfile = 
                                    oSession.getSelectedAuthNProfile();
                                if (oAuthNProfile != null)
                                    sAuthNProfile = oAuthNProfile.getID();
                            }
                            
                            if (sAuthNProfile == null)
                                sAuthNProfile = oTGT.getAuthNProfileIDs().get(0);
                        }
                        else
                        {
                            IAuthenticationProfile oAuthNProfile = 
                                oSession.getSelectedAuthNProfile();
                            if (oAuthNProfile == null)
                            {
                                _logger.warn("No authentication profile found in Session");
                                throw new ASelectException(
                                    ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                            }
                            
                            sAuthNProfile = oAuthNProfile.getID();
                        }
                                                
                        Integer intAuthSPLevel = getAuthSPLevel(sAuthNProfile);
                        
                        String sUid = null;
                        try
                        {
                            sUid = getUid(oUser, oASRequestorPool, 
                                oRequestorPool, oRequestor);
                        }
                        catch (ASelectException e)
                        {
                            if (oTGT != null)
                            {
                                oTGT.removeRequestorID(oRequestor.getID());
                                _aliasStoreSPRole.removeAlias(
                                    BrowserHandler.ALIAS_TYPE_CREDENTIALS, 
                                    oRequestor.getID(), sCredentials);
                                
                                if (oTGT.getRequestorIDs().size() == 0)
                                {
                                    oTGT.expire();
                                    oTGT.persist();
                                }
                            }
                            
                            throw e;
                        }
                        
                        String sAttributes = null;
                        
                        IAttributes attributes = oUser.getAttributes();
                        if (attributes != null && attributes.size() > 0)
                            sAttributes = serializeAttributes(attributes);
                        
                        oResponse = oBinding.getResponse();
                        oResponse.setParameter(
                            ASelectProcessor.PARAM_ORGANIZATION, 
                            oUser.getOrganization());    
                        oResponse.setParameter(
                            ASelectProcessor.PARAM_UID, sUid); 
                        oResponse.setParameter(
                            ASelectProcessor.PARAM_TGT_EXP_TIME, 
                            String.valueOf(lTGTExpireTime));
                        oResponse.setParameter(
                            ASelectProcessor.PARAM_APP_LEVEL, sAppLevel);
                        oResponse.setParameter(
                            ASelectProcessor.PARAM_AUTHSP, sAuthNProfile);
                        oResponse.setParameter(
                            ASelectProcessor.PARAM_ASP, sAuthNProfile);
                        oResponse.setParameter(
                            ASelectProcessor.PARAM_AUTHSP_LEVEL, 
                            String.valueOf(intAuthSPLevel));
                        oResponse.setParameter(
                            ASelectProcessor.PARAM_ASP_LEVEL, 
                            String.valueOf(intAuthSPLevel));
                        
                        if (sAttributes != null)
                            oResponse.setParameter(
                                ASelectProcessor.PARAM_ATTRIBUTES, sAttributes);
                        
                        sResultCode = ASelectErrors.ERROR_ASELECT_SUCCESS;
                        
                        break;
                    }
                    case USER_CANCELLED:
                    {
                        sResultCode = ASelectErrors.ERROR_ASELECT_SERVER_CANCEL;
                        break;
                    }
                    case AUTHN_FAILED:
                    {
                        sResultCode = 
                            ASelectErrors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;
                        break;
                    }
                    case PRE_AUTHZ_FAILED:
                    {
                        sResultCode = 
                            ASelectErrors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER;
                        break;
                    }
                    case AUTHN_SELECTION_FAILED:
                    {
                        sResultCode = 
                            ASelectErrors.ERROR_ASELECT_AUTHSP_COULD_NOT_AUTHENTICATE_USER; 
                        break;
                    }
                    case USER_BLOCKED:
                    {
                        sResultCode = 
                            ASelectErrors.ERROR_USER_BLOCKED;
                        break;
                    }
                    case USER_UNKNOWN:
                    {
                        sResultCode = 
                            ASelectErrors.ERROR_ASELECT_UDB_UNKNOWN_USER;
                        break;
                    }
                    case PASSIVE_FAILED:
                    {
                        sResultCode = 
                            ASelectErrors.ERROR_PASSIVE_FAILED;
                        break;
                    }
                    default:
                    {
                        sResultCode = 
                            ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR;
                        break;
                    }
                }
            }
            catch (ASelectException e)
            {
                sResultCode = e.getMessage();
                if (sResultCode.equals(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST))
                    throw e;
                
                oLogItem = new RequestorEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(), 
                    RequestorEvent.TOKEN_DEREFERENCE_SUCCESSFUL, 
                    this, "request=verify_credentials: IDP");
            }
            oResponse.setParameter(ASelectProcessor.PARAM_RESULT_CODE, 
                sResultCode);
            oResponse.setParameter(ASelectProcessor.PARAM_ASELECTSERVER, 
                _OAServer.getID());

            if (oLogItem == null)
                oLogItem = new RequestorEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(), 
                    RequestorEvent.TOKEN_DEREFERENCE_SUCCESSFUL,
                    this, "request=verify_credentials: IDP");
            
            _eventLogger.info(oLogItem);
            
            _logger.debug("Remove session id: " + sRID);
            oSession.expire();
            oSession.persist();
            
            oResponse.send();
            
            StringBuffer sbDebug = new StringBuffer(
                "Send verify_credentials response with '");
            sbDebug.append(ASelectProcessor.PARAM_RESULT_CODE);
            sbDebug.append("': ");
            sbDebug.append(sResultCode);
            _logger.debug(sbDebug.toString());
        }
        catch (ASelectException e)
        {
            if (oSession != null)
                oLogItem = new RequestorEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(), 
                    RequestorEvent.REQUEST_INVALID, this, 
                    "request=verify_credentials: " + e.getMessage());
            else
                oLogItem = new RequestorEventLogItem(null, null, 
                    null, RequestorEvent.REQUEST_INVALID, null, 
                    oServletRequest.getRemoteAddr(), null, this, 
                    "request=verify_credentials: " + e.getMessage());
            _eventLogger.info(oLogItem);
            
            throw e;
        }
        catch (Exception e)
        {
            if (oSession != null)
                oLogItem = new RequestorEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(), 
                    RequestorEvent.INTERNAL_ERROR, this, 
                    "request=verify_credentials");
            else
                oLogItem = new RequestorEventLogItem(null, null, 
                    null, RequestorEvent.INTERNAL_ERROR, null, 
                    oServletRequest.getRemoteAddr(), null, this, 
                    "request=verify_credentials");
            _eventLogger.info(oLogItem);
            
            _logger.fatal(
                "Internal error during 'verify_crendentials' process", e);
            throw new ASelectException(
                ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
        }
    }
    
    
    /**
     * Processes the <code>request=slo</code> API call.
     *
     * The request parameters that are supported:
     * <table border='1'>
     * <tr><th><i>parameter</i></th><th><i>value</i></th><th><i>optional?</i></th></tr>
     * <tr><td>request</td><td>logout</td><td>false</td></tr>
     * <tr><td>a-select-server</td><td>[a-select-server]</td><td>false</td></tr>
     * <tr><td>app_id</td><td>[app_id]</td><td>false</td></tr>
     * <tr><td>app_url</td><td>[app_url]</td><td>false</td></tr>
     * <tr><td>signature</td><td>[signature]</td><td>true</td></tr>
     * </table>
     * 
     * @param oServletRequest HTTP servlet request object
     * @param oBinding The binding object
     * @throws ASelectException if request handling failed
     * @since 1.4
     */
    public void slo(HttpServletRequest oServletRequest, 
        IBinding oBinding) throws ASelectException
    {
        ISession oSession = null;
        AbstractEventLogItem oLogItem = null;
        try
        {
            IRequest oRequest = oBinding.getRequest();
            
            String sASelectServer = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_ASELECTSERVER);
            if (sASelectServer == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_ASELECTSERVER);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            String sLocalIdp = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_LOCAL_IDP);
            if (sLocalIdp == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_LOCAL_IDP);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            String sLocalIdpUrl = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_LOCAL_IDP_URL);
            if (sLocalIdpUrl == null)
            {//DD idp calls require the local_as_url otherwise the user will not be loggout out at the requestor
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_LOCAL_IDP_URL);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            String sCredentials = (String)oRequest.getParameter(
                ASelectProcessor.PARAM_ASELECT_CREDENTIALS);
            if (sCredentials == null)
            {
                StringBuffer sbError = new StringBuffer("No '");
                sbError.append(ASelectProcessor.PARAM_ASELECT_CREDENTIALS);
                sbError.append("' found in request");
                _logger.debug(sbError.toString());
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
            }
            
            IResponse oResponse = oBinding.getResponse();
            if (oResponse == null)
            {
                _logger.error("No response for request");
                throw new ASelectException(
                    ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
            }
            
            String sResultCode = ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR;
            try
            {
                if (!_OAServer.getID().equals(sASelectServer))
                {
                    StringBuffer sbError = new StringBuffer(
                        "The server ID doesn't correspond to the supplied '");
                    sbError.append(ASelectProcessor.PARAM_ASELECTSERVER);
                    sbError.append("' parameter: ");
                    sbError.append(sASelectServer);
                    _logger.debug(sbError.toString());
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_SERVER_ID_MISMATCH);
                }
                
                IRequestor oRequestor = _requestorPoolFactory.getRequestor(sLocalIdp);
                if (oRequestor == null)
                {
                    StringBuffer sbError = new StringBuffer("Unknown '");
                    sbError.append(ASelectProcessor.PARAM_LOCAL_IDP);
                    sbError.append("' found in request: ");
                    sbError.append(sLocalIdp);
                    _logger.debug(sbError.toString());
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
                }
                
                if (!oRequestor.isEnabled())
                {
                    StringBuffer sbError = new StringBuffer("Disabled '");
                    sbError.append(ASelectProcessor.PARAM_LOCAL_IDP);
                    sbError.append("' found in request: ");
                    sbError.append(sLocalIdp);
                    _logger.debug(sbError.toString());
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_APP);
                }
                
                RequestorPool oRequestorPool = 
                    _requestorPoolFactory.getRequestorPool(oRequestor.getID());
                if (oRequestorPool == null)
                {
                    _logger.warn("Requestor not available in a pool: " 
                        + oRequestor.getID());
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                }
                
                if (!oRequestorPool.isEnabled())
                {
                    StringBuffer sbError = new StringBuffer("Requestor '");
                    sbError.append(sLocalIdp);
                    sbError.append("' is found in a disabled requestor pool: ");
                    sbError.append(oRequestorPool.getID());
                    _logger.warn(sbError.toString());
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
                }
                
                ASelectRequestorPool oASRequestorPool = _htASelectRequestorPools.get(oRequestorPool.getID());
                if (doSigning(oRequestorPool, oASRequestorPool, oRequestor))
                {
                    String sSignature = (String)oRequest.getParameter(
                        ASelectProcessor.PARAM_SIGNATURE);
                    if (sSignature == null)
                    {
                        StringBuffer sbError = new StringBuffer("No '");
                        sbError.append(ASelectProcessor.PARAM_SIGNATURE);
                        sbError.append("' found in request");
                        _logger.debug(sbError.toString());
                        
                        throw new ASelectException(
                            ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                    }
                    
                    Hashtable<String,String> htSignatureData = new Hashtable<String,String>();
                    htSignatureData.put(ASelectProcessor.PARAM_ASELECTSERVER, sASelectServer);
                    htSignatureData.put(ASelectProcessor.PARAM_ASELECT_CREDENTIALS, sCredentials);
                    htSignatureData.put(ASelectProcessor.PARAM_LOCAL_IDP_URL, sLocalIdpUrl);
                    htSignatureData.put(ASelectProcessor.PARAM_LOCAL_IDP, sLocalIdp);
                    if (!verifySignature(sSignature, oRequestor.getID(), 
                        htSignatureData))
                    {
                        _logger.error(
                            "Invalid signature for request from requestor with id: " 
                            + oRequestor.getID());
                        throw new ASelectException(
                            ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST);
                    }
                }
                
                if (!_aliasStoreSPRole.isAlias(
                    BrowserHandler.ALIAS_TYPE_CREDENTIALS, sLocalIdp, sCredentials))
                {
                    _logger.debug("Unknown credentials supplied in request: " + sCredentials);
                    throw new ASelectException(ASelectErrors.ERROR_ASELECT_SERVER_UNKNOWN_TGT);
                }
                
                try
                {
                    new URL(sLocalIdpUrl);
                }
                catch (MalformedURLException e)
                {
                    StringBuffer sbError = new StringBuffer("The supplied '");
                    sbError.append(ASelectProcessor.PARAM_LOCAL_IDP_URL);
                    sbError.append("' parameter isn't an URL: ");
                    sbError.append(sLocalIdpUrl);
                    _logger.debug(sbError.toString(), e);
                    
                    throw new ASelectException(
                        ASelectErrors.ERROR_ASELECT_SERVER_INVALID_APP_URL);
                }
                
                String sAsUrl = _sRedirectURL;
                if (sAsUrl == null)
                    sAsUrl = oRequest.getRequestedURL();
                
                oSession = _sessionFactory.createSession(sLocalIdp);
                
                //set all the attributes needed for the verify credentials handling
                ISessionAttributes oAttributes = oSession.getAttributes();
                oAttributes.put(ASelectProcessor.class, 
                    ASelectProcessor.SESSION_REQUESTOR_URL, sLocalIdpUrl);
                
                oSession.persist();
                
                StringBuffer sbAsUrl = new StringBuffer(sAsUrl);
                sbAsUrl.append("?request=logout");
                oResponse.setParameter(ASelectProcessor.PARAM_ASELECT_URL, 
                    sbAsUrl.toString());
                oResponse.setParameter(ASelectProcessor.PARAM_RID, 
                    oSession.getId());
                
                sResultCode = ASelectErrors.ERROR_ASELECT_SUCCESS;
            }
            catch (ASelectException e)
            {
                sResultCode = e.getMessage();
                
                if (sResultCode.equals(
                    ASelectErrors.ERROR_ASELECT_SERVER_INVALID_REQUEST))
                    throw e;

                oLogItem = new RequestorEventLogItem(null, null, null, 
                    RequestorEvent.REQUEST_INVALID, null, 
                    oServletRequest.getRemoteAddr(), 
                    sLocalIdp, this, "request=slo: " + sResultCode);
            }
            
            oResponse.setParameter(ASelectProcessor.PARAM_RESULT_CODE, 
                sResultCode);
            oResponse.setParameter(ASelectProcessor.PARAM_ASELECTSERVER, 
                _OAServer.getID());

            if (oLogItem == null)
                oLogItem = new RequestorEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(), 
                    RequestorEvent.LOGOUT_INITIATION_SUCCESSFUL, this, 
                    "request=slo: IDP");
            
            _eventLogger.info(oLogItem);
            
            oResponse.send();
        }
        catch (ASelectException e)
        {
            oLogItem = new RequestorEventLogItem(null, null, 
                null, RequestorEvent.REQUEST_INVALID, null, 
                oServletRequest.getRemoteAddr(), null, this, 
                "request=slo: " + e.getMessage());
            
            _eventLogger.info(oLogItem);
            
            throw e;
        }
        catch (OAException e)
        {
            if (oSession != null)
                oLogItem = new RequestorEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(), 
                    RequestorEvent.REQUEST_INVALID, this, 
                    "request=slo: " + e.getMessage());
            else
                oLogItem = new RequestorEventLogItem(null, null, 
                    null, RequestorEvent.REQUEST_INVALID, null, 
                    oServletRequest.getRemoteAddr(), null, this, 
                    "request=slo: " + e.getMessage());
            _eventLogger.info(oLogItem);
            
            throw new ASelectException(e.getMessage());
        }
        catch (Exception e)
        {
            if (oSession != null)
                oLogItem = new RequestorEventLogItem(oSession, 
                    oServletRequest.getRemoteAddr(), 
                    RequestorEvent.INTERNAL_ERROR, this, "request=slo");
            else
                oLogItem = new RequestorEventLogItem(null, null, 
                    null, RequestorEvent.INTERNAL_ERROR, null, 
                    oServletRequest.getRemoteAddr(), null, this, 
                    "request=slo");
            _eventLogger.info(oLogItem);
            
            _logger.fatal("Internal error during 'slo' process", e);
            throw new ASelectException(
                ASelectErrors.ERROR_ASELECT_INTERNAL_ERROR);
        }
    }

}
