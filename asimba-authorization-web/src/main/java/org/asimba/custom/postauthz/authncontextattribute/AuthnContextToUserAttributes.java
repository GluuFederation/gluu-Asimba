package org.asimba.custom.postauthz.authncontextattribute;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.UserEvent;
import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.attribute.ITGTAttributes;
import com.alfaariss.oa.api.authentication.IAuthenticationContext;
import com.alfaariss.oa.api.authentication.IAuthenticationContexts;
import com.alfaariss.oa.api.authorization.IAuthorizationAction;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.tgt.ITGT;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.authentication.AuthenticationContexts;
import com.alfaariss.oa.sso.authorization.web.IWebAuthorizationMethod;

/**
 * PostAuthorization module that takes attributes from the Authentication Context
 * and moves them to the User Attributes
 * 
 * Also does some authorization, as in that Authentiction Context attributes may be required
 * for an authentication to be valid. This is configurable.
 * 
 * @author mdobrinic, for GLUU
 *
 */
public class AuthnContextToUserAttributes implements IWebAuthorizationMethod {

	/** Local logger instance */
	private Log _oLogger = LogFactory.getLog(AuthnContextToUserAttributes.class);

	public static final String EL_ENABLED = "enabled";
	public static final String EL_ID = "id";
	public static final String EL_FRIENDLYNAME= "friendlyname";
	public static final String EL_ATTRIBUTES = "attributes";
	public static final String EL_ATTRIBUTE = "attribute";

	private String _sID;
	private String _sFriendlyname;
	private boolean _enabled;
	
	private List<ACAttribute> _lConfiguredAttributes;


	public String getID() {
		return _sID;
	}

	public String getFriendlyName() {
		return _sFriendlyname;
	}

	public boolean isEnabled() {
		return _enabled;
	}

	public String getAuthority() {
		// TODO Auto-generated method stub
		return null;
	}

	public UserEvent authorize(HttpServletRequest oRequest,
			HttpServletResponse oResponse, ISession oSession)
					throws OAException {

		if (! _enabled) {
			_oLogger.debug("AuthnContextToUserAttributes '"+_sID+"' was disabled; skipping.");
			return UserEvent.AUTHZ_METHOD_SUCCESSFUL;
		}
		
		if (_lConfiguredAttributes == null) {
			_oLogger.debug("No AuthnContext attributes processed.");
			return UserEvent.AUTHZ_METHOD_SUCCESSFUL;
		}

		//// Lookup AuthenticationContexts from Session:
		IAuthenticationContexts oAuthenticationContexts = 
				(IAuthenticationContexts) oSession.getAttributes().get(AuthenticationContexts.class, AuthenticationContexts.ATTR_AUTHCONTEXTS);

		if (oAuthenticationContexts == null) {
			_oLogger.debug("Trying to get AuthenticationContexts from TGT ...");
			
			String sTGTID = oSession.getTGTId();
			if (sTGTID != null) {
				Engine oEngine = Engine.getInstance();
				
				ITGT oTGT = oEngine.getTGTFactory().retrieve(sTGTID);
				
				if (oTGT != null) {
					ITGTAttributes oTGTAttributes = oTGT.getAttributes();
					oAuthenticationContexts = 
							(IAuthenticationContexts) oTGTAttributes.get(AuthenticationContexts.class, AuthenticationContexts.ATTR_AUTHCONTEXTS);
				}
				
			} else {
				_oLogger.warn("Could not find TGT for Session, so no AuthenticationContext was resolved!");
			}
		}
		
		if (oAuthenticationContexts == null) _oLogger.warn("No AuthenticationContext was resolved - will fail on required attributes!");

		IUser oUser = oSession.getUser();
		IAttributes oUserAttributes = oUser.getAttributes();
		
		for(ACAttribute o: _lConfiguredAttributes) {
			String val = getAttributeValue(o, oAuthenticationContexts);
			if (val != null) {
				oUserAttributes.put(o.getDest(), val);
			} else {
				_oLogger.debug("No value established for "+o.getAuthnMethodID()+":"+o.getSrc());
				if (o.isRequired()) {
					_oLogger.info("Failing Authorization because attribute '"+o.getSrc()+"' is required.");
					return UserEvent.AUTHZ_METHOD_FAILED;
				}
			}
		}

		return UserEvent.AUTHZ_METHOD_SUCCESSFUL;
	}

	
	public void start(IConfigurationManager oConfigurationManager,
			Element eConfig, Map<String, IAuthorizationAction> mapActions)
					throws OAException {

		_oLogger.trace("start() called.");

		_enabled = true;
        String sEnabled = oConfigurationManager.getParam(eConfig, EL_ENABLED);
        if (sEnabled != null) {
            _enabled = Boolean.valueOf(sEnabled);
        }
        
        _sID = oConfigurationManager.getParam(eConfig, EL_ID);
        if (_sID == null || "".equals(_sID)) {
            _oLogger.error("No '"+EL_ID+"' found for authorization method");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
         }
        
        _sFriendlyname = oConfigurationManager.getParam(eConfig, EL_FRIENDLYNAME);
        if (_sFriendlyname == null) {
            _oLogger.error("No '"+EL_FRIENDLYNAME+"' found for authorization method");
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
		
		_lConfiguredAttributes = null;

		if (_enabled) {
			Element eAttributes = oConfigurationManager.getSection(eConfig, EL_ATTRIBUTES);
			if (eAttributes == null) {
				_oLogger.info("No attributes configured for AuthnContextToUserAttributes: no processing.");
				return;
			}
	
			readAttributes(oConfigurationManager, eAttributes);
		}

		_oLogger.info("Initialized AuthnContextToUserAttributes (enabled: "+_enabled+")");
	}

	public void stop() {
		_oLogger.trace("stop() called.");
		_lConfiguredAttributes.clear();
	}


	private void readAttributes(IConfigurationManager oConfigurationManager, Element eAttributesConfig) throws OAException
	{
		_lConfiguredAttributes = new ArrayList<ACAttribute>();
		
		Element eAttribute = oConfigurationManager.getSection(eAttributesConfig, EL_ATTRIBUTE);
    	while (eAttribute != null)
    	{
    		ACAttribute oConfiguredAttribute = ACAttribute.fromConfig(oConfigurationManager, eAttribute);
    		if (oConfiguredAttribute == null) {
    			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
    		}
    		
    		_lConfiguredAttributes.add(oConfiguredAttribute);
    		
    		eAttribute = oConfigurationManager.getNextSection(eAttribute);
    	}
	}
	
	
	/**
	 * 
	 * @param oConfiguredAttribute
	 * @param oAuthenticationContexts
	 * @return value, or null when no value could be established
	 */
	private String getAttributeValue(ACAttribute oConfiguredAttribute, 
			IAuthenticationContexts oAuthenticationContexts)
	{
		if (oAuthenticationContexts == null) {
			if (oConfiguredAttribute.isRequired()) { 
				return null;
			} else {
				return oConfiguredAttribute.getDefault();
			}
		}
		
		IAuthenticationContext oAuthenticationContext = 
				oAuthenticationContexts.getAuthenticationContext(oConfiguredAttribute.getAuthnMethodID());
		
		if (oAuthenticationContext == null) {
			if (oConfiguredAttribute.isRequired()) { 
				return null;
			} else {
				return oConfiguredAttribute.getDefault();
			}
		}
		
		String value = (String) oAuthenticationContext.get(oConfiguredAttribute.getSrc());
		
		if (value == null) {
			value = oConfiguredAttribute.getDefault();	// if not set, this will also be null
		}
		
		return value;
	}
}
