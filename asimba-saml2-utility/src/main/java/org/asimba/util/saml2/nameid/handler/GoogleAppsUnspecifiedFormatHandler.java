/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
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
package org.asimba.util.saml2.nameid.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.session.ISession;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.util.saml2.NameIDFormatter;

/**
 * GoogleAppsUnspecifiedFormatHandler implements an example of a custom
 * unspecified NameIDFormat handler, that is used to provide an attribute-based
 * NameID value to GoogleApps SP's, and a Persistent Identifier NameID value to
 * all other SP's 
 * 
 * A GoogleApps SP is recognized based on a Requestor Property, which must be set
 * to a non-null value; there can also be a Requestor-specific property set with
 * the name of the attribute that must be used as NameID-value; when this is not set,
 * the attributename of the googleapps_attribute-value is used. 
 * 
 * Note: the attribute must exists in the User's attributes, so it must be made
 *   available through the AttributeReleasePolicy!
 * 
 * Example configuration:
 * <format type="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
 * 		class="org.asimba.util.saml2.nameid.handler.GoogleAppsUnspecifiedFormatHandler">
 *   <!-- Specific Attribute configuration -->
 *   <selector_property name="saml2.nameid.unspecified11" value="" />
 *   <attribute_property name="saml2.nameid.arg.attributename" />
 *   <googleapps_attribute name="_uid" removeAfterUse="true" />
 *   
 *   <!-- Default fallback configuration (ref: DefaultPersistent...) -->
 *   <opaque enabled="true" salt="toomuchisbadforyou" />
 *   <attribute name="_theNormalUID" removeAfterUse="true" />
 * </format>
 * 
 * A requestor must have the property set for the ProfileID scope, i.e.
 *   When handling a request to a profile on url "/asimba-wa/profiles/saml2", 
 *   the property "saml2.nameid.arg.unspecified" must be set to _some_ value
 * Or when using XML-configured Requestors, configure the Requestor like:
 * <requestor id="google.com/a/domain.com" friendlyname="GoogleApps SP on primary domain" enabled="true">
 *   <properties>
 *     <property name="saml2.nameid.unspecified11" value="" />
 *     <property name="saml2.nameid.arg.attributename" value="_uid" />
 *   </properties>
 * </requestor>
 * 
 * 
 * @author mdobrinic
 */
public class GoogleAppsUnspecifiedFormatHandler extends DefaultUnspecifiedFormatHandler {
	
	/**
	 * configuration element names
	 */
	public static final String EL_GAPPS_ATTRIBUTE = "googleapps_attribute";
	public static final String EL_ATTR_GAPPS_NAME = "name";
	public static final String EL_ATTR_GAPPS_REMOVE = "removeAfterUse";	// default: true
	
	public static final String EL_SELECTOR_PROPERTY = "selector_property";
	public static final String EL_ATTRIBUTE_PROPERTY = "attribute_property";
	public static final String EL_ATTR_PROPNAME = "name";
	public static final String EL_ATTR_PROPVALUE = "value";

	/**
	 * Local logger instance
	 */
    private static final Log _oLogger = LogFactory.getLog(GoogleAppsUnspecifiedFormatHandler.class);

    /**
     * Name of the Requestor Property that must be set to enable this specific attribute 
     *   NameID handling
     */
	protected String _sRequestorPropertySelector = "saml2.nameid.unspecified11";
	
	/**
	 * Value that the RequestorProperty must be set to, to activate attribute NameID handling
	 *   When this is not explicitly set (ReqPropVal=null), the value of the property must be non-null
	 * Default: null
	 */
	protected String _sRequestorPropertyValue = null;
	
	/**
	 * Property that configures the User-attribute to use as NameID-value for the particular SP
	 * When omitted, the value from the global googleapps_attribute is used
	 */
	protected String _sRequestorPropertyAttribute = null;
    
    /**
     * Name of the User Attribute that is used as GoogleApps UID when
     * the Requestor is established as GoogleApps SP
     * Default: '_uid'
     */
    protected String _sGAppsAttributeName = "_uid";

	
    /**
     * Remove the attribute from the user's attribute-set when it was used
     * Default: true
     */
    protected boolean _bGAppsRemoveAfterUse = true;
	
	
	public String format(IUser oUser, String sEntityID, String sTGTID,
			ISession oSession) throws OAException 
	{
		// Get the property to establish how to behave:
		IRequestor oRequestor = 
				Engine.getInstance().getRequestorPoolFactory().getRequestor(sEntityID);
		String sPropertyValue = (String) oRequestor.getProperty(_sRequestorPropertySelector);
				
		String sUserAttributeName = (String) oRequestor.getProperty(_sRequestorPropertyAttribute);
		if (sUserAttributeName == null) {
			sUserAttributeName = _sGAppsAttributeName;
		}

		String sResult = null;
		
		// Do we need to do our own handling?
		if ((_sRequestorPropertyValue == null && sPropertyValue != null) ||
				(_sRequestorPropertyValue != null) && sPropertyValue.equalsIgnoreCase(_sRequestorPropertyValue))
		{
			sResult = getUserAttributeValue(oUser, sUserAttributeName, _bGAppsRemoveAfterUse);
			_oLogger.info("GoogleApps Requestor '"+sEntityID+"'; NameID established as "+sResult);
		}
		else {
			// Attribute did not get used, but see if we still need to remove it:
			if (_bGAppsRemoveAfterUse) {
				oUser.getAttributes().remove(sUserAttributeName);	// does this do anything???
			}
			
			sResult = super.format(oUser, sEntityID, sTGTID, oSession);
			_oLogger.info("Non GoogleApps Requestor '"+sEntityID+"'; NameID established as "+sResult);
		}
		
		return sResult;
	}

	
	@Override
	public void reformat(IUser oUser, String sEntityID, String sTGTID, 
			ISession oSession) throws OAException 
	{
		IRequestor oRequestor = 
				Engine.getInstance().getRequestorPoolFactory().getRequestor(sEntityID);
		String sPropertyValue = (String) oRequestor.getProperty(_sRequestorPropertySelector);
				
		String sUserAttributeName = (String) oRequestor.getProperty(_sRequestorPropertyAttribute);
		if (sUserAttributeName == null) {
			sUserAttributeName = _sGAppsAttributeName;
		}
		
		if ((_sRequestorPropertyValue == null && sPropertyValue != null) ||
				(_sRequestorPropertyValue != null) && sPropertyValue.equalsIgnoreCase(_sRequestorPropertyValue))
		{
			if (_bGAppsRemoveAfterUse) {
				oUser.getAttributes().remove(sUserAttributeName);
			}
		}
		else {
			// Attribute did not get used, but see if we still need to remove it:
			if (_bGAppsRemoveAfterUse) {
				oUser.getAttributes().remove(sUserAttributeName);	// does this do anything???
			}
			
			super.reformat(oUser, sEntityID, sTGTID, oSession);
		}
	}

	
	public void init(IConfigurationManager oConfigManager, Element elConfig,
			NameIDFormatter oParentFormatter) throws OAException 
	{
		super.init(oConfigManager, elConfig, oParentFormatter);
		
		// Also, initialize our own properties:
		Element elGAppsAttribute = oConfigManager.getSection(elConfig, EL_GAPPS_ATTRIBUTE);
		if (elGAppsAttribute == null) {
			_oLogger.error("Optional " + EL_GAPPS_ATTRIBUTE+" element is not configured.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		} else {
			String sName = oConfigManager.getParam(elGAppsAttribute, EL_ATTR_GAPPS_NAME);
			if (sName == null) {
				_oLogger.error("Optional " + EL_ATTRIBUTE+"@"+EL_ATTR_NAME+" is not configured, using default.");
				_sGAppsAttributeName = "_uid";
			} else {
				_sGAppsAttributeName = sName;
			}
			
			String sRAU = oConfigManager.getParam(elGAppsAttribute, EL_ATTR_GAPPS_REMOVE);
			if ("TRUE".equalsIgnoreCase(sRAU)) {
				_bGAppsRemoveAfterUse = true;
			} else if (!"FALSE".equalsIgnoreCase(sRAU)) {
				_oLogger.warn("Invalid value for "+EL_GAPPS_ATTRIBUTE+"@"+EL_ATTR_GAPPS_REMOVE+": "+sRAU);
			}
		}
		
		_oLogger.info("GoogleApps Attributename set to "+_sAttributeName+"; the value "+
				(_bGAppsRemoveAfterUse?"WILL":"WILL NOT")+" be removed after use.");
		
		Element elReqProperty = oConfigManager.getSection(elConfig, EL_SELECTOR_PROPERTY);
		if (elReqProperty != null) {
			String sPropName = oConfigManager.getParam(elReqProperty, EL_ATTR_PROPNAME);
			if (sPropName == null) {
				_oLogger.info(EL_SELECTOR_PROPERTY+"@"+EL_ATTR_PROPNAME+" was not explicitly configured, using default.");
			} else {
				_sRequestorPropertySelector = sPropName;
			}
			
			_sRequestorPropertyValue = oConfigManager.getParam(elReqProperty, EL_ATTR_PROPVALUE);
			if ("".equals(_sRequestorPropertySelector)) _sRequestorPropertyValue = null;
			
		}
		_oLogger.info("Using property name '"+_sRequestorPropertySelector+"' and value "+
				(_sRequestorPropertyValue==null?"[non-null-value]":_sRequestorPropertyValue));

		Element elReqPropertyAttr = oConfigManager.getSection(elConfig, EL_ATTRIBUTE_PROPERTY);
		if (elReqPropertyAttr != null) {
			String sPropName = oConfigManager.getParam(elReqPropertyAttr, EL_ATTR_PROPNAME);
			if (sPropName == null) {
				_oLogger.info(EL_ATTRIBUTE_PROPERTY+"@"+EL_ATTR_PROPNAME+" was not explicitly configured, using"+
						" global setting: '"+_sAttributeName+"'");
			} else {
				_sRequestorPropertyAttribute = sPropName;
			}
		}
	}
}
