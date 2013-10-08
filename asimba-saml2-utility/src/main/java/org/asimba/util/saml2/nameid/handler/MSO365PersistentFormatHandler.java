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

import java.util.Locale;

import org.apache.commons.codec.digest.DigestUtils;
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
 * MSO365PersistentHandler implements an example of a custom
 * unspecified NameIDFormat handler, that is used to provide a
 * predictable or specific value as NameId value when the
 * requestor is Microsoft Office 365.
 * 
 * More information about the problem analysis is available
 * on the Asimba Wiki's.
 * 
 * Microsoft Office 365 is recognized by the EntityId of the
 * Requestor; this is default "urn:federation:MicrosoftOnline" but is configurable
 *
 * When the requestor is _not_ Microsoft Office 365, the default Persistent
 * NameId generation process is performed.
 *  
 * Otherwise, if a user-attribute mso365immutableid (configurable) is available, 
 * this value is used as NameId value
 * 
 * Otherwise, the value for NameId is calculated as:
 * 		uppercase( base64enc( sha1( [some-attribute ) ) )
 * 
 * where some-attribute is configurable, defaulting to "uid"
 * 
 * 
 * Note: the attribute must exists in the User's attributes, so it must be made
 *   available through the AttributeReleasePolicy!
 * 
 * Example configuration:
 * <format type="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
 * 		class="org.asimba.util.saml2.nameid.handler.MSO365PersistentFormatHandler">
 *   <!-- Optional;  
 *   	immutableid_attribute@name : the name of the user attribute that contains the value
 *   		to overrule the internal ImmutableId generation; default: "mso365immutableid"
 *   	immutableid_attribute@removeAfterUse : configure whether the attribute should
 *   		be removed from the user's attributes after processing
 *   -->
 *   <immutableid_attribute name="mso365immutableid" removeAfterUse="true" />
 *   
 *   <!-- Default fallback configuration (ref: DefaultPersistent...) -->
 *   <opaque enabled="true" salt="toomuchisbadforyou" />
 *   <attribute name="_theNormalUID" removeAfterUse="true" />
 * </format>
 * 
 * 
 * 
 * @author mdobrinic
 */
public class MSO365PersistentFormatHandler extends DefaultPersistentFormatHandler {
	
	/** configuration element names */
	public static final String EL_MSO365 = "mso365";
	public static final String ATTR_ENTITYID = "entityId";	// default: ENTITY_ID_MICROSOFT_OFFICE_365
	public static final String EL_IMMUTABLEID_ATTRIBUTE = "immutableid_attribute";
	public static final String EL_ATTR_MSO365_NAME = "name";				// default: "mso365immutableid"
	public static final String EL_ATTR_MSO365_REMOVE = "removeAfterUse";	// default: true
	
	public static final String EL_UID_ATTRIBUTE = "uid_attribute";
	public static final String EL_ATTR_UID_ATTR_NAME = "name";	// default: "uid"
	public static final String EL_ATTR_UIT_ATTR_REMOVE = "removeAfterUse";	// default: false
	
	public static final String EL_ATTR_PROPNAME = "name";
	public static final String EL_ATTR_PROPVALUE = "value";
	
	/** Microsoft Office 365 Service Provider Entity Id */
	public static final String ENTITY_ID_MICROSOFT_OFFICE_365 = "urn:federation:MicrosoftOnline";
	
	/** Local logger instance */
    private static final Log _oLogger = LogFactory.getLog(MSO365PersistentFormatHandler.class);

    /**
     * EntityId of the Microsoft Office 365 Service Provider
     * Default: ENTITY_ID_MICROSOFT_OFFICE_365
     */
    protected String _sMSO365EntityId = ENTITY_ID_MICROSOFT_OFFICE_365;
    
    
    /**
     * Name of the attribute that is used as the source for the hash calculation
     * Default: "uid"
     */
    protected String _sUIDAttributeName = "uid";
    
    /**
     * Remove the uid-attribute from the user's attribute-set when it was used
     * Default: false
     */
    protected boolean _bUIDAttributeRemoveAfterUse = false;
    
    /**
     * Name of the User Attribute that is used as Immutable Id
     * Default: "mso365immutableid"
     */
    protected String _sMSO365ImmutableIdAttributeName = "mso365immutableid";

	
    /**
     * Remove the MSO365 ImmutableId attribute from the user's attribute-set when it was used
     * Default: true
     */
    protected boolean _bMSO365ImmutableIdRemoveAfterUse = true;
	
	
    /**
     * Generate the ImmutableId value as:
     * 		uppercase( hexstring( sha1( UserAttributes[ _sUIDAttributeName ] ) ) ) 
     * @param oUser Authenticated user, must have an attribute _sUIDAttributeName in its IAttributes collection
     * @return generated ImmutableId
     */
    protected String generateMSO365ImmutableId(IUser oUser) {
    	String sUid = getUserAttributeValue(oUser, _sUIDAttributeName, false);	// just take the value
    	
    	if (sUid == null) {
    		_oLogger.warn("No attribute '"+_sUIDAttributeName+"' available; could not generate ImmutableId! (available: "+oUser.getAttributes().toString()+")");
    		return null;
    	}
    	
    	// Do the sha1 thing:
    	String sResult = DigestUtils.shaHex(sUid);
    	
    	return sResult.toUpperCase(Locale.ENGLISH);
    	
    }
    
    
	public String format(IUser oUser, String sEntityID, String sTGTID,
			ISession oSession) throws OAException 
	{
		String sImmutableId;
		sImmutableId = getUserAttributeValue(oUser, _sMSO365ImmutableIdAttributeName, _bMSO365ImmutableIdRemoveAfterUse);

		if (! _sMSO365EntityId.equals(sEntityID)) {
			_oLogger.trace("Format NameId for non-Microsoft Office 365 requestor '"+sEntityID+"'; using default handler.");
			return super.format(oUser, sEntityID, sTGTID, oSession);
		}
		
		// Does a overruling mso365 ImmutableId attribute exist? Then use that. 
		if (sImmutableId != null) {
			return sImmutableId;
		}
		
		// Generate the ImmutableId:
		sImmutableId = generateMSO365ImmutableId(oUser); 
		
		if (_bUIDAttributeRemoveAfterUse) {
			if (oUser.getAttributes().contains(_sUIDAttributeName)) {
				_oLogger.info("Reformat: removing attribute '"+_sUIDAttributeName+"'");
				oUser.getAttributes().remove(_sUIDAttributeName);
			}
		}
		
		_oLogger.info("Microsoft Office 365 ImmutableId established as "+sImmutableId);

		return sImmutableId;
	}

	
	@Override
	public void reformat(IUser oUser, String sEntityID, String sTGTID, 
			ISession oSession) throws OAException 
	{
		if (_bMSO365ImmutableIdRemoveAfterUse) {
			if (oUser.getAttributes().contains(_sMSO365ImmutableIdAttributeName)) {
				_oLogger.info("Reformat: removing attribute '"+_sMSO365ImmutableIdAttributeName+"'");
				oUser.getAttributes().remove(_sMSO365ImmutableIdAttributeName);
			}
		}
		
		if (_bUIDAttributeRemoveAfterUse) {
			if (oUser.getAttributes().contains(_sUIDAttributeName)) {
				_oLogger.info("Reformat: removing attribute '"+_sUIDAttributeName+"'");
				oUser.getAttributes().remove(_sUIDAttributeName);
			}
		}

		if (! _sMSO365EntityId.equals(sEntityID)) {
			_oLogger.trace("Reformat NameId for non-Microsoft Office 365 requestor '" + sEntityID+"'");
			super.reformat(oUser, sEntityID, sTGTID, oSession);
			
			return;
		}
	}

	
	public void init(IConfigurationManager oConfigManager, Element elConfig,
			NameIDFormatter oParentFormatter) throws OAException 
	{
		super.init(oConfigManager, elConfig, oParentFormatter);
		
		// Also, initialize our own properties:
		Element elMSO365 = oConfigManager.getSection(elConfig, EL_MSO365);
		if (elMSO365 == null) {
			_oLogger.info("Optional '"+EL_MSO365+"' is not configured, "+
					"using '"+_sMSO365EntityId+"'");
		} else {
			_sMSO365EntityId = oConfigManager.getParam(elMSO365, ATTR_ENTITYID);
			if (_sMSO365EntityId == null) {
				_oLogger.error("No value configured for "+EL_MSO365+"@"+ATTR_ENTITYID);
				throw new OAException(SystemErrors.ERROR_CONFIG_READ);
			}
			_oLogger.info("Using MSO365 EntityId '"+_sMSO365EntityId+"'");
		}
		
		
		Element elUIDAttribute = oConfigManager.getSection(elConfig, EL_UID_ATTRIBUTE);
		if (elUIDAttribute == null) {
			_oLogger.info("Optional '"+EL_UID_ATTRIBUTE+"' is not configured, "+
					"using '"+_sUIDAttributeName+"'");
		} else {
			String sUIDAttributeName = oConfigManager.getParam(elUIDAttribute, EL_ATTR_UID_ATTR_NAME);
			if (sUIDAttributeName == null) {
				_oLogger.info("Optional " + EL_UID_ATTRIBUTE+"@"+EL_ATTR_UID_ATTR_NAME+" is not configured, "+
						"using default '"+_sUIDAttributeName+"'");
			} else {
				_sUIDAttributeName = sUIDAttributeName;
				_oLogger.info("Optional " + EL_UID_ATTRIBUTE+"@"+EL_ATTR_UID_ATTR_NAME+" is configured "+
						"with value '"+_sUIDAttributeName+"'");
			}
			
			_bUIDAttributeRemoveAfterUse = false;
			String sRAU = oConfigManager.getParam(elUIDAttribute, EL_ATTR_UIT_ATTR_REMOVE);
			if (sRAU == null) {
				_oLogger.info("Optional " + EL_UID_ATTRIBUTE+"@"+EL_ATTR_UIT_ATTR_REMOVE+" is not configured, "+
						"using default '"+_bUIDAttributeRemoveAfterUse+"'");
			} else if ("TRUE".equalsIgnoreCase(sRAU)) {
				_oLogger.info("Optional " + EL_UID_ATTRIBUTE+"@"+EL_ATTR_UIT_ATTR_REMOVE+" is configured "+
						"with value '"+_bUIDAttributeRemoveAfterUse+"'");
				_bUIDAttributeRemoveAfterUse = true;
			} else if (!"FALSE".equalsIgnoreCase(sRAU)) {
				_oLogger.error("Invalid value for "+EL_UID_ATTRIBUTE+"@"+EL_ATTR_UIT_ATTR_REMOVE+": "+sRAU);
				throw new OAException(SystemErrors.ERROR_CONFIG_READ);
			} else {
				_oLogger.info("Optional " + EL_UID_ATTRIBUTE+"@"+EL_ATTR_UIT_ATTR_REMOVE+" is configured "+
						"with value '"+_bUIDAttributeRemoveAfterUse+"'");
			}
		}
		
		
		Element elImmutableIdAttribute = oConfigManager.getSection(elConfig, EL_IMMUTABLEID_ATTRIBUTE);
		if (elImmutableIdAttribute == null) {
			_oLogger.info("Optional '" + EL_IMMUTABLEID_ATTRIBUTE+"' element is not configured, "+
					"using '"+_sMSO365ImmutableIdAttributeName+"'; removeAfterUse is '"+_bMSO365ImmutableIdRemoveAfterUse+"'");
		} else {
			String sName = oConfigManager.getParam(elImmutableIdAttribute, EL_ATTR_MSO365_NAME);
			if (sName == null) {
				_oLogger.info("Optional " + EL_IMMUTABLEID_ATTRIBUTE+"@"+EL_ATTR_MSO365_NAME+" is not configured, "+
						"using default '"+_sMSO365ImmutableIdAttributeName+"'");
			} else {
				_sMSO365ImmutableIdAttributeName = sName;
				_oLogger.info("Optional " + EL_IMMUTABLEID_ATTRIBUTE+"@"+EL_ATTR_MSO365_NAME+" is configured "+
						"with value '"+_sMSO365ImmutableIdAttributeName+"'");
			}
			
			_bMSO365ImmutableIdRemoveAfterUse = true;
			String sRAU = oConfigManager.getParam(elImmutableIdAttribute, EL_ATTR_MSO365_REMOVE);
			if (sRAU == null) {
				_oLogger.info("Optional " + EL_IMMUTABLEID_ATTRIBUTE+"@"+EL_ATTR_MSO365_REMOVE+" is not configured, "+
						"using default '"+_bMSO365ImmutableIdRemoveAfterUse+"'");
			} else if ("TRUE".equalsIgnoreCase(sRAU)) {
				_oLogger.info("Optional " + EL_IMMUTABLEID_ATTRIBUTE+"@"+EL_ATTR_MSO365_REMOVE+" is configured "+
						"with value '"+_bMSO365ImmutableIdRemoveAfterUse+"'");
				_bMSO365ImmutableIdRemoveAfterUse = true;
			} else if (!"FALSE".equalsIgnoreCase(sRAU)) {
				_oLogger.error("Invalid value for "+EL_IMMUTABLEID_ATTRIBUTE+"@"+EL_ATTR_MSO365_REMOVE+": "+sRAU);
				throw new OAException(SystemErrors.ERROR_CONFIG_READ);
			} else {
				_oLogger.info("Optional " + EL_IMMUTABLEID_ATTRIBUTE+"@"+EL_ATTR_MSO365_REMOVE+" is configured "+
						"with value '"+_bUIDAttributeRemoveAfterUse+"'");
			}
		}
	}
}
