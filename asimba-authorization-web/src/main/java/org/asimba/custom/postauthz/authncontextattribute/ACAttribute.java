package org.asimba.custom.postauthz.authncontextattribute;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;

/**
 * ACAttribute is a configured AuthenticationContext-attributes;
 * it can be configured like this:
 * 
 * <attribute authnmethod="saml2" src="unknown" dest="alt" required="false" default="missing" />
 * 
 * @authnmethod references the authentication method of which the authentication context must be used
 * @src is the name of the property of the authentication context
 * @dest is the name of the attribute that must be set with the value of value of the src-property
 * @required indicates whether the src-property must exist for the authentication to succeed
 * @default provides a value to set for @dest when the src-property does not exist  
 * 
 * @author mdobrinic
 */
public class ACAttribute {

	/** Local logger instance */
	private static Log _oLogger = LogFactory.getLog(ACAttribute.class);

	public static final String ATTR_AUTHNMETHOD = "authnmethod";
	public static final String ATTR_SRC = "src";
	public static final String ATTR_DEST = "dest";
	public static final String ATTR_REQUIRED = "required";
	public static final String ATTR_DEFAULT = "default";


	private String _sAuthnMethodID;
	private String _sSrc;
	private String _sDest;
	private boolean _required;
	private String _sDefault;

	public ACAttribute() {
		// empty;
	}

	public String getAuthnMethodID() {
		return _sAuthnMethodID;
	}

	public String getSrc() {
		return _sSrc;
	}

	public String getDest() {
		return _sDest;
	}

	public boolean isRequired() {
		return _required;
	}

	public String getDefault() {
		return _sDefault;
	}

	public static ACAttribute fromConfig(IConfigurationManager oConfigurationManager, Element eAttributeConfig)
	{
		ACAttribute oACAttribute = new ACAttribute();

		try {
			String sAuthnMethod = oConfigurationManager.getParam(eAttributeConfig, ATTR_AUTHNMETHOD);
			if (sAuthnMethod == null) {
				_oLogger.error("Attribute did not configure attribute '"+ATTR_AUTHNMETHOD+"'");
				return null;
			}
			oACAttribute._sAuthnMethodID = sAuthnMethod;

			String sSrc = oConfigurationManager.getParam(eAttributeConfig, ATTR_SRC);
			if (sSrc == null) {
				_oLogger.error("Attribute did not configure attribute '"+ATTR_SRC+"'");
				return null;
			}
			oACAttribute._sSrc = sSrc;

			String sDest = oConfigurationManager.getParam(eAttributeConfig, ATTR_DEST);
			if (sDest == null) {
				oACAttribute._sDest = sSrc;
			} else {
				oACAttribute._sDest = sDest;
			}

			String sRequired = oConfigurationManager.getParam(eAttributeConfig, ATTR_REQUIRED);
			if (sRequired == null) {
				oACAttribute._required = true;
			} else {
				oACAttribute._required = Boolean.valueOf(sRequired);
			}

			String sDefault = oConfigurationManager.getParam(eAttributeConfig, ATTR_DEFAULT);
			if (sDefault == null) {
				if (! oACAttribute._required) {
					_oLogger.info("Attribute '"+sSrc+"' not required and no default value configured.");
				}
				oACAttribute._sDefault = null;
			} else {
				oACAttribute._sDefault = sDefault;
			}
		} catch (ConfigurationException e) {
			_oLogger.error("Could not configure attribute: "+e.getMessage());
			return null;
		}
		
		_oLogger.info("Added attribute "+oACAttribute.toString());
		return oACAttribute;
	}

	public String toString() {
		return "{authnmethod:'"+_sAuthnMethodID+"'; src:'"+_sSrc+"'; dest:'"+_sDest
				+"'; required: "+_required+"; default:"+(_sDefault==null?_sDefault:"'"+_sDefault+"'")+"}";
	}


}
