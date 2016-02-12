package org.asimba.util.saml2.nameid.handler;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.api.attribute.IAttributes;
import com.alfaariss.oa.api.configuration.ConfigurationException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.requestor.IRequestor;
import com.alfaariss.oa.api.user.IUser;
import com.alfaariss.oa.engine.core.Engine;
import com.alfaariss.oa.engine.core.crypto.CryptoException;
import com.alfaariss.oa.engine.core.crypto.CryptoManager;
import com.alfaariss.oa.engine.core.requestor.factory.IRequestorPoolFactory;
//import static org.powermock.api.mockito.PowerMockito.*;
import com.alfaariss.oa.util.saml2.NameIDFormatter;

@RunWith(PowerMockRunner.class)
@PrepareForTest( { Engine.class })
public class GoogleAppsUnspecifiedFormatHandlerTest {

	private static final Logger _logger = LoggerFactory.getLogger(GoogleAppsUnspecifiedFormatHandlerTest.class);

	public static final String REQUESTOR_PROPERTY_SELECTOR = "custom_selector";
	public static final String SELECTOR_VALUE = "yes";

	public static final String CUSTOM_USER_ATTRIBUTE = "custom_uid";


	// (class-wide) mocked members for configuration
	private IConfigurationManager _mockedConfigManager = mock(IConfigurationManager.class);
	
	// (class-wide) mocked members for initialization
	private NameIDFormatter _mockedNameIDFormatter = mock(NameIDFormatter.class);



	@Before
	public void setup() throws Exception
	{
		mockRequestorPoolFactory();
		mockInitParameters();
	}


	/**
	 * Test the NameIDHandler when a custom selector requestor property was configured with a NON-NULL value. 
	 * This test performs the following evaluations:<br/>
	 * <ol>
	 * <li>Format for user (without custom attribute) for a Requestor that does not have the custom property set<li>
	 * <li>Format for user (without custom attribute) for a Requestor that *does* have any value for the custom property set</li>
	 * <li>Format for user (without custom attribute) for a Requestor that *does* have any value for the custom property set</li>
	 * </ol>
	 * 
	 * <table border=1>
	 * <tr>
	 * <th/><th>User without custom attribute</th><th>User *with* custom attribute</th>
	 * </tr>
	 * <tr><td>Requestor without properties</td><td/><td/></tr>
	 * <tr><td>Requestor with property/ANY value</td><td/><td/></tr>
	 * <tr><td>Requestor with property/SPECIFIC value</td><td/><td/></tr>
	 * </table>
	 * 
	 * @throws Exception
	 */
	@Test
	public void customSelectorPropertyTest() throws Exception
	{
		// Precondition for testing:
		mockRequestorPoolFactory();
		
		// Configure handler for a selector attribute with a non-null value 
		mockInitParameters();
		Element mockedElConfig = mock(Element.class);
		mockConfigManager__SelectorWithAnyValue(mockedElConfig);
		
		GoogleAppsUnspecifiedFormatHandler h = new GoogleAppsUnspecifiedFormatHandler();
		h.init(_mockedConfigManager, mockedElConfig, _mockedNameIDFormatter);

		// -- Run tests with User that *has* the custom attributes
		IUser mockUser;
		String s;
		
		// Test with user WITH custom attributes set
		mockUser = mockUserWithCustomAttributes();

		// Requestor does not qualify, so default unspecified/persistent handler handles request:
		s = h.format(mockUser, "urn:asimba:test:requestor:noCustomPropertiesRequestor", null, null);
		_logger.info("(A/1) Formatted NameID: {}", s);
		assertEquals("_uid-value!urn:asimba:test:requestor:noCustomPropertiesRequestor", s);

		// Requestor does qualify, so "_uid"-attribute value is taken as nameid
		s = h.format(mockUser, "urn:asimba:test:requestor:customSelectorPropertyAnyValueRequestor", null, null);
		_logger.info("(A/2) Formatted NameID: {}", s);
		assertEquals("_uid-value", s);

		// Requestor does qualify, so "_uid"-attribute value is taken as nameid
		s = h.format(mockUser, "urn:asimba:test:requestor:customSelectorPropertySpecificValueRequestor", null, null);
		_logger.info("(A/3) Formatted NameID: {}", s);
		assertEquals("_uid-value", s);

		
		// -- Run tests with User that *does not have* the custom attributes
		// (while the 
		mockUser = mockUserWithoutCustomAttributes();

		// Requester does not qualify, so default unspecified/persistent handler handles request
		// As _uid-attribute does not exist, IUser.getID() is taken as user ID (and scoped for requestor)
		s = h.format(mockUser, "urn:asimba:test:requestor:noCustomPropertiesRequestor", null, null);
		_logger.info("(B/1) Formatted NameID: {}", s);
		assertEquals("mockUserWithoutCustomAttributes!urn:asimba:test:requestor:noCustomPropertiesRequestor", s);

		// Requestor does qualify; _uid-attribute is taken, but is missing -- fall back on IUser.getID() (unscoped)
		s = h.format(mockUser, "urn:asimba:test:requestor:customSelectorPropertyAnyValueRequestor", null, null);
		_logger.info("(B/2) Formatted NameID: {}", s);
		assertEquals("mockUserWithoutCustomAttributes", s);

		// Requestor does qualify; _uid-attribute is taken, but is missing -- fall back on IUser.getID() (unscoped)
		s = h.format(mockUser, "urn:asimba:test:requestor:customSelectorPropertySpecificValueRequestor", null, null);
		_logger.info("(B/3) Formatted NameID: {}", s);
		assertEquals("mockUserWithoutCustomAttributes", s);
		
	}


	/**
	 * Test the NameIDHandler when a custom selector requestor-property was configured with a 
	 * SPECIFIC value. 
	 * 
	 */
	@Test
	public void customAttributePropertyTest() throws Exception
	{
		// Precondition for testing:
		mockRequestorPoolFactory();
		
		// Configure handler for a selector attribute with a non-null value 
		mockInitParameters();
		Element mockedElConfig = mock(Element.class);
		mockConfigManager__SelectorWithSpecificValue(mockedElConfig);
		
		GoogleAppsUnspecifiedFormatHandler h = new GoogleAppsUnspecifiedFormatHandler();
		h.init(_mockedConfigManager, mockedElConfig, _mockedNameIDFormatter);

		IUser mockUser;
		String s;
		
		// Test with user WITH custom attributes set
		mockUser = mockUserWithCustomAttributes();

		// Requestor does not qualify, so default unspecified/persistent handler handles request:
		// As _uid-attribute does not exist, IUser.getID() is taken as user ID (and scoped for requestor)
		s = h.format(mockUser, "urn:asimba:test:requestor:noCustomPropertiesRequestor", null, null);
		_logger.info("(A/1) Formatted NameID: {}", s);
		assertEquals("_uid-value!urn:asimba:test:requestor:noCustomPropertiesRequestor", s);

		// Requestor does not qualify, so default unspecified/persistent handler handles request:
		s = h.format(mockUser, "urn:asimba:test:requestor:customSelectorPropertyAnyValueRequestor", null, null);
		_logger.info("(A/2) Formatted NameID: {}", s);
		assertEquals("_uid-value!urn:asimba:test:requestor:customSelectorPropertyAnyValueRequestor", s);

		// Requestor does qualify, so "_uid"-attribute value is taken as nameid
		s = h.format(mockUser, "urn:asimba:test:requestor:customSelectorPropertySpecificValueRequestor", null, null);
		_logger.info("(A/3) Formatted NameID: {}", s);
		assertEquals("_uid-value", s);

		
		// Test with user WITH custom attributes set
		mockUser = mockUserWithoutCustomAttributes();

		// Requestor does not qualify, so default unspecified/persistent handler handles request:
		// As _uid-attribute does not exist, IUser.getID() is taken as user ID (and scoped for requestor)
		s = h.format(mockUser, "urn:asimba:test:requestor:noCustomPropertiesRequestor", null, null);
		_logger.info("(B/1) Formatted NameID: {}", s);
		assertEquals("mockUserWithoutCustomAttributes!urn:asimba:test:requestor:noCustomPropertiesRequestor", s);

		// Requestor does not qualify, so default unspecified/persistent handler handles request:
		// As _uid-attribute does not exist, IUser.getID() is taken as user ID (and scoped for requestor)
		s = h.format(mockUser, "urn:asimba:test:requestor:customSelectorPropertyAnyValueRequestor", null, null);
		_logger.info("(B/2) Formatted NameID: {}", s);
		assertEquals("mockUserWithoutCustomAttributes!urn:asimba:test:requestor:customSelectorPropertyAnyValueRequestor", s);

		// Requestor does qualify; _uid-attribute is taken, but is missing -- fall back on IUser.getID() (unscoped)
		s = h.format(mockUser, "urn:asimba:test:requestor:customSelectorPropertySpecificValueRequestor", null, null);
		_logger.info("(B/3) Formatted NameID: {}", s);
		assertEquals("mockUserWithoutCustomAttributes", s);
	}




	/**
	 * Mock configuration for:<br/>
	 * <ul>
	 * <li>&lt;googleapps_attribute name="_uid" removeAfterUse="true" /&gt;</li>
	 * <li>&lt;selector_property name="custom_selector" value="yes" /&gt;</li>
	 * <li>&lt;attribute_property name="custom_uid" /&gt;</li>
	 * <li>&lt;opaque enabled="true" salt="toomuchisbadforyou" /&gt;</li>
	 * <li>&lt;attribute name="_theNormalUID" removeAfterUse="true" /&gt;</li>
	 * </ul>
	 * 
	 * @throws ConfigurationException
	 */
	private void mockConfigManager__SelectorWithAnyValue(Element mockedElConfig) throws ConfigurationException
	{
		// Now for providing the default configuration:
		// -- mock the configuration of the (required) GoogleApps Attribute Name
		Element elGoogleAppsAttribute = mock(Element.class);
		when(_mockedConfigManager.getSection(mockedElConfig, GoogleAppsUnspecifiedFormatHandler.EL_GAPPS_ATTRIBUTE))
		.thenReturn(elGoogleAppsAttribute);
		when(_mockedConfigManager.getParam(elGoogleAppsAttribute, GoogleAppsUnspecifiedFormatHandler.EL_ATTR_GAPPS_NAME))
		.thenReturn("_uid");	// configure googleapps_attribute@name="_uid"
		when(_mockedConfigManager.getParam(elGoogleAppsAttribute, GoogleAppsUnspecifiedFormatHandler.EL_ATTR_GAPPS_REMOVE))
		.thenReturn("true");	// configure googleapps_attribute@removeAfterUse="true"

		// -- mock the configuration of the (optional) selector property
		Element elSelectorProperty = mock(Element.class);
		when(_mockedConfigManager.getSection(mockedElConfig, GoogleAppsUnspecifiedFormatHandler.EL_SELECTOR_PROPERTY))
		.thenReturn(elSelectorProperty);
		when(_mockedConfigManager.getParam(elSelectorProperty, GoogleAppsUnspecifiedFormatHandler.EL_ATTR_PROPNAME))
		.thenReturn(REQUESTOR_PROPERTY_SELECTOR);	// configure selector@name="_uid"

		// -- mock the configuration of the (user) attribute property
		Element elAttributeProperty = mock(Element.class);
		when(_mockedConfigManager.getSection(mockedElConfig, GoogleAppsUnspecifiedFormatHandler.EL_ATTRIBUTE_PROPERTY))
		.thenReturn(elAttributeProperty);
		when(_mockedConfigManager.getParam(elAttributeProperty, GoogleAppsUnspecifiedFormatHandler.EL_ATTR_PROPNAME))
		.thenReturn(CUSTOM_USER_ATTRIBUTE);	// configure attribute_property@name="custom_uid"


		// ==== super-class
		// -- mock opaque settings 
		Element elOpaque = mock(Element.class);
		when(_mockedConfigManager.getSection(mockedElConfig, DefaultPersistentFormatHandler.EL_OPAQUE))
		.thenReturn(elOpaque);
		when(_mockedConfigManager.getParam(elOpaque, DefaultPersistentFormatHandler.EL_ATTR_ENABLED))
		.thenReturn("false");	// configure opaque@enabled="true"
		when(_mockedConfigManager.getParam(elOpaque, DefaultPersistentFormatHandler.EL_ATTR_SALT))
		.thenReturn("pepper");	// configure opaque@salt="pepper"

		// -- mock attribute settings
		Element elAttribute = mock(Element.class);
		when(_mockedConfigManager.getSection(mockedElConfig, DefaultPersistentFormatHandler.EL_ATTRIBUTE))
		.thenReturn(elGoogleAppsAttribute);
		when(_mockedConfigManager.getParam(elAttribute, DefaultPersistentFormatHandler.EL_ATTR_NAME))
		.thenReturn("_theNormalUID");	// configure attribute@name="_theNormalUID"
		when(_mockedConfigManager.getParam(elAttribute, DefaultPersistentFormatHandler.EL_ATTR_REMOVE))
		.thenReturn("true");	// configure attribute@removeAfterUse="true"


	}


	private void mockConfigManager__SelectorWithSpecificValue(Element mockedElConfig) throws ConfigurationException
	{
		mockConfigManager__SelectorWithAnyValue(mockedElConfig);

		// Override specific configuration:
		Element elSelectorProperty = mock(Element.class);
		when(_mockedConfigManager.getSection(mockedElConfig, GoogleAppsUnspecifiedFormatHandler.EL_SELECTOR_PROPERTY))
		.thenReturn(elSelectorProperty);
		when(_mockedConfigManager.getParam(elSelectorProperty, GoogleAppsUnspecifiedFormatHandler.EL_ATTR_PROPNAME))
		.thenReturn(REQUESTOR_PROPERTY_SELECTOR);	// configure selector@name="_uid"
		when(_mockedConfigManager.getParam(elSelectorProperty, GoogleAppsUnspecifiedFormatHandler.EL_ATTR_PROPVALUE))
		.thenReturn(SELECTOR_VALUE);	// configure selector@value="yes"
	}

	
	private void mockInitParameters() throws NoSuchAlgorithmException, CryptoException
	{
		CryptoManager mockedCryptoManager = mock(CryptoManager.class);
		
		when(_mockedNameIDFormatter.getCryptoManager()).thenReturn(mockedCryptoManager);

		SecureRandom sr = new SecureRandom();
		MessageDigest md = MessageDigest.getInstance("SHA1");	// whatever...
		when(mockedCryptoManager.getSecureRandom()).thenReturn(sr);
		when(mockedCryptoManager.getMessageDigest()).thenReturn(md);
	}


	/**
	 * Mock a RequestorPoolFactory such that Engine will return this one instead of
	 * something from its own (singleton) context.
	 * 
	 * Initializes the RequestorPoolFactory with three Requestors:
	 * 
	 * 
	 * @throws Exception
	 */
	private void mockRequestorPoolFactory() throws Exception
	{
		IRequestorPoolFactory mockedRequestorPoolFactory = mock(IRequestorPoolFactory.class);

		// Mock the Requestors:
		/** 1- Requestor with no custom properties */
		IRequestor requestorNoCustomProperties = mock(IRequestor.class);
		when(requestorNoCustomProperties.getProperty(REQUESTOR_PROPERTY_SELECTOR)).thenReturn(null);
		
		/** 2- Requestor with selector property with non-null value */
		IRequestor requestorCustomSelectorPropertyAnyValue = mock(IRequestor.class);
		when(requestorCustomSelectorPropertyAnyValue.getProperty(REQUESTOR_PROPERTY_SELECTOR)).thenReturn("non-null-value");
		
		/** 3- Requestor with selector property with the configured specific */
		IRequestor requestorCustomSelectorPropertySpecificValue = mock(IRequestor.class);
		when(requestorCustomSelectorPropertySpecificValue.getProperty(REQUESTOR_PROPERTY_SELECTOR)).thenReturn(SELECTOR_VALUE);
		
		
		// RequestorPoolFactory behavior:
		when(mockedRequestorPoolFactory.getRequestor("urn:asimba:test:requestor:noCustomPropertiesRequestor"))
		.thenReturn(requestorNoCustomProperties);
		when(mockedRequestorPoolFactory.getRequestor("urn:asimba:test:requestor:customSelectorPropertyAnyValueRequestor"))
		.thenReturn(requestorCustomSelectorPropertyAnyValue);		
		when(mockedRequestorPoolFactory.getRequestor("urn:asimba:test:requestor:customSelectorPropertySpecificValueRequestor"))
		.thenReturn(requestorCustomSelectorPropertySpecificValue);

		// Mock Engine to return the mocked RequestorPoolFactory:
		Engine mockedEngine = mock(Engine.class);
		Whitebox.setInternalState(Engine.class, "_engine", mockedEngine);

		when(mockedEngine.getRequestorPoolFactory()).thenReturn(mockedRequestorPoolFactory);
	}


	/**
	 * Mock an IUser instance that has an attribute-set with both the GoogleApps-handler user id 
	 * attribute ("_uid") as well as the fallback user id attribute ("_theNormalUID") set with a value 
	 * @return
	 */
	private IUser mockUserWithCustomAttributes()
	{
		IUser mockUser = mock(IUser.class);

		IAttributes mockAttributes = mock(IAttributes.class);
		when(mockAttributes.get("_uid")).thenReturn("_uid-value");
		when(mockAttributes.contains("_uid")).thenReturn(true);
		when(mockAttributes.get("_theNormalUID")).thenReturn("_theNormalUID-value");
		when(mockAttributes.contains("_theNormalUID")).thenReturn(true);
		// Always pass the remove
		doNothing().when(mockAttributes).remove(anyString());
		when(mockUser.getAttributes()).thenReturn(mockAttributes);
		
		when(mockUser.getID()).thenReturn("mockUserWithCustomAttributes");

		return mockUser;
	}

	
	/**
	 * Mock an IUser instance that has an attribute-set with neither the GoogleApps-handler user id 
	 * attribute ("_uid") nor user id attribute ("_theNormalUID") set with a value 
	 * @return
	 */
	private IUser mockUserWithoutCustomAttributes()
	{
		IUser mockUser = mock(IUser.class);

		IAttributes mockAttributes = mock(IAttributes.class);
		when(mockAttributes.get("_uid")).thenReturn(null);
		when(mockAttributes.contains("_uid")).thenReturn(true);
		when(mockAttributes.get("_theNormalUID")).thenReturn(null);
		when(mockAttributes.contains("_theNormalUID")).thenReturn(true);
		// Always pass the remove
		doNothing().when(mockAttributes).remove(anyString());
		when(mockUser.getAttributes()).thenReturn(mockAttributes);

		when(mockUser.getID()).thenReturn("mockUserWithoutCustomAttributes");

		return mockUser;
	}

}
