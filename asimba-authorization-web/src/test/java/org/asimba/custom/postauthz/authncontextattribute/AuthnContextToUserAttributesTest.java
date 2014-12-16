/**
 * 
 */
package org.asimba.custom.postauthz.authncontextattribute;

import static org.easymock.EasyMock.expect;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
/**
 * @author mdobrinic
 *
 */
public class AuthnContextToUserAttributesTest {

	/** Mock configuration */
	private Element mockedConfig = mock(Element.class);
	private Element mockedAttributes = mock(Element.class);
	private Element mockedAttribute = mock(Element.class);
	private IConfigurationManager mockedConfigurationManager = mock(IConfigurationManager.class);

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception 
	{
		// Static configuration
		when(mockedConfigurationManager.getParam(mockedConfig, AuthnContextToUserAttributes.EL_ENABLED)).thenReturn("true");
		when(mockedConfigurationManager.getParam(mockedConfig, AuthnContextToUserAttributes.EL_ID)).thenReturn("MockID");
		when(mockedConfigurationManager.getParam(mockedConfig, AuthnContextToUserAttributes.EL_FRIENDLYNAME)).thenReturn("Mocked Instance");

		doReturn(mockedAttributes).when(mockedConfigurationManager).getParam(mockedConfig, AuthnContextToUserAttributes.EL_ATTRIBUTES);

		// Only mock one attribute configuration; when getting next section, return null
		doReturn(mockedAttribute).
		when(mockedConfigurationManager).getParam(mockedConfig, AuthnContextToUserAttributes.EL_ATTRIBUTE);

		doReturn(null).
		when(mockedConfigurationManager).getNextSection(mockedAttribute);
		
		// Static Mocking:
		

	}
	
	
	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testHappy() throws Exception {
		AuthnContextToUserAttributes authnContextToUserAttributes = new AuthnContextToUserAttributes();
		
		// Mock the configured attribute
		ACAttribute mockedConfiguredAttribute = mock(ACAttribute.class);
		when(mockedConfiguredAttribute.getAuthnMethodID()).thenReturn("RemoteSAML");
		when(mockedConfiguredAttribute.getSrc()).thenReturn("issuer");
		when(mockedConfiguredAttribute.getDest()).thenReturn("issuerDest");
		when(mockedConfiguredAttribute.isRequired()).thenReturn(true);
		when(mockedConfiguredAttribute.getDefault()).thenReturn("default");
		
		// Mock the ConfiguredAttribute class here:
		mockStatic(ACAttribute.class);
		expect(ACAttribute.fromConfig(mockedConfigurationManager, mockedAttribute)).andReturn(mockedConfiguredAttribute);


		// Perform test:
		try {
			authnContextToUserAttributes.start(mockedConfigurationManager, mockedConfig, null);
		} catch (OAException oae) {
			fail("Exception throws upon initialization.");
		}
		
	}

}
