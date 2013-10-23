/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2008 Alfa & Ariss B.V.
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
package org.asimba.utility.idmapper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.SystemErrors;
import com.alfaariss.oa.api.configuration.IConfigurationManager;
import com.alfaariss.oa.api.idmapper.IIDMapper;

/**
 * Chained ID Mapper
 * 
 * Chain together multiple ID Mappers; the first mapped value of the
 * first IDMapper that matches the request, will provide the result
 * 
 * Configure like this:
 * <idmapper class="org.asimba.idmapper.ChainedIDMapper" ...>
 *   <mappers>
 *     <mapper id="idmapper.1" class="[another-IIDMapper-implementation]" ..>
 *     </mapper>
 *     ...
 *     <mapper id="idmapper.n" class="[another-IIDMapper-implementation]" ..>
 *     </mapper>
 *   </mappers>
 * </idmapper>
 * 
 * @author mdobrinic
 *
 */
public class ChainedIDMapper implements IIDMapper {

	/**
	 * Local logger instance
	 */
    private final Log _oLogger = LogFactory.getLog(ChainedIDMapper.class);


    /**
     * Ordered list of IIDMapper id's
     */
    protected List<String> _lIDMapperIDs;
    
    /**
     * Map of IIDMappers
     */
    protected Map<String, IIDMapper> _mIDMappers;
    
    
	public void start(IConfigurationManager oConfigManager, Element eConfig)
			throws OAException 
	{
		_lIDMapperIDs = new ArrayList<String>();
		_mIDMappers = new HashMap<String, IIDMapper>();
		
		Element elMappers = oConfigManager.getSection(eConfig, "mappers");
		if (elMappers == null) {
			_oLogger.error("No mappers element defined in ChainedIDMapper.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		Element elMapper = oConfigManager.getSection(elMappers, "mapper");
		if (elMapper == null) {
			_oLogger.error("Must configure at least one mapper element in mappers.");
			throw new OAException(SystemErrors.ERROR_CONFIG_READ);
		}
		
		while (elMapper != null) {
			String sClass = oConfigManager.getParam(elMapper, "class");
			if (sClass == null) {
				_oLogger.error("Must configure a @class parameter with a mapper.");
				throw new OAException(SystemErrors.ERROR_CONFIG_READ);
			}
			
			String sID = oConfigManager.getParam(elMapper, "id");
			if (sID == null) {
				_oLogger.error("Must configure a @id parameter with a mapper.");
				throw new OAException(SystemErrors.ERROR_CONFIG_READ);
			}
			
			// Add id to list, retain order
			_lIDMapperIDs.add(sID);

			// Instantiate and start the mapper
			IIDMapper oMapper = createMapper(sClass);
			oMapper.start(oConfigManager, elMapper);
			
			// Put the mapper in the map
			_mIDMappers.put(sID, oMapper);
			
			// Continue with other mappers
			elMapper = oConfigManager.getNextSection(elMapper);
		}

	}

	
	/**
	 * Map the provided value to a projected value.
	 * 
	 * Traverse the ordered IIDMappers and return the value of the
	 * first IIDMaper that returned a result.
	 * 
	 * @param sID the ID that needs to be mapped
	 * @return the mapped value, or null if no mapping could be established
	 * @throws OAException when something in the IIDMapper went wrong
	 */
	public String map(String sID) throws OAException {
		String sMappedValue = null;
		for (String sMapperID: _lIDMapperIDs) {
			sMappedValue = _mIDMappers.get(sMapperID).map(sID);
			if (sMappedValue != null) {
				return sMappedValue;
			}
		}
		return sMappedValue;
	}
	

	/**
	 * Return the original (as in: original <-- sMappedID) value of the
	 * provided mapped value.
	 * 
	 * Traverse the ordered IIDMappers and return the value of the
	 * first IIDMapper that returned a result.
	 * 
	 * @param sMappedID the ID that was result of a mapping
	 * @return the original value that resulted in the sMappedID value, or null if
	 *   the original could not be established
	 * @throws OAException when something in the IIDMapper went wrong
	 */
	public String remap(String sMappedID) throws OAException {
		String sReMappedValue = null;
		for (String sMapperID: _lIDMapperIDs) {
			sReMappedValue = _mIDMappers.get(sMapperID).remap(sMappedID);
			if (sReMappedValue != null) {
				return sReMappedValue;
			}
		}
		return sReMappedValue;
	}

	
	public void stop() {
		for (String sMapperID: _lIDMapperIDs) {
			_mIDMappers.get(sMapperID).stop();
		}
		
		// clear list and map:
		_mIDMappers.clear();
		_lIDMapperIDs.clear();
	}
	
	
	/**
	 * Helper to instantiate the configured IIDMapper class
	 * @param sClass Name of class to instantiate
	 * @return Instantiated class
	 * @throws OAException when class was not found, or when class could not be instantiated
	 */
    private IIDMapper createMapper(String sClass)
    	throws OAException
    {
    	IIDMapper oIDMapper = null;
    	
    	Class<?> oClass = null;
        try {
            oClass = Class.forName(sClass);
        } catch (Exception e) {
            _oLogger.error("No 'class' found with name: " + sClass, e);
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        try {
        	oIDMapper = (IIDMapper) oClass.newInstance();
        } catch (Exception e) {
            _oLogger.error("Could not create an 'IIDMapper' instance of class with name '"+
            	sClass + "'", e); 
            throw new OAException(SystemErrors.ERROR_CONFIG_READ);
        }
        
        return oIDMapper;
    }

	
	
	
}
