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
package com.alfaariss.oa.profile.aselect.ws;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.soap.SOAP11Constants;
import org.apache.axiom.soap.SOAP12Constants;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;

import com.alfaariss.oa.OAException;
import com.alfaariss.oa.RequestorEvent;
import com.alfaariss.oa.profile.aselect.business.BusinessRuleException;

/**
 * SOAPFault wrapper exception.
 *  
 * @author EVB
 * @author Alfa & Ariss
 *
 */
public class WSFault extends AxisFault
{
    /** serialVersionUID  */
    private static final long serialVersionUID = -7697539037912726984L;
    
    /**
     * Create a SOAP fault for the given <code>BusinessRuleException</code>.
     * @param e The exception.
     */
    public WSFault (BusinessRuleException e)
    {        
        //TODO message from bundle? (erwin)
        //Create AxisFault with reason
        super(e.getEvent().name());
        MessageContext messageContext = MessageContext.getCurrentMessageContext();
        
        OMFactory factory = null;
        if(messageContext != null)
        {
            //Create faultcode
            String faultCode = SOAP12Constants.FAULT_CODE_SENDER;
            if (messageContext.isSOAP11()) 
            {
                faultCode = SOAP11Constants.FAULT_CODE_SENDER;
            }       
            super.setFaultCode(faultCode);
            factory = messageContext.getEnvelope().getOMFactory(); 
        }
        else
        {
            factory = OMAbstractFactory.getOMFactory();
        }   
        
        OMElement problemDetail = factory.createOMElement(
            new QName(ASelectProfileWS.TARGET_NAMESPACE, "result_code", "oa"));
        problemDetail.setText(e.getMessage());
        super.setDetail(problemDetail);
    }
    
    /**
     * Create a SOAP fault for the given <code>OAException</code>.
     * @param e The exception.
     */
    public WSFault(OAException e)
    {
        //TODO message from bundle? (erwin)
        //Create AxisFault with reason
        super(RequestorEvent.INTERNAL_ERROR.name());
        MessageContext messageContext = MessageContext.getCurrentMessageContext();
        OMFactory factory = null;
        if(messageContext != null)
        {
            //Create faultcode
            String faultCode = SOAP12Constants.FAULT_CODE_RECEIVER;
            if (messageContext.isSOAP11()) 
            {
                faultCode = SOAP11Constants.FAULT_CODE_RECEIVER;
            }       
            super.setFaultCode(faultCode);
            factory = messageContext.getEnvelope().getOMFactory();
        }
        else
        {
            factory = OMAbstractFactory.getOMFactory();
        }        
        
        OMElement problemDetail = factory.createOMElement(
            new QName(ASelectProfileWS.TARGET_NAMESPACE, "result_code", "oa"));
        problemDetail.setText(e.getMessage());
        super.setDetail(problemDetail);
    }

   
}
