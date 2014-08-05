package org.asimba.wa.integrationtest.client.saml;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EmptyServerHandler extends AbstractHandler
{
	private static final Logger _logger = LoggerFactory.getLogger(EmptyServerHandler.class);
	
    @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
    {
    	_logger.info("handle() called.");
        baseRequest.setHandled(true);
    }
}
