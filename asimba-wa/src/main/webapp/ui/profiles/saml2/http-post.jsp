<?xml version="1.0" encoding="UTF-8"?>
<%--
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
--%>
<%@ page contentType="text/html; charset=UTF-8" 
	language="java" isErrorPage="true" isELIgnored ="false" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<!DOCTYPE html 
     PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<c:if test="${requestScope.sessionLocale != null}">
	<fmt:setLocale value="${requestScope.sessionLocale}"/>
</c:if>
<fmt:setBundle
	basename="org.asimba.profile.saml2.resources.messages" 
	var="messages" scope="request"/> 

<html xmlns="http://www.w3.org/1999/xhtml">
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
		<link rel="stylesheet" href="${pageContext.request.contextPath}/static/css/default.css" type="text/css" />
		<link rel="shortcut icon" href="${pageContext.request.contextPath}/static/images/logo.ico"  type="image/x-icon" />
		<title>
			<c:if test="${requestScope.serverInfo != null}">
				<c:out value="${requestScope.serverInfo.organization.friendlyName}"/>
			</c:if>			
		</title>
	</head>
	<body onload="document.forms[0].submit()">
		<div id="container">
			<div id="header">
				<img 
					src="${pageContext.request.contextPath}/<fmt:message bundle='${messages}' key='page_logo' />" 
					alt="<fmt:message bundle='${messages}' key='page_logo_alt' />" 
					id="headerlogo" />
				<h1><fmt:message bundle='${messages}' key='page_title'/></h1>
			</div>
			<c:if test="${requestScope.serverInfo != null}">
				<div id="subheader">
					<c:out value="${requestScope.serverInfo.organization.friendlyName}"/>
				</div>
			</c:if>		
			<div id="content">	
				<div id="contentHeader">	
					<h2>
						SAML 2 HTTP-POST binding
					</h2>
				</div>		
				<noscript>			
					<p class="warning">
						 <strong>Note:</strong> Since your browser does not support JavaScript,
	                	you must press the Continue button once to proceed.
					</p>		
				</noscript>
				<div id="contentMain">							
					<form id="saml2Form" class="oaForm" action="${requestScope.action}" method="post">
						<fieldset>
							<c:if test="${requestScope.RelayState != null}">
								<input type="hidden" name="RelayState" value="<c:out value="${requestScope.RelayState}"/>"/>
							</c:if>
							<c:if test="${requestScope.SAMLRequest != null}">
		                		<input type="hidden" name="SAMLRequest" value="${requestScope.SAMLRequest}"/>
		                	</c:if>
		                	<c:if test="${requestScope.SAMLResponse != null}">
		                		<input type="hidden" name="SAMLResponse" value="${requestScope.SAMLResponse}"/>
		                	</c:if>	 
	                    </fieldset>
	                    <noscript>               		
			              <input type="submit" value="Continue" />
		                </noscript>	
					</form>
				</div>
			</div>
			<c:if test="${requestScope.serverInfo != null}">
				<div id="footer">
					<div id="footer1">
						<c:out value="${requestScope.serverInfo.friendlyName}"/> (<c:out value="${requestScope.serverInfo.ID}"/>)
					</div>
					<div id="footer2">	
						<a href="http://www.asimba.org">Asimba</a> - Serious Open Source SSO				
					</div>
				</div>
			</c:if>
		</div>
	</body>
</html>
