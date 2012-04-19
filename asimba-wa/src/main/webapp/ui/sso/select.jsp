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
	language="java" isErrorPage="false" isELIgnored ="false" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<c:if test="${requestScope.sessionLocale != null}">
	<fmt:setLocale value="${requestScope.sessionLocale}"/>
</c:if>
<fmt:setBundle
	basename="com.alfaariss.oa.sso.web.resources.messages" 
	var="messages" scope="request"/>
<fmt:setBundle
	basename="com.alfaariss.oa.sso.web.resources.errors" 
	var="errors" scope="request"/>  
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
		<link rel="stylesheet" href="${pageContext.request.contextPath}/static/css/default.css" type="text/css">
		<link rel="shortcut icon" href="${pageContext.request.contextPath}/static/images/logo.ico"  type="image/x-icon" />
		<title>
			<fmt:message bundle="${messages}" key="sso_selection_page_title">
				<fmt:param>
					<c:out value="${requestScope.serverInfo.organization.friendlyName}"/>
				</fmt:param>
				<fmt:param>
					<fmt:message bundle='${messages}' key='sso_selection' />
				</fmt:param>
			</fmt:message>
		</title>
	</head>	
	<body>	
		<div id="container">
			<div id="header">
				<img 
					src="${pageContext.request.contextPath}/<fmt:message bundle='${messages}' key='page_logo' />" 
					alt="<fmt:message bundle='${messages}' key='page_logo_alt' />" 
					id="headerlogo">
				<h1><fmt:message bundle='${messages}' key='page_title'/></h1>
			</div>
			<div id="subheader">
				<fmt:message bundle='${messages}' key='page_subtitle'/> - <c:out value="${requestScope.serverInfo.organization.friendlyName}"/>
			</div>
			<div id="content">
				<div id="contentHeader">
					<h2>
						<fmt:message bundle='${messages}' key='sso_selection'>
							<fmt:param>
								<c:out value="${requestScope.requestor.friendlyName}"/>
							</fmt:param>
						</fmt:message>
					</h2>	
				</div>	
				<c:if test="${requestScope.userEvent != null}">
					<div id="contentError" class="warning">				
						<h2>
							<fmt:message bundle="${errors}" 
								key="${requestScope.userEvent}"/>
						</h2>						
					</div>
				</c:if>
				<div id="contentMain">
					<p>
						<fmt:message bundle='${messages}' key='authn_header'>
							<fmt:param>
								<c:out value="${requestScope.requestor.friendlyName}"/>
							</fmt:param>
						</fmt:message>
					</p>
																	
					<form id="selectionForm" class="oaForm imageSelection" action="${pageContext.request.contextPath}/sso/web" method="post" name="select">
						<input type="hidden" name="asid" value="${requestScope.asid}">					
						<c:set var="remoteCounter" value="0"/>
						<c:set var="localCounter" value="0"/>	
						<fieldset>
							<fmt:message var="imageLocal" bundle="${messages}" key="image_local" />
							<legend>
								<fmt:message bundle="${messages}" key="authn_local_header">
									<fmt:param>
										<c:out value="${requestScope.requestor.friendlyName}"/>
									</fmt:param>
								</fmt:message>
							</legend>
							<ul>
								<c:forEach var="authenticationProfile" items="${requestScope.authenticationProfiles}">
									<c:choose>
										<c:when test='${!fn:startsWith(authenticationProfile.ID, "remote.")}'>
											<c:set var="liImageName" value="image_${authenticationProfile.ID}" />
											<c:set var="liImageValue" value="???${liImageName}???" />
											<fmt:message var="liImage" bundle="${messages}" key="${liImageName}" />
											<li>
												<a href='${pageContext.request.contextPath}/sso/web?asid=${requestScope.asid}&amp;profile=<c:out value="${authenticationProfile.ID}"/>'>
													<img src='${pageContext.request.contextPath}/${liImage == liImageValue ? imageLocal : liImage}' 
														alt='<c:out value="${authenticationProfile.friendlyName}"/>'>													
													<c:out value="${authenticationProfile.friendlyName}"/>
												</a>
											</li>																	
											<c:set var="localCounter" value="${localCounter+1}"></c:set>		
										</c:when>
										<c:otherwise>
											<c:set var="remoteCounter" value="${remoteCounter+1}"></c:set>
										</c:otherwise>
									</c:choose>
								</c:forEach>
							</ul>
							<c:if test="${localCounter <= 0}">
								<p>
									<fmt:message bundle="${messages}" key="authn_local_not_found" />
								</p>
							</c:if>
						</fieldset>
						<c:if test="${remoteCounter > 0}">
							<fieldset>
								<fmt:message var="imageRemote" bundle="${messages}" key="image_remote" />
								<legend>
									<fmt:message bundle="${messages}" key="authn_remote_header">
										<fmt:param>${requestScope.serverInfo.organization.friendlyName}</fmt:param>
									</fmt:message>	
								</legend>
								<ul>
								<c:forEach var="authenticationProfile" items="${requestScope.authenticationProfiles}">
									<c:if test='${fn:startsWith(authenticationProfile.ID, "remote.")}'>
										<c:set var="liImageName" value="image_${authenticationProfile.ID}" />
										<c:set var="liImageValue" value="???${liImageName}???" />
										<fmt:message var="liImage" bundle="${messages}" key="${liImageName}" />
										<li>
											<a href='${pageContext.request.contextPath}/sso/web?asid=${requestScope.asid}&amp;profile=<c:out value="${authenticationProfile.ID}"/>'>
												<img src='${pageContext.request.contextPath}/${liImage == liImageValue ? imageRemote : liImage}' 
													alt='<c:out value="${authenticationProfile.friendlyName}"/>'>	
												<c:out value="${authenticationProfile.friendlyName}"/>
											</a>
										</li>
									</c:if>
								</c:forEach>
							</ul>
							</fieldset>
						</c:if>					
						<fieldset>
							<legend></legend>
							<input type="submit" name="cancel" 
								value="<fmt:message bundle='${messages}' key='cancel_button'/>">
						</fieldset>
					</form>		
				</div>
			</div>
			<div id="footer">
				<div id="footer1">
					<c:out value="${requestScope.serverInfo.friendlyName}"/> (<c:out value="${requestScope.serverInfo.ID}"/>)
				</div>
				<div id="footer2">	
					<a href="http://www.asimba.org">Asimba</a> - Serious Open Source SSO				
				</div>
			</div>
		</div>
	</body>
</html>