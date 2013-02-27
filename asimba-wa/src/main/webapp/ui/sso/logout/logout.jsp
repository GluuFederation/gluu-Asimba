<%--
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2009 Alfa & Ariss B.V.
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
	language="java" isErrorPage="false" isELIgnored="false" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<c:if test="${requestScope.sessionLocale != null}">
	<fmt:setLocale value="${requestScope.sessionLocale}"/>
</c:if>
<fmt:setBundle
	basename="com.alfaariss.oa.sso.web.profile.logout.resources.messages" 
	var="messages" scope="request"/> 
<fmt:setBundle
	basename="com.alfaariss.oa.sso.web.profile.logout.resources.warnings" 
	var="warnings" scope="request"/>  	
<fmt:setBundle
	basename="com.alfaariss.oa.sso.web.profile.logout.resources.errors" 
	var="errors" scope="request"/> 
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
		
		<c:if test="${requestScope.logoutState == 'USER_LOGOUT_IN_PROGRESS'}">
			<meta http-equiv="REFRESH" content="5;URL='${pageContext.request.contextPath}/sso/logout/force?asid=${requestScope.asid}'">
		</c:if>
		
		<link rel="stylesheet" href="${pageContext.request.contextPath}/static/css/default.css" type="text/css" />
		<link rel="shortcut icon" href="${pageContext.request.contextPath}/static/images/logo.ico"  type="image/x-icon" />
		<title>
			<fmt:message bundle="${messages}" key="logout_page_title">
				<fmt:param>
					<c:out value="${requestScope.serverInfo.organization.friendlyName}"/>
				</fmt:param>
				<fmt:param>
					<fmt:message bundle='${messages}' key='logout' />	
				</fmt:param>
			</fmt:message>
		</title>
		
		<c:if test="${requestScope.logoutState == 'USER_LOGOUT_IN_PROGRESS'}">

			<script type="text/javascript" language="javascript">
				var request;  
				var stateTimerId;
				
				var buttonCount;
				var buttonName;
				var buttonTimerId;
					
				window.onload = function() 
				{
					<!--
						var pic1= new Image(25,25); 
						pic1.src="${pageContext.request.contextPath}/static/images/wait.gif"; 
					//-->
				
					request = initXMLHttpClient();
					stateTimerId = setInterval(sendRequest, 1000);
	
					buttonCount = 5;
					buttonName = document.getElementById('logoutButton').value;
					document.getElementById('logoutButton').value= buttonName + ' (' + buttonCount + ')';
					buttonTimerId = setInterval(updateLogoutButton, 1000);
				}
				
				function updateLogoutButton()
				{
					buttonCount = buttonCount-1;
					if (buttonCount == 0)
					{
						clearInterval(buttonTimerId);
						clearInterval(stateTimerId);
					}
					else
					{
						document.getElementById('logoutButton').value= buttonName + ' (' + buttonCount + ')';
					}
				}
				
				// create an XMLHttpClient 
				function initXMLHttpClient()
				{  
					var xmlhttp;  
					try 
					{// Mozilla/Safari/IE7
						xmlhttp = new XMLHttpRequest();
					}
					catch(e)
					{// IE (other?)  
						var success = false;  
						var XMLHTTP_IDS = new Array('MSXML2.XMLHTTP.5.0','MSXML2.XMLHTTP.4.0','MSXML2.XMLHTTP.3.0','MSXML2.XMLHTTP','Microsoft.XMLHTTP');  
						for (var i = 0; i < XMLHTTP_IDS.length && !success; i++)
						{
							try 
							{
								success = true; 
								xmlhttp = new ActiveXObject(XMLHTTP_IDS[i]);
							} 
							catch(e)
							{}  
						}
						
						if (!success) 
							throw new Error('XMLHttp (AJAX) not supported');  
					}  
					return xmlhttp;  
				} 
				
				function sendRequest()
				{
					request.open('POST','${pageContext.request.contextPath}/sso/logout/state?asid=${requestScope.asid}', true); // open asynchronus request
					request.onreadystatechange = requestHandler;// set request handler  
					request.send(null);// send request  
				}
				
				function requestHandler()
				{
					if (request.readyState == 4)
					{//the operation is completed  
						if (request.status == 200)
						{//do logout redirect
							clearInterval(stateTimerId);
							window.location.href='${pageContext.request.contextPath}/sso/logout/force?asid=${requestScope.asid}';
						}
					}  
				} 
			</script>
		</c:if>
	
	</head>	
		
	<body>
		<div id="container">
			<div id="header">
				<img 
					src="${pageContext.request.contextPath}/<fmt:message bundle='${messages}' key='page_logo' />" 
					alt="<fmt:message bundle='${messages}' key='page_logo_alt' />" 
					id="headerlogo" />
				<h1><fmt:message bundle='${messages}' key='page_title'/></h1>
			</div>
			<div id="subheader">
				<c:out value="${requestScope.serverInfo.organization.friendlyName}"/>
			</div>		
			<div id="content">	
				<div id="contentHeader">
					<h2>
						<fmt:message bundle='${messages}' key='logout' />
					</h2>
				</div>
				
				<c:if test="${requestScope.logoutState != null}">
					<div id="contentError" class="warning">				
						<h2>
							<fmt:message bundle="${errors}" key="${requestScope.logoutState}" />
						</h2>
					</div>
				</c:if>
				
				<c:if test="${requestScope.details != null && fn:length(requestScope.details) > 0}">
					<div id="contentWarning" class="warning">				
						<ul>
							<c:forEach items="${requestScope.details}" var="warning">
								<c:if test="${warning.code != 'USER_LOGGED_OUT'}">
									<li>
										<c:choose>
											<c:when test="${warning.detail != null}">
												<fmt:message bundle="${messages}" key="logout_detail">
													<fmt:param>
														<fmt:message bundle="${warnings}" key="${warning.code}" />
													</fmt:param>
													<fmt:param>
														<c:out value="${warning.detail}"/>
													</fmt:param>
												</fmt:message>
											</c:when>
											<c:otherwise>
												<fmt:message bundle="${warnings}" key="${warning.code}" />
											</c:otherwise>
										</c:choose>
									</li>
								</c:if>
							</c:forEach>
						</ul>
					</div>
				</c:if>	
				
				<div id="contentMain">
					<c:if test="${requestScope.logoutState == 'USER_LOGOUT_IN_PROGRESS'}">
						<div id="wait">
							<img src="${pageContext.request.contextPath}/static/images/wait.gif" alt="...">
						</div>
					
						<form action="${pageContext.request.contextPath}/sso/logout/force" method="post" id="logout_form" name="logout_form">
							<c:if test="${requestScope.asid != null}">
								<input type="hidden" name="asid" value='<c:out value="${requestScope.asid}"/>'>
							</c:if>
							<input type="submit" id="logoutButton" name="logout" value="<fmt:message bundle='${messages}' key='logout_forced_button'/>">
						</form>
					</c:if>
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