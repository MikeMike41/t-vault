/** *******************************************************************************
*  Copyright 2020 T-Mobile, US
*   
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*  
*     http://www.apache.org/licenses/LICENSE-2.0
*  
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*  See the readme.txt file for additional language around disclaimer of warranties.
*********************************************************************************** */
package com.tmobile.cso.vault.api.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.tmobile.cso.vault.api.controller.ControllerUtil;
import com.tmobile.cso.vault.api.model.*;
import com.tmobile.cso.vault.api.process.RequestProcessor;
import com.tmobile.cso.vault.api.process.Response;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.logging.log4j.LogManager;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.StringUtils;


import com.tmobile.cso.vault.api.common.IAMServiceAccountConstants;
import org.springframework.http.ResponseEntity;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

@RunWith(PowerMockRunner.class)
@ComponentScan(basePackages={"com.tmobile.cso.vault.api"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@PrepareForTest({ JSONUtil.class, ControllerUtil.class })
@PowerMockIgnore({"javax.management.*", "javax.script.*"})
public class IAMServiceAccountUtilsTest {

    @InjectMocks
    IAMServiceAccountUtils iamServiceAccountUtils;

    @Mock
    RequestProcessor reqProcessor;

    @Mock
    Response response;

    @Mock
    StatusLine statusLine;

    @Mock
    HttpEntity mockHttpEntity;

    @Mock
    CloseableHttpClient httpClient;

    @Mock
    CloseableHttpResponse httpResponse;

    @Mock
    HttpUtils httpUtils;

    @Before
    public void setUp() {
        PowerMockito.mockStatic(JSONUtil.class);
        PowerMockito.mockStatic(ControllerUtil.class);
        Whitebox.setInternalState(ControllerUtil.class, "log", LogManager.getLogger(ControllerUtil.class));
        Whitebox.setInternalState(ControllerUtil.class, "reqProcessor", reqProcessor);
        when(JSONUtil.getJSON(Mockito.any())).thenReturn("log");
        ReflectionTestUtils.setField(iamServiceAccountUtils, "iamPortalAuthEndpoint", "testendpoint");
        ReflectionTestUtils.setField(iamServiceAccountUtils, "iamPortalDomain", "testdomain");
        ReflectionTestUtils.setField(iamServiceAccountUtils, "iamPortalrotateSecretEndpoint", "testendpoint");
        ReflectionTestUtils.setField(iamServiceAccountUtils, "iamPortalCreateKeyEndpoint", "testendpoint");

        when(ControllerUtil.getReqProcessor()).thenReturn(reqProcessor);
        Map<String, String> currentMap = new HashMap<>();
        currentMap.put("apiurl", "http://localhost:8080/vault/v2/sdb");
        currentMap.put("user", "");
        ThreadLocalContext.setCurrentMap(currentMap);
    }


    Response getMockResponse(HttpStatus status, boolean success, String expectedBody) {
        response = new Response();
        response.setHttpstatus(status);
        response.setSuccess(success);
        response.setResponse("");
        if (!StringUtils.isEmpty(expectedBody)) {
            response.setResponse(expectedBody);
        }
        return response;
    }

    UserDetails getMockUser(boolean isAdmin) {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = new UserDetails();
        userDetails.setUsername("normaluser");
        userDetails.setAdmin(isAdmin);
        userDetails.setClientToken(token);
        userDetails.setSelfSupportToken(token);
        return userDetails;
    }

    @Test
    public void test_getIAMApproleToken_success() throws IOException {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");

        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);

        String responseString = "{\"auth\": {\"client_token\": \""+token+"\"}}";
        when(mockHttpEntity.getContent()).thenReturn( new ByteArrayInputStream(responseString.getBytes()));

        String actualToken = iamServiceAccountUtils.getIAMApproleToken();
        assertEquals(token, actualToken);
    }

    @Test
    public void test_getIAMApproleToken_failed_invalid_sscred() throws IOException {

        when(ControllerUtil.getSscred()).thenReturn(null);
        String actualToken = iamServiceAccountUtils.getIAMApproleToken();
        assertNull(actualToken);
    }

    @Test
    public void test_getIAMApproleToken_failed_httpClient_error() throws IOException {

        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");

        when(httpUtils.getHttpClient()).thenReturn(null);

        String actualToken = iamServiceAccountUtils.getIAMApproleToken();
        assertNull(actualToken);
    }

    @Test
    public void test_getIAMApproleToken_execute_failed() throws IOException {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");

        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenThrow(new IOException());
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);

        String responseString = "{\"auth\": {\"client_token\": \""+ tkn +"\"}}";
        when(mockHttpEntity.getContent()).thenReturn( new ByteArrayInputStream(responseString.getBytes()));

        String actualToken = iamServiceAccountUtils.getIAMApproleToken();
        assertNull(actualToken);
    }

    @Test
    public void test_rotateIAMSecret_success() throws IOException {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";
        String iamSecret = "abcdefgh";
        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");

        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);

        String responseString = "{\"accessKeyId\": \"testaccesskey\", \"userName\": \"svc_vault_test5\", \"accessKeySecret\": \"abcdefgh\", \"expiryDateEpoch\": \"1609754282000\"}";
        String responseStringToken = "{\"auth\": {\"client_token\": \""+token+"\"}}";
        when(mockHttpEntity.getContent()).thenAnswer(new Answer() {
            private int count = 0;

            public Object answer(InvocationOnMock invocation) {
                if (count++ == 1)
                    return new ByteArrayInputStream(responseString.getBytes());

                return new ByteArrayInputStream(responseStringToken.getBytes());
            }
        });

        IAMServiceAccountSecret expectedIamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");
        IAMServiceAccountRotateRequest iamServiceAccountRotateRequest = new IAMServiceAccountRotateRequest(accessKeyId, iamServiceAccountName, awsAccountId);
        IAMServiceAccountSecret iamServiceAccountSecret = iamServiceAccountUtils.rotateIAMSecret(iamServiceAccountRotateRequest);
        assertEquals(expectedIamServiceAccountSecret.getAccessKeySecret(), iamServiceAccountSecret.getAccessKeySecret());
    }

    @Test
    public void test_rotateIAMSecret_null_http_client_failed() throws IOException {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";
        String iamSecret = "abcdefgh";
        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");

        when(httpUtils.getHttpClient()).thenReturn(httpClient).thenReturn(null);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);

        String responseString = "{\"accessKeyId\": \"testaccesskey\", \"userName\": \"svc_vault_test5\", \"accessKeySecret\": \"abcdefgh\", \"expiryDateEpoch\": \"1609754282000\"}";
        String responseStringToken = "{\"auth\": {\"client_token\": \""+ tkn +"\"}}";
        when(mockHttpEntity.getContent()).thenAnswer(new Answer() {
            private int count = 0;

            public Object answer(InvocationOnMock invocation) {
                if (count++ == 1)
                    return new ByteArrayInputStream(responseString.getBytes());

                return new ByteArrayInputStream(responseStringToken.getBytes());
            }
        });

        IAMServiceAccountRotateRequest iamServiceAccountRotateRequest = new IAMServiceAccountRotateRequest(accessKeyId, iamServiceAccountName, awsAccountId);
        IAMServiceAccountSecret iamServiceAccountSecret = iamServiceAccountUtils.rotateIAMSecret(iamServiceAccountRotateRequest);
        assertNull(iamServiceAccountSecret);
    }

    @Test
    public void testRotateIAMSecretFailedInvalidIAMApproleToken() throws IOException {

		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamServiceAccountName = "svc_vault_test5";
		String awsAccountId = "1234567890";
		String accessKeyId = "testaccesskey";
		String iamSecret = "abcdefgh";
        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");

        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(300);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);

        String responseString = "{\"accessKeyId\": \"testaccesskey\", \"userName\": \"svc_vault_test5\", \"accessKeySecret\": \"abcdefgh\", \"expiryDateEpoch\": \"1609754282000\"}";
        String responseStringToken = "{\"auth\": {\"client_token\": \""+token+"\"}}";
        when(mockHttpEntity.getContent()).thenAnswer(new Answer() {
            private int count = 0;

            public Object answer(InvocationOnMock invocation) {
                if (count++ == 1)
                    return new ByteArrayInputStream(responseString.getBytes());

                return new ByteArrayInputStream(responseStringToken.getBytes());
            }
        });

        IAMServiceAccountSecret expectedIamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");
        IAMServiceAccountRotateRequest iamServiceAccountRotateRequest = new IAMServiceAccountRotateRequest(accessKeyId, iamServiceAccountName, awsAccountId);
        IAMServiceAccountSecret iamServiceAccountSecret = iamServiceAccountUtils.rotateIAMSecret(iamServiceAccountRotateRequest);
    }

    @Test
    public void testRotateIAMSecretFailedInvalidIAMPortalDomain() throws IOException {

		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamServiceAccountName = "svc_vault_test5";
		String awsAccountId = "1234567890";
		String accessKeyId = "testaccesskey";
		String iamSecret = "abcdefgh";
        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");

        ReflectionTestUtils.setField(iamServiceAccountUtils, "iamPortalDomain", "");

        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);

        String responseString = "{\"accessKeyId\": \"testaccesskey\", \"userName\": \"svc_vault_test5\", \"accessKeySecret\": \"abcdefgh\", \"expiryDateEpoch\": \"1609754282000\"}";
        String responseStringToken = "{\"auth\": {\"client_token\": \""+token+"\"}}";
        when(mockHttpEntity.getContent()).thenAnswer(new Answer() {
            private int count = 0;

            public Object answer(InvocationOnMock invocation) {
                if (count++ == 1)
                    return new ByteArrayInputStream(responseString.getBytes());

                return new ByteArrayInputStream(responseStringToken.getBytes());
            }
        });

        IAMServiceAccountSecret expectedIamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");
        IAMServiceAccountRotateRequest iamServiceAccountRotateRequest = new IAMServiceAccountRotateRequest(accessKeyId, iamServiceAccountName, awsAccountId);
        IAMServiceAccountSecret iamServiceAccountSecret = iamServiceAccountUtils.rotateIAMSecret(iamServiceAccountRotateRequest);
    }

    @Test
    public void testRotateIAMSecretFailedInvalidIAMPortalEndPoint() throws IOException {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamServiceAccountName = "svc_vault_test5";
		String awsAccountId = "1234567890";
		String accessKeyId = "testaccesskey";
		String iamSecret = "abcdefgh";
        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");
        ReflectionTestUtils.setField(iamServiceAccountUtils, "iamPortalrotateSecretEndpoint", "");
        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);
        String responseString = "{\"accessKeyId\": \"testaccesskey\", \"userName\": \"svc_vault_test5\", \"accessKeySecret\": \"abcdefgh\", \"expiryDateEpoch\": \"1609754282000\"}";
        String responseStringToken = "{\"auth\": {\"client_token\": \""+token+"\"}}";
        when(mockHttpEntity.getContent()).thenAnswer(new Answer() {
            private int count = 0;
            public Object answer(InvocationOnMock invocation) {
                if (count++ == 1)
                    return new ByteArrayInputStream(responseString.getBytes());

                return new ByteArrayInputStream(responseStringToken.getBytes());
            }
        });
        IAMServiceAccountSecret expectedIamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");
        IAMServiceAccountRotateRequest iamServiceAccountRotateRequest = new IAMServiceAccountRotateRequest(accessKeyId, iamServiceAccountName, awsAccountId);
        IAMServiceAccountSecret iamServiceAccountSecret = iamServiceAccountUtils.rotateIAMSecret(iamServiceAccountRotateRequest);
    }

    @Test
    public void testRotateIAMSecretFailedEmptyHttpClient() throws IOException {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamServiceAccountName = "svc_vault_test5";
		String awsAccountId = "1234567890";
		String accessKeyId = "testaccesskey";
		String iamSecret = "abcdefgh";
        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");
        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        String responseString = "{}";
        String responseStringToken = "{\"auth\": {\"client_token\": \""+token+"\"}}";
        when(mockHttpEntity.getContent()).thenAnswer(new Answer() {
            private int count = 0;
            public Object answer(InvocationOnMock invocation) {
                if (count++ == 1)
                    return new ByteArrayInputStream(responseString.getBytes());

                return new ByteArrayInputStream(responseStringToken.getBytes());
            }
        });
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        IAMServiceAccountSecret expectedIamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");
        IAMServiceAccountRotateRequest iamServiceAccountRotateRequest = new IAMServiceAccountRotateRequest(accessKeyId, iamServiceAccountName, awsAccountId);
        IAMServiceAccountSecret iamServiceAccountSecret = iamServiceAccountUtils.rotateIAMSecret(iamServiceAccountRotateRequest);
    }

    @Test
    public void testRotateIAMSecretFailedEmptyRequest() throws IOException {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamServiceAccountName = "svc_vault_test5";
		String awsAccountId = "1234567890";
		String accessKeyId = "testaccesskey";
		String iamSecret = "abcdefgh";
        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");
        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        String responseString = null;
        String responseStringToken = "{\"auth\": {\"client_token\": \""+token+"\"}}";
        when(mockHttpEntity.getContent()).thenAnswer(new Answer() {
            private int count = 0;
            public Object answer(InvocationOnMock invocation) {
                if (count++ == 1)
                    return new ByteArrayInputStream(responseString.getBytes());

                return new ByteArrayInputStream(responseStringToken.getBytes());
            }
        });
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        IAMServiceAccountSecret expectedIamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");
        IAMServiceAccountRotateRequest iamServiceAccountRotateRequest = new IAMServiceAccountRotateRequest(accessKeyId, iamServiceAccountName, awsAccountId);
        IAMServiceAccountSecret iamServiceAccountSecret = iamServiceAccountUtils.rotateIAMSecret(iamServiceAccountRotateRequest);
    }

    @Test
    public void testRotateIAMSecretFailedInvalidRequest() throws IOException {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamServiceAccountName = "svc_vault_test5";
		String awsAccountId = "1234567890";
		String accessKeyId = "testaccesskey";
		String iamSecret = "abcdefgh";
        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");
        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        String responseString = "{\"accessKeyId\": \"testaccesskey\", \"userName\": \"svc_vault_test5\", \"accessKeySecret\": \"abcdefgh\", \"expiryDateEpoch\": \"1609754282000\"}";
        String responseStringToken = "{\"auth\": {\"client_tokenn\": \""+token+"\"}}";
        when(mockHttpEntity.getContent()).thenAnswer(new Answer() {
            private int count = 0;
            public Object answer(InvocationOnMock invocation) {
                if (count++ == 1)
                    return new ByteArrayInputStream(responseString.getBytes());

                return new ByteArrayInputStream(responseStringToken.getBytes());
            }
        });
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);
        when(statusLine.getStatusCode()).thenReturn(300);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        IAMServiceAccountSecret expectedIamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");
        IAMServiceAccountRotateRequest iamServiceAccountRotateRequest = new IAMServiceAccountRotateRequest(accessKeyId, iamServiceAccountName, awsAccountId);
        IAMServiceAccountSecret iamServiceAccountSecret = iamServiceAccountUtils.rotateIAMSecret(iamServiceAccountRotateRequest);
    }

    @Test
    public void test_writeIAMSvcAccSecret_success() {

        String iamServiceAccountName = "svc_vault_test5";
        String token = "123123123123";
        String awsAccountId = "1234567890";
        String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
        String iamSecret = "abcdefgh";
        String accessKeyId = "testaccesskey";
        IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");
        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(reqProcessor.process(eq("/write"), Mockito.any(), eq(token))).thenReturn(response);
        boolean actualStatus = iamServiceAccountUtils.writeIAMSvcAccSecret(token, path, iamServiceAccountName, iamServiceAccountSecret);
        assertTrue(actualStatus);
    }

    @Test
    public void test_writeIAMSvcAccSecret_failed() {

        String iamServiceAccountName = "svc_vault_test5";
        String token = "123123123123";
        String awsAccountId = "1234567890";
        String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
        String iamSecret = "abcdefgh";
        String accessKeyId = "testaccesskey";
        IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");
        Response response = getMockResponse(HttpStatus.BAD_REQUEST, true, "");
        when(reqProcessor.process(eq("/write"), Mockito.any(), eq(token))).thenReturn(response);
        boolean actualStatus = iamServiceAccountUtils.writeIAMSvcAccSecret(token, path, iamServiceAccountName, iamServiceAccountSecret);
        assertFalse(actualStatus);
    }

    @Test
    public void testWriteIAMSvcAccSecretFailedNoData() {

        String iamServiceAccountName = "svc_vault_test5";
        String token = "123123123123";
        String awsAccountId = "1234567890";
        String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
        String iamSecret = "abcdefgh";
        String accessKeyId = "testaccesskey";
        IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret();
        Response response = getMockResponse(HttpStatus.BAD_REQUEST, true, "");
        when(reqProcessor.process(eq("/write"), Mockito.any(), eq(token))).thenReturn(response);
        boolean actualStatus = iamServiceAccountUtils.writeIAMSvcAccSecret(token, path, iamServiceAccountName, iamServiceAccountSecret);
        assertFalse(actualStatus);
    }

    @Test
    public void test_updateActivatedStatusInMetadata_success() {

        String iamServiceAccountName = "svc_vault_test5";
        String token = "123123123123";
        String awsAccountId = "1234567890";
        String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
        String iamSecret = "abcdefgh";
        String accessKeyId = "testaccesskey";

        Response response = getMockResponse(HttpStatus.OK, true, "{ \"data\": { \"isActivated\": false}}");
        when(reqProcessor.process(eq("/read"),Mockito.any(),eq(token))).thenReturn(response);
        Response response204 = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(reqProcessor.process(eq("/write"), Mockito.any(), eq(token))).thenReturn(response204);
        Response actualResponse = iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId);
        assertEquals(HttpStatus.NO_CONTENT, actualResponse.getHttpstatus());
    }

    @Test
    public void test_updateActivatedStatusInMetadata_failed() {

        String iamServiceAccountName = "svc_vault_test5";
        String token = "123123123123";
        String awsAccountId = "1234567890";
        String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
        String iamSecret = "abcdefgh";
        String accessKeyId = "testaccesskey";

        Response response = getMockResponse(HttpStatus.NOT_FOUND, true, "");
        when(reqProcessor.process(eq("/read"),Mockito.any(),eq(token))).thenReturn(response);

        Response actualResponse = iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId);
        assertNull(actualResponse);
    }

    @Test
    public void testUpdateActivatedStatusInMetadataFailed() {

        String iamServiceAccountName = "svc_vault_test5";
        String token = "123123123123";
        String awsAccountId = "1234567890";
        String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
        String iamSecret = "abcdefgh";
        String accessKeyId = "testaccesskey";

        Response response = getMockResponse(HttpStatus.OK, true, null);
        when(reqProcessor.process(eq("/read"),Mockito.any(),eq(token))).thenReturn(response);
        Response response204 = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(reqProcessor.process(eq("/write"), Mockito.any(), eq(token))).thenReturn(response204);
        Response actualResponse = iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId);
    }

    @Test
    public void testUpdateActivatedStatusInMetadataFailedActivated() {

        String iamServiceAccountName = "svc_vault_test5";
        String token = "123123123123";
        String awsAccountId = "1234567890";
        String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
        String iamSecret = "abcdefgh";
        String accessKeyId = "testaccesskey";

        Response response = getMockResponse(HttpStatus.OK, true, "{ \"data\": { \"isActivated\": true}}");
        when(reqProcessor.process(eq("/read"),Mockito.any(),eq(token))).thenReturn(response);
        Response response204 = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(reqProcessor.process(eq("/write"), Mockito.any(), eq(token))).thenReturn(response204);
        Response actualResponse = iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId);
    }

    @Test
    public void test_updateIAMSvcAccNewAccessKeyIdInMetadata_success() {

        String iamServiceAccountName = "svc_vault_test5";
        String token = "123123123123";
        String awsAccountId = "1234567890";
        String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
        String iamSecret = "abcdefgh";
        String accessKeyId = "testaccesskey";

        Response response = getMockResponse(HttpStatus.OK, true, "{ \"data\": {\"secret\": [{\"accessKeyId\": \"testaccesskey\", \"expiryDuration\": 1609668443000}]}}");
        when(reqProcessor.process(eq("/read"),Mockito.any(),eq(token))).thenReturn(response);
        Response response204 = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(reqProcessor.process(eq("/write"), Mockito.any(), eq(token))).thenReturn(response204);

        IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

        Response actualResponse = iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(token, awsAccountId, iamServiceAccountName, accessKeyId, iamServiceAccountSecret);
        assertEquals(HttpStatus.NO_CONTENT, actualResponse.getHttpstatus());
    }

    @Test
    public void test_updateIAMSvcAccNewAccessKeyIdInMetadata_failure_no_metadata() {

        String iamServiceAccountName = "svc_vault_test5";
        String token = "123123123123";
        String awsAccountId = "1234567890";
        String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
        String iamSecret = "abcdefgh";
        String accessKeyId = "testaccesskey";

        Response response = getMockResponse(HttpStatus.NOT_FOUND, true, "");
        when(reqProcessor.process(eq("/read"),Mockito.any(),eq(token))).thenReturn(response);
        IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

        Response actualResponse = iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(token, awsAccountId, iamServiceAccountName, accessKeyId, iamServiceAccountSecret);
        assertNull(actualResponse);
    }

    @Test
    public void testUpdateIAMSvcAccNewAccessKeyIdInMetadataFailed() {

        String iamServiceAccountName = "svc_vault_test5";
        String token = "123123123123";
        String awsAccountId = "1234567890";
        String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
        String iamSecret = "abcdefgh";
        String accessKeyId = "testaccesskey";

        Response response = getMockResponse(HttpStatus.OK, true, "{ \"data\": {\"secretvals\": [{\"accessKeyId\": \"testaccesskey\", \"expiryDuration\": 1609668443000}]}}");
        when(reqProcessor.process(eq("/read"),Mockito.any(),eq(token))).thenReturn(response);
        Response response204 = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(reqProcessor.process(eq("/write"), Mockito.any(), eq(token))).thenReturn(response204);

        IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

        Response actualResponse = iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(token, awsAccountId, iamServiceAccountName, accessKeyId, iamServiceAccountSecret);

    }

    @Test
    public void testUpdateIAMSvcAccNewAccessKeyIdInMetadataSuccessKeyMsmatch() {

        String iamServiceAccountName = "svc_vault_test5";
        String token = "123123123123";
        String awsAccountId = "1234567890";
        String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
        String iamSecret = "abcdefgh";
        String accessKeyId = "testaccesskey1";

        Response response = getMockResponse(HttpStatus.OK, true, "{ \"data\": {\"secret\": [{\"accessKeyId\": \"testaccesskey\", \"expiryDuration\": 1609668443000}]}}");
        when(reqProcessor.process(eq("/read"),Mockito.any(),eq(token))).thenReturn(response);
        Response response204 = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(reqProcessor.process(eq("/write"), Mockito.any(), eq(token))).thenReturn(response204);

        IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

        Response actualResponse = iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(token, awsAccountId, iamServiceAccountName, accessKeyId, iamServiceAccountSecret);
        assertEquals(HttpStatus.NO_CONTENT, actualResponse.getHttpstatus());
    }

    @Test
    public void testUpdateIAMSvcAccNewAccessKeyIdInMetadataFailedNoData() {

        String iamServiceAccountName = "svc_vault_test5";
        String token = "123123123123";
        String awsAccountId = "1234567890";
        String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
        String iamSecret = "abcdefgh";
        String accessKeyId = "testaccesskey";

        Response response = getMockResponse(HttpStatus.OK, true, null);
        when(reqProcessor.process(eq("/read"),Mockito.any(),eq(token))).thenReturn(response);
        Response response204 = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(reqProcessor.process(eq("/write"), Mockito.any(), eq(token))).thenReturn(response204);

        IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

        Response actualResponse = iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(token, awsAccountId, iamServiceAccountName, accessKeyId, iamServiceAccountSecret);
    }

    @Test
    public void testUpdateIAMSvcAccNewAccessKeyIdInMetadataFailedInvalidSecret() {

        String iamServiceAccountName = "svc_vault_test5";
        String token = "123123123123";
        String awsAccountId = "1234567890";
        String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
        String iamSecret = "abcdefgh";
        String accessKeyId = "testaccesskey1";

        Response response = getMockResponse(HttpStatus.OK, true, "{ \"data\": {\"secret\": [{\"accessKeyId\": \"testaccesskey\", \"expiryDuration\": 1609668443000}]}}");
        when(reqProcessor.process(eq("/read"),Mockito.any(),eq(token))).thenReturn(response);
        Response response204 = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(reqProcessor.process(eq("/write"), Mockito.any(), eq(token))).thenReturn(response204);

        IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

        Response actualResponse = iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(token, awsAccountId, iamServiceAccountName, accessKeyId, iamServiceAccountSecret);

    }

    @Test
    public void test_getTokenPoliciesAsListFromTokenLookupJson_success() throws IOException {

        List<String> expectedPolicies = new ArrayList<>();
        expectedPolicies.add("default");
        String policyJson = "{ \"policies\": [\"default\"]}";

        List<String> currentpolicies = iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(new ObjectMapper(), policyJson);
        assertEquals(expectedPolicies,currentpolicies);
    }

    @Test
    public void test_getTokenPoliciesAsListFromTokenLookupJson_success_single_policy() throws IOException {

        List<String> expectedPolicies = new ArrayList<>();
        expectedPolicies.add("default");
        String policyJson = "{ \"policies\": \"default\"}";

        List<String> currentpolicies = iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(new ObjectMapper(), policyJson);
        assertEquals(expectedPolicies,currentpolicies);
    }

    @Test
    public void testGetTokenPoliciesAsListFromTokenLookupJsonFailed() throws IOException {

        List<String> expectedPolicies = new ArrayList<>();
        expectedPolicies.add("default");
        String policyJson = "{ \"policy\": [\"default\"]}";

        List<String> currentpolicies = iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(new ObjectMapper(), policyJson);
    }


    @Test
    public void test_getIdentityPoliciesAsListFromTokenLookupJson_success() throws IOException {

        List<String> expectedPolicies = new ArrayList<>();
        expectedPolicies.add("default");
        String policyJson = "{ \"identity_policies\": [\"default\"]}";

        List<String> currentpolicies = iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(new ObjectMapper(), policyJson);
        assertEquals(expectedPolicies,currentpolicies);
    }

    @Test
    public void test_getIdentityPoliciesAsListFromTokenLookupJson_success_single_policy() throws IOException {

        List<String> expectedPolicies = new ArrayList<>();
        expectedPolicies.add("default");
        String policyJson = "{ \"identity_policies\": \"default\"}";

        List<String> currentpolicies = iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(new ObjectMapper(), policyJson);
        assertEquals(expectedPolicies,currentpolicies);
    }

    @Test
    public void testGetIdentityPoliciesAsListFromTokenLookupJsonFailed() throws IOException {

        List<String> expectedPolicies = new ArrayList<>();
        expectedPolicies.add("default");
        String policyJson = "{ \"identity_policy\": [\"default\"]}";

        List<String> currentpolicies = iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(new ObjectMapper(), policyJson);
    }

    @Test
    public void test_createAccessKeys() throws IOException {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";
        String iamSecret = "abcdefgh";
        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");

        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);

        String responseString = "{\"accessKeyId\": \"AKIA2GBSJB3123\",\"accessKeySecret\": \"abcdefgh\",\"awsAccountId\": \"1234567890\",\"createDate\": \"2021-05-03T08:56:42.000+0000\",\"expiryDate\": null,\"expiryDateEpoch\": 1627808202000,\"status\": \"Active\",\"userName\": \"svc_vault_test5\"}";
        String responseStringToken = "{\"auth\": {\"client_token\": \""+token+"\"}}";
        when(mockHttpEntity.getContent()).thenAnswer(new Answer() {
            private int count = 0;

            public Object answer(InvocationOnMock invocation) {
                if (count++ == 1)
                    return new ByteArrayInputStream(responseString.getBytes());

                return new ByteArrayInputStream(responseStringToken.getBytes());
            }
        });

        IAMServiceAccountSecret expectedIamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

        IAMServiceAccountSecretResponse expectedIamServiceAccountSecretResponse = new IAMServiceAccountSecretResponse();
        expectedIamServiceAccountSecretResponse.setIamServiceAccountSecret(expectedIamServiceAccountSecret);
        expectedIamServiceAccountSecretResponse.setStatusCode(200);
        IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = iamServiceAccountUtils.createAccessKeys(awsAccountId, iamServiceAccountName);
        assertEquals(expectedIamServiceAccountSecretResponse.getIamServiceAccountSecret().getAccessKeySecret(), iamServiceAccountSecretResponse.getIamServiceAccountSecret().getAccessKeySecret());
    }

    @Test
    public void test_createAccessKeys_null_http_client_success() throws IOException {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";
        String iamSecret = "abcdefgh";
        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");

        when(httpUtils.getHttpClient()).thenReturn(httpClient).thenReturn(null);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);

        String responseString = "{\"accessKeyId\": \"AKIA2GBSJB3123\",\"accessKeySecret\": \"abcdefgh\",\"awsAccountId\": \"1234567890\",\"createDate\": \"2021-05-03T08:56:42.000+0000\",\"expiryDate\": null,\"expiryDateEpoch\": 1627808202000,\"status\": \"Active\",\"userName\": \"svc_vault_test5\"}";
        String responseStringToken = "{\"auth\": {\"client_token\": \""+ tkn +"\"}}";
        when(mockHttpEntity.getContent()).thenAnswer(new Answer() {
            private int count = 0;

            public Object answer(InvocationOnMock invocation) {
                if (count++ == 1)
                    return new ByteArrayInputStream(responseString.getBytes());

                return new ByteArrayInputStream(responseStringToken.getBytes());
            }
        });

        IAMServiceAccountSecret expectedIamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

        IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = iamServiceAccountUtils.createAccessKeys(awsAccountId, iamServiceAccountName);
        assertNull(iamServiceAccountSecretResponse.getIamServiceAccountSecret());
    }

    @Test
    public void test_createAccessKeys_null_endpoint_success() throws IOException {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";
        String iamSecret = "abcdefgh";
        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");

        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);

        String responseString = "{\"accessKeyId\": \"AKIA2GBSJB3123\",\"accessKeySecret\": \"abcdefgh\",\"awsAccountId\": \"1234567890\",\"createDate\": \"2021-05-03T08:56:42.000+0000\",\"expiryDate\": null,\"expiryDateEpoch\": 1627808202000,\"status\": \"Active\",\"userName\": \"svc_vault_test5\"}";
        String responseStringToken = "{\"auth\": {\"client_token\": \""+ tkn +"\"}}";
        when(mockHttpEntity.getContent()).thenAnswer(new Answer() {
            private int count = 0;

            public Object answer(InvocationOnMock invocation) {
                if (count++ == 1)
                    return new ByteArrayInputStream(responseString.getBytes());

                return new ByteArrayInputStream(responseStringToken.getBytes());
            }
        });

        IAMServiceAccountSecret expectedIamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

        ReflectionTestUtils.setField(iamServiceAccountUtils, "iamPortalCreateKeyEndpoint", "");

        IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = iamServiceAccountUtils.createAccessKeys(awsAccountId, iamServiceAccountName);
        assertNull(iamServiceAccountSecretResponse.getIamServiceAccountSecret());
    }

    @Test
    public void test_createAccessKeys_null_token() {
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";

        IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = iamServiceAccountUtils.createAccessKeys(awsAccountId, iamServiceAccountName);
        assertNull(iamServiceAccountSecretResponse.getIamServiceAccountSecret());
    }
    
    @Test
    public void test_deleteAccessKeyFromIAMSvcAccMetadata_success() {
        String iamServiceAccountName = "svc_vault_test5";
        String token = "123123123123";
        String awsAccountId = "1234567890";
        String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
        String iamSecret = "abcdefgh";
        String accessKeyId = "testaccesskey";

        Response response = getMockResponse(HttpStatus.OK, true, "{ \"data\": {\"secret\": [{\"accessKeyId\": \"testaccesskey\", \"expiryDuration\": 1609668443000}]}}");
        when(reqProcessor.process(eq("/read"),Mockito.any(),eq(token))).thenReturn(response);
        Response response204 = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(reqProcessor.process(eq("/write"), Mockito.any(), eq(token))).thenReturn(response204);
        Response actualResponse = iamServiceAccountUtils.deleteAccessKeyFromIAMSvcAccMetadata(token, awsAccountId, iamServiceAccountName, accessKeyId);
        assertEquals(HttpStatus.NO_CONTENT, actualResponse.getHttpstatus());
    }

    @Test
    public void test_deleteAccessKeyFromIAMSvcAccMetadata_io_exception_failed() {
        String iamServiceAccountName = "svc_vault_test5";
        String tkn = "123123123123";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";

        Response response = getMockResponse(HttpStatus.OK, true, null);
        when(reqProcessor.process(eq("/read"),Mockito.any(),eq(tkn))).thenReturn(response);
        Response response204 = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(reqProcessor.process(eq("/write"), Mockito.any(), eq(tkn))).thenReturn(response204);
        Response actualResponse = iamServiceAccountUtils.deleteAccessKeyFromIAMSvcAccMetadata(tkn, awsAccountId, iamServiceAccountName, accessKeyId);
        assertNull(actualResponse.getHttpstatus());
        assertEquals("{} \t", actualResponse.getResponse());
    }

    @Test
    public void test_deleteAccessKeyFromIAMSvcAccMetadata_failed() {
        String iamServiceAccountName = "svc_vault_test5";
        String token = "123123123123";
        String awsAccountId = "1234567890";
        String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
        String iamSecret = "abcdefgh";
        String accessKeyId = "testaccesskey";

        Response response = getMockResponse(HttpStatus.FORBIDDEN, true, "{ \"data\": {\"secret\": [{\"accessKeyId\": \"testaccesskey\", \"expiryDuration\": 1609668443000}]}}");
        when(reqProcessor.process(eq("/read"),Mockito.any(),eq(token))).thenReturn(response);
        Response response204 = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(reqProcessor.process(eq("/write"), Mockito.any(), eq(token))).thenReturn(response204);
        Response actualResponse = iamServiceAccountUtils.deleteAccessKeyFromIAMSvcAccMetadata(token, awsAccountId, iamServiceAccountName, accessKeyId);
        assertEquals(HttpStatus.FORBIDDEN, actualResponse.getHttpstatus());
    }

    @Test
    public void test_deleteIAMAccesskeyFromIAM_success() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";

        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");

        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);

        String responseString = "{\"auth\": {\"client_token\": \"" + tkn + "\"}}";
        when(mockHttpEntity.getContent()).thenReturn( new ByteArrayInputStream(responseString.getBytes()));

        ReflectionTestUtils.setField(iamServiceAccountUtils, "iamPortalDeleteKeyEndpoint", "testendpoint");

        boolean actualResult = iamServiceAccountUtils.deleteIAMAccesskeyFromIAM(awsAccountId, iamServiceAccountName, accessKeyId);
        assertTrue(actualResult);
    }

    @Test
    public void test_deleteIAMAccesskeyFromIAM_execute_exception_failed() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";

        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");

        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse)
                .thenThrow(new UnsupportedEncodingException());
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);

        String responseString = "{\"auth\": {\"client_token\": \"" + tkn + "\"}}";
        when(mockHttpEntity.getContent()).thenReturn( new ByteArrayInputStream(responseString.getBytes()));

        ReflectionTestUtils.setField(iamServiceAccountUtils, "iamPortalDeleteKeyEndpoint", "testendpoint");

        boolean actualResult = iamServiceAccountUtils.deleteIAMAccesskeyFromIAM(awsAccountId, iamServiceAccountName, accessKeyId);
        assertFalse(actualResult);
    }

    @Test
    public void test_deleteIAMAccesskeyFromIAM_delete_failed() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";

        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");

        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200).thenReturn(500);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);

        String responseString = "{\"auth\": {\"client_token\": \"" + tkn + "\"}}";
        when(mockHttpEntity.getContent()).thenReturn(new ByteArrayInputStream(responseString.getBytes()));

        ReflectionTestUtils.setField(iamServiceAccountUtils, "iamPortalDeleteKeyEndpoint", "testendpoint");

        boolean actualResult = iamServiceAccountUtils.deleteIAMAccesskeyFromIAM(awsAccountId, iamServiceAccountName, accessKeyId);
        assertFalse(actualResult);
    }

    @Test
    public void test_deleteIAMAccesskeyFromIAM_unsupported_encoding_exception_failed() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";
        String iamSecret = "omg_so_secret";
        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");

        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);
        String responseString = "{\"accessKeyId\": \"testaccesskey\", \"userName\": \"svc_vault_test5\", \"accessKeySecret\": \"abcdefgh\", \"expiryDateEpoch\": \"1609754282000\"}";
        String responseStringToken = "{\"auth\": {\"client_token\": \""+tkn+"\"}}";
        when(mockHttpEntity.getContent()).thenAnswer(new Answer() {
            private int count = 0;

            public Object answer(InvocationOnMock invocation) {
                if (count++ == 1)
                    return new ByteArrayInputStream(responseString.getBytes());

                return new ByteArrayInputStream(responseStringToken.getBytes());
            }
        });

        IAMServiceAccountSecret expectedIamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");
        IAMServiceAccountRotateRequest iamServiceAccountRotateRequest = new IAMServiceAccountRotateRequest(accessKeyId, iamServiceAccountName, awsAccountId);
        Boolean iamServiceAccountSecret = iamServiceAccountUtils.deleteIAMAccesskeyFromIAM(awsAccountId,iamServiceAccountName,accessKeyId);
        assertEquals(false,iamServiceAccountSecret);
    }
    
    @Test
    public void test_deleteIAMAccesskeyFromIAM_null_http_client_failed() throws IOException {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";
        String iamSecret = "omg_so_secret";
        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");
        when(httpUtils.getHttpClient()).thenReturn(null);
        when(httpUtils.getHttpClient()).thenReturn(httpClient).thenReturn(null);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);


        String responseString = "{\"accessKeyId\": \"testaccesskey\", \"userName\": \"svc_vault_test5\", \"accessKeySecret\": \"abcdefgh\", \"expiryDateEpoch\": \"1609754282000\"}";
        String responseStringToken = "{\"auth\": {\"client_token\": \""+tkn+"\"}}";
        when(mockHttpEntity.getContent()).thenAnswer(new Answer() {
            private int count = 0;

            public Object answer(InvocationOnMock invocation) {
                if (count++ == 1)
                    return new ByteArrayInputStream(responseString.getBytes());

                return new ByteArrayInputStream(responseStringToken.getBytes());
            }
        });

        IAMServiceAccountSecret expectedIamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");
        IAMServiceAccountRotateRequest iamServiceAccountRotateRequest = new IAMServiceAccountRotateRequest(accessKeyId, iamServiceAccountName, awsAccountId);
        Boolean iamServiceAccountSecret = iamServiceAccountUtils.deleteIAMAccesskeyFromIAM(awsAccountId,iamServiceAccountName,accessKeyId);
        assertEquals(false,iamServiceAccountSecret);
    }
   

    @Test
    public void test_deleteIAMAccesskeyFromIAM_null_endpoint_property_failed() throws IOException {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";
        String iamSecret = "omg_so_secret";

        when(ControllerUtil.getSscred()).thenReturn(new SSCred());
        when(ControllerUtil.getIamUsername()).thenReturn("M2UyNTA0MGYtODIwNS02ZWM2LTI4Y2ItOGYwZTQ1NDI1YjQ4");
        when(ControllerUtil.getIamPassword()).thenReturn("MWFjOGM1ZTgtZjE5Ny0yMTVlLTNmODUtZWIwMDc3ZmY3NmQw");
        when(httpUtils.getHttpClient()).thenReturn(null);
        when(httpUtils.getHttpClient()).thenReturn(httpClient);
        when(httpClient.execute(any())).thenReturn(httpResponse);
        when(httpResponse.getStatusLine()).thenReturn(statusLine);
        when(statusLine.getStatusCode()).thenReturn(200);
        when(httpResponse.getEntity()).thenReturn(mockHttpEntity);
        String responseString = "{\"accessKeyId\": \"AKIA2GBSJB3123\",\"accessKeySecret\": \"abcdefgh\",\"awsAccountId\": \"1234567890\",\"createDate\": \"2021-05-03T08:56:42.000+0000\",\"expiryDate\": null,\"expiryDateEpoch\": 1627808202000,\"status\": \"Active\",\"userName\": \"svc_vault_test5\"}";
        String responseStringToken = "{\"auth\": {\"client_token\": \""+tkn+"\"}}";
        when(mockHttpEntity.getContent()).thenAnswer(new Answer() {
            private int count = 0;

            public Object answer(InvocationOnMock invocation) {
                if (count++ == 1)
                    return new ByteArrayInputStream(responseString.getBytes());

                return new ByteArrayInputStream(responseStringToken.getBytes());
            }
        });

        IAMServiceAccountSecret expectedIamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

        IAMServiceAccountSecretResponse expectedIamServiceAccountSecretResponse = new IAMServiceAccountSecretResponse();
        expectedIamServiceAccountSecretResponse.setIamServiceAccountSecret(expectedIamServiceAccountSecret);
        expectedIamServiceAccountSecretResponse.setStatusCode(200);
        IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = iamServiceAccountUtils.createAccessKeys(awsAccountId, iamServiceAccountName);
//        assertEquals(expectedIamServiceAccountSecretResponse.getIamServiceAccountSecret().getAccessKeySecret(), iamServiceAccountSecretResponse.getIamServiceAccountSecret().getAccessKeySecret());
       
        when(mockHttpEntity.getContent()).thenReturn( new ByteArrayInputStream(responseString.getBytes()));

        boolean actualResult = iamServiceAccountUtils.deleteIAMAccesskeyFromIAM(awsAccountId, iamServiceAccountName, accessKeyId);
        assertFalse(actualResult);
    }

    @Test
    public void test_deleteIAMAccesskeyFromIAM_null_token_failed() {
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";

        boolean actualResult = iamServiceAccountUtils.deleteIAMAccesskeyFromIAM(awsAccountId, iamServiceAccountName, accessKeyId);
        assertFalse(actualResult);
    }

    @Test
    public void test_addIAMSvcAccNewAccessKeyIdToMetadata_success() throws JsonProcessingException {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";
        String iamSecret = "omg_so_secret";
        IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId,
                iamSecret, 1609754282000L, awsAccountId, "", "");

        List<IAMSecretsMetadata> iamSecretsMetadataList = new ArrayList<>();
        IAMSecretsMetadata iamSecretsMetadata = new IAMSecretsMetadata();
        iamSecretsMetadata.setAccessKeyId("111");
        iamSecretsMetadata.setExpiryDuration(1234567L);
        iamSecretsMetadataList.add(iamSecretsMetadata);

        ObjectMapper objectMapper = new ObjectMapper();
        String iamSecretsMetadataListStr = objectMapper.writeValueAsString(iamSecretsMetadataList);

        Response readResponse = getMockResponse(HttpStatus.OK, true, "{ \"data\": { \"secret\": " +
                iamSecretsMetadataListStr + "}}");
        when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_svc_vault_test5\"}", tkn))
                .thenReturn(readResponse);

        Response metaResponse = new Response();
        metaResponse.setHttpstatus(HttpStatus.NO_CONTENT);
        when(reqProcessor.process("/write", "{\"path\":\"metadata/iamsvcacc/1234567890_svc_vault_test5\",\"data\":" +
                "{\"secret\":[{\"accessKeyId\":\"111\",\"expiryDuration\":1609754282000},{\"accessKeyId\":\"testaccesskey\"," +
                "\"expiryDuration\":1609754282000}],\"expiryDateEpoch\":1609754282000}}", tkn)).thenReturn(metaResponse);

        Response actualResponse = iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(tkn, awsAccountId, iamServiceAccountName,
                iamServiceAccountSecret);
        assertEquals(metaResponse, actualResponse);
    }

    @Test
    public void test_addIAMSvcAccNewAccessKeyIdToMetadata_read_metadata_failed() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";
        String iamSecret = "omg_so_secret";
        IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId,
                iamSecret, 1609754282000L, awsAccountId, "", "");

        List<IAMSecretsMetadata> iamSecretsMetadataList = new ArrayList<>();
        IAMSecretsMetadata iamSecretsMetadata = new IAMSecretsMetadata();
        iamSecretsMetadata.setAccessKeyId("111");
        iamSecretsMetadata.setExpiryDuration(1234567L);
        iamSecretsMetadataList.add(iamSecretsMetadata);

        Response readResponse = getMockResponse(HttpStatus.NOT_FOUND, true, "{}");
        when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_svc_vault_test5\"}", tkn))
                .thenReturn(readResponse);

        Response metaResponse = new Response();
        metaResponse.setHttpstatus(HttpStatus.NOT_FOUND);
        metaResponse.setSuccess(true);
        metaResponse.setResponse("{}");
        when(reqProcessor.process("/write", "{\"path\":\"metadata/iamsvcacc/1234567890_svc_vault_test5\",\"data\":" +
                "{\"secret\":[{\"accessKeyId\":\"111\",\"expiryDuration\":1609754282000},{\"accessKeyId\":\"testaccesskey\"," +
                "\"expiryDuration\":1609754282000}],\"expiryDateEpoch\":1609754282000}}", tkn)).thenReturn(metaResponse);

        Response actualResponse = iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(tkn, awsAccountId, iamServiceAccountName,
                iamServiceAccountSecret);
        assertEquals(metaResponse.getHttpstatus(), actualResponse.getHttpstatus());
        assertEquals(metaResponse.getResponse(), actualResponse.getResponse());
    }

    @Test
    public void test_addIAMSvcAccNewAccessKeyIdToMetadata_json_parse_exception_failed() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";
        String iamSecret = "omg_so_secret";
        IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId,
                iamSecret, 1609754282000L, awsAccountId, "", "");

        List<IAMSecretsMetadata> iamSecretsMetadataList = new ArrayList<>();
        IAMSecretsMetadata iamSecretsMetadata = new IAMSecretsMetadata();
        iamSecretsMetadata.setAccessKeyId("111");
        iamSecretsMetadata.setExpiryDuration(1234567L);
        iamSecretsMetadataList.add(iamSecretsMetadata);
        Response readResponse = getMockResponse(HttpStatus.OK, true, "{ \"data\": { \"secret\": " +
                iamSecretsMetadataList + "}}");
        when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_svc_vault_test5\"}", tkn))
                .thenReturn(readResponse);

        Response actualResponse = iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(tkn, awsAccountId, iamServiceAccountName,
                iamServiceAccountSecret);
        assertEquals(actualResponse.getResponse(), "{} \t");
        assertNull(actualResponse.getHttpstatus());

    }
      @Test
    public void test_IAMSvcAccNewAccessKeyIdToMetadata_failure(){
        String sampletok = "123123123123";
        String awsAccountId = "1234567890";
        String iamSvcaccName = "svc_vault_test5";
        String PATHSTR = "{\"path\":\"";
        IAMServiceAccountSecret iamServiceAccount =new IAMServiceAccountSecret();
        iamServiceAccount.setUserName("testuser");
        iamServiceAccount.setAwsAccountId(awsAccountId);
        iamServiceAccount.setExpiryDateEpoch(1619823077L);
        iamServiceAccount.setCreateDate("01-01-2000");
        iamServiceAccount.setAccessKeyId("passtest");
        iamServiceAccount.setAccessKeySecret("testpass");
        iamServiceAccount.setStatus("success");
        String uniqueIAMSvcaccName = awsAccountId + "_" + iamSvcaccName;
        String path = new StringBuffer(IAMServiceAccountConstants.IAM_SVCC_ACC_PATH).append(uniqueIAMSvcaccName).toString();
        path = "metadata/"+path;
        String pathjson =PATHSTR+path+"\"}";

        ResponseEntity<String> expectedResponse= ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Invalid input values for creating safe\"]}");

        // metadataResponse.getHttpstatus()=metadataResponse.setHttpstatus(HttpStatus.OK);
        Response response1 = getMockResponse(HttpStatus.OK, true, "");
        Mockito.when(reqProcessor.process("/read",pathjson,sampletok)).thenReturn(response1);
        //  String userName, String accessKeyId, String accessKeySecret, Long expiryDateEpoch, String awsAccountId, String createDate, String status)
        //  String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount\", \"createdAtEpoch\": 1619823077, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":1627685477}]}, \"path\": \"iamsvcacc/1234567890_testaccount\"}";

        Response test= iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(sampletok, awsAccountId, iamSvcaccName, iamServiceAccount);
        // assertEquals(expectedResponse,test);
    }
   

@Test
    public void test_createAccessKeys_failure() throws IOException {
        String sampletok = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String iamServiceAccountName = "svc_vault_test5";
        String awsAccountId = "1234567890";
        String accessKeyId = "testaccesskey";
        String iamSecret = "abcdefgh";

        String responseString = "{\"auth\": {\"client_token\": \"" + sampletok + "\"}}";
        when(mockHttpEntity.getContent()).thenReturn( new ByteArrayInputStream(responseString.getBytes()));

        ReflectionTestUtils.setField(iamServiceAccountUtils, "iamPortalDeleteKeyEndpoint", "testendpoint");

        boolean actualResult = iamServiceAccountUtils.deleteIAMAccesskeyFromIAM(awsAccountId, iamServiceAccountName, accessKeyId);
        assertFalse(actualResult);
    }

}