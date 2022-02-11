// =========================================================================
// Copyright 2019 T-Mobile, US
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// See the readme.txt file for additional language around disclaimer of warranties.
// =========================================================================
package com.tmobile.cso.vault.api.service;

import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.tmobile.cso.vault.api.model.*;
import com.tmobile.cso.vault.api.utils.CommonUtils;
import com.tmobile.cso.vault.api.utils.EmailUtils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.logging.log4j.LogManager;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.mockito.InjectMocks;
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
import org.springframework.http.ResponseEntity;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.tmobile.cso.vault.api.common.TVaultConstants;
import com.tmobile.cso.vault.api.controller.ControllerUtil;
import com.tmobile.cso.vault.api.process.RequestProcessor;
import com.tmobile.cso.vault.api.process.Response;
import com.tmobile.cso.vault.api.utils.JSONUtil;
import com.tmobile.cso.vault.api.utils.ThreadLocalContext;

@RunWith(PowerMockRunner.class)
@ComponentScan(basePackages={"com.tmobile.cso.vault.api"})
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@PrepareForTest({ControllerUtil.class, JSONUtil.class})
@PowerMockIgnore( {"javax.management.*", "javax.script.*"})
public class AppRoleServiceTest {

    @InjectMocks
    AppRoleService appRoleService;

    @Mock
    RequestProcessor reqProcessor;
    
    @Mock
    JsonNode jsonNode;

    @Mock
    private CommonUtils commonUtils;

    @Mock
    private EmailUtils emailUtils;
    
    ObjectMapper objMapper = new ObjectMapper();

    @Before
    public void setUp() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, NoSuchFieldException{
    	PowerMockito.mockStatic(ControllerUtil.class);
    	PowerMockito.mockStatic(JSONUtil.class);
    	
    	Whitebox.setInternalState(ControllerUtil.class, "log", LogManager.getLogger(ControllerUtil.class));
        when(JSONUtil.getJSON(Mockito.any(ImmutableMap.class))).thenReturn("log");
 	
        Map<String, String> currentMap = new HashMap<>();
        currentMap.put("apiurl", "http://localhost:8080/vault/v2/sdb");
        currentMap.put("user", "");
        ThreadLocalContext.setCurrentMap(currentMap);

    }

    private Response getMockResponse(HttpStatus status, boolean success, String expectedBody) {
        Response response = new Response();
        response.setHttpstatus(status);
        response.setSuccess(success);
        if (expectedBody!="") {
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
    
    UserDetails getMockUser(String username, boolean isAdmin) {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String selfServToken = "s5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = new UserDetails();
        userDetails.setUsername(username);
        userDetails.setAdmin(isAdmin);
        userDetails.setClientToken(token);
        userDetails.setSelfSupportToken(selfServToken);
        return userDetails;
    }

    @Test
    public void test_createAppRole_successfully() {

        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String [] policies = {"default"};
        AppRole appRole = new AppRole("approle1", policies, true, 1, 100, 0);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole created successfully\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process("/auth/approle/role/create", jsonStr,token)).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}",token)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(token))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.createAppRole(token, appRole, userDetails);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_createAppRole_successfully_with_shared_to() {
        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String [] policies = {"default"};
        List<String> sharedTo = new ArrayList<>();
        sharedTo.add("someone");
        AppRole appRole = new AppRole("approle1", policies, true, 1, 100, 0);
        appRole.setShared_to(sharedTo);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole created successfully\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process("/auth/approle/role/create", jsonStr,token)).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}",token)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);
        UserDetails userDetails = getMockUser(true);

        // update metadata for sharedTo
        String metaJson = "{\"path\":\"metadata/approle/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}";
        when(ControllerUtil.populateAppRoleMetaJson(Mockito.any(), Mockito.any())).thenReturn(metaJson);

        String userMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateUserMetaJson(Mockito.any(), Mockito.any())).thenReturn(userMetaJson);

        String sharedToUserMetaJson = "{\"path\":\"metadata/approle_users/someone/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateSharedToUserMetaJson(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(sharedToUserMetaJson);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(token))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.createAppRole(token, appRole, userDetails);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_createAppRole_shared_to_user_is_owner_failure() {
        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String [] policies = {"default"};
        List<String> sharedTo = new ArrayList<>();
        sharedTo.add("normaluser");
        AppRole appRole = new AppRole("approle1", policies, true, 1, 100, 0);
        appRole.setShared_to(sharedTo);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"An AppRole cannot be shared with the current owner\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process("/auth/approle/role/create", jsonStr, tkn)).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);
        UserDetails userDetails = getMockUser(true);

        // update metadata for sharedTo
        String metaJson = "{\"path\":\"metadata/approle/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"normaluser\",\"sharedTo\":[\"normaluser\"]}}";
        when(ControllerUtil.populateAppRoleMetaJson(Mockito.any(), Mockito.any())).thenReturn(metaJson);

        String userMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"normaluser\",\"sharedTo\":[\"normaluser\"]}}\n";
        when(ControllerUtil.populateUserMetaJson(Mockito.any(), Mockito.any())).thenReturn(userMetaJson);

        String sharedToUserMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"normaluser\",\"sharedTo\":[\"normaluser\"]}}\n";
        when(ControllerUtil.populateSharedToUserMetaJson(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(sharedToUserMetaJson);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.createAppRole(tkn, appRole, userDetails);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_createAppRole_failure_400() {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String [] policies = {"default"};
        AppRole appRole = new AppRole("selfservicesupportrole", policies, true, 1, 100, 0);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: no permission to create an approle named "+appRole.getRole_name()+"\"]}");
        UserDetails userDetails = getMockUser(true);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.createAppRole(token, appRole, userDetails);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_createAppRole_successfully_metadata_failure_reverted() {

        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response response_403 =getMockResponse(HttpStatus.UNAUTHORIZED, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String [] policies = {"default"};
        AppRole appRole = new AppRole("approle1", policies, true, 1, 100, 0);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"AppRole creation failed.\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        when(reqProcessor.process("/auth/approle/role/create", jsonStr,token)).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}",token)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr,token)).thenReturn(response);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(token))).thenReturn(response_403);
        ResponseEntity<String> responseEntityActual = appRoleService.createAppRole(token, appRole, userDetails);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_createAppRole_metadata_failure_empty_sharedTo_reverted() {
        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response response_403 = getMockResponse(HttpStatus.UNAUTHORIZED, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String [] policies = {"default"};
        List<String> sharedTo = new ArrayList<>();
        sharedTo.add("");
        AppRole appRole = new AppRole("approle1", policies, true, 1, 100, 0);
        appRole.setShared_to(sharedTo);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"AppRole creation failed.\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        when(reqProcessor.process("/auth/approle/role/create", jsonStr, tkn)).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);

        // update metadata for sharedTo
        String metaJson = "{\"path\":\"metadata/approle/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"\"]}}";
        when(ControllerUtil.populateAppRoleMetaJson(Mockito.any(), Mockito.any())).thenReturn(metaJson);

        String userMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"\"]}}\n";
        when(ControllerUtil.populateUserMetaJson(Mockito.any(), Mockito.any())).thenReturn(userMetaJson);

        String sharedToUserMetaJson = "{\"path\":\"metadata/approle_users/someone/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"\"]}}\n";
        when(ControllerUtil.populateSharedToUserMetaJson(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(sharedToUserMetaJson);

        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr, tkn)).thenReturn(response);

        UserDetails userDetails = getMockUser(true);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response_403);

        ResponseEntity<String> responseEntityActual = appRoleService.createAppRole(tkn, appRole, userDetails);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_createAppRole_successfully_revert_metadata_failure() {
        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response deleteResponse = getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, false, "");

        Response response_403 = getMockResponse(HttpStatus.UNAUTHORIZED, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String [] policies = {"default"};
        AppRole appRole = new AppRole("approle1", policies, true, 1, 100, 0);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        when(reqProcessor.process("/auth/approle/role/create", jsonStr, tkn)).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr, tkn)).thenReturn(deleteResponse);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response_403);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK)
                .body("{\"messages\":[\"AppRole created however metadata update failed. Please try with AppRole/update \"]}");
        ResponseEntity<String> responseEntityActual = appRoleService.createAppRole(tkn, appRole, userDetails);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_createAppRole_successfully_metadata_failure() {

        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response response500 =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response response_403 =getMockResponse(HttpStatus.UNAUTHORIZED, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String [] policies = {"default"};
        AppRole appRole = new AppRole("approle1", policies, true, 1, 100, 0);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"AppRole creation failed.\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        when(reqProcessor.process("/auth/approle/role/create", jsonStr,token)).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}",token)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr,token)).thenReturn(response500);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(token))).thenReturn(response_403);
        ResponseEntity<String> responseEntityActual = appRoleService.createAppRole(token, appRole, userDetails);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_createAppRole_failure_duplicate() {

        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"approle1\" ]}");
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String [] policies = {"default"};
        AppRole appRole = new AppRole("approle1", policies, true, 1, 100, 0);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"AppRole already exists and can't be created\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("approle1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"approle1\" ]}")).thenReturn(appRolesList);
        when(reqProcessor.process("/auth/approle/role/list","{}",token)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);
        UserDetails userDetails = getMockUser(true);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"approle1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        ResponseEntity<String> responseEntityActual = appRoleService.createAppRole(token, appRole, userDetails);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_createAppRole_InvalidAppRoleInputs() {

        Response response =getMockResponse(HttpStatus.BAD_REQUEST, true, "");
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String [] policies = {"default"};
        AppRole appRole = new AppRole("", policies, true, 1, 100, 0);
        String jsonStr = "{\"role_name\":\"\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Invalid input values for AppRole creation\"]}");
        
        when(reqProcessor.process("/auth/approle/role/create", jsonStr,token)).thenReturn(response);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(false);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);
        UserDetails userDetails = getMockUser(true);
        ResponseEntity<String> responseEntityActual = appRoleService.createAppRole(token, appRole, userDetails);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }
    
    @Test
    public void test_createAppRole_Failure_404() {

        String responseBody = "{\"errors\":[\"Invalid input values for AppRole creation\"]}";
        Response response =getMockResponse(HttpStatus.NOT_FOUND, true, responseBody);
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String [] policies = {"default"};
        AppRole appRole = new AppRole("", policies, true, 1, 100, 0);
        String jsonStr = "{\"role_name\":\"\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.NOT_FOUND).body(responseBody);
        
        when(reqProcessor.process("/auth/approle/role/create", jsonStr,token)).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}",token)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);
        UserDetails userDetails = getMockUser(true);
        ResponseEntity<String> responseEntityActual = appRoleService.createAppRole(token, appRole, userDetails);
        
        assertEquals(HttpStatus.NOT_FOUND, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_readAppRole_successfully() throws JsonProcessingException {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\"data\":{ \"bind_secret_id\": true, \"policies\": [\"test-access-policy\"]}}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"data\":{ \"bind_secret_id\": true, \"policies\": [\"test-access-policy\"]}}");
        Response response =getMockResponse(HttpStatus.OK, true, responseJson);
        String appRole = "approle1";

        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\""+appRole+"\"}",token)).thenReturn(response);

        String role_name = "testapprole01";
        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);

        when(reqProcessor.process("/read", "{\"path\":\"metadata/approle/approle1\"}", token)).thenReturn(mapResponse);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRole(token, appRole);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRole_approle_not_found_failure() throws JsonProcessingException {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK)
                .body("{\"errors\":[\"AppRole doesn't exist\"]}");
        Response response = getMockResponse(HttpStatus.NOT_FOUND, true, "");
        String rolename = "approle1";

        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\""+ rolename +"\"}", tkn)).thenReturn(response);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRole(tkn, rolename);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRole_failure_500() throws JsonProcessingException {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("{} \t");
        Response response = getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, "");
        String rolename = "approle1";

        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\""+ rolename +"\"}", tkn)).thenReturn(response);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRole(tkn, rolename);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }
    
    @Test
    public void test_readAppRole_failed_to_add_sharedTo() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\"data\":{ \"bind_secret_id\": true, \"policies\": [\"test-access-policy\"]}}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK)
                .body("{\"data\":{ \"bind_secret_id\": true, \"policies\": [\"test-access-policy\"]}}");
        Response response =getMockResponse(HttpStatus.OK, true, responseJson);
        String appRole = "approle1";
        
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"" + appRole + "\"}", tkn)).thenReturn(response);

        Response sharedToResponse = getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, "");
        when(reqProcessor.process("/read", "{\"path\":\"metadata/approle/approle1\"}", tkn)).thenReturn(sharedToResponse);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRole(tkn, appRole);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRole_failure_400() {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: no permission to read this AppRole\"]}");
        String appRole = "selfservicesupportrole";
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRole(token, appRole);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRoleId_successfully() {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\"data\":{ \"role_id\": \"f1f72163-287e-b3a4-1fdc-fd21a35c7d57\"}}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"data\":{ \"role_id\": \"f1f72163-287e-b3a4-1fdc-fd21a35c7d57\"}}");
        Response response =getMockResponse(HttpStatus.OK, true, responseJson);
        String appRoleName = "approle1";
        
        when(reqProcessor.process("/auth/approle/role/readRoleID","{\"role_name\":\""+appRoleName+"\"}",token)).thenReturn(response);
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleRoleId(token, appRoleName);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
        
    }

    @Test
    public void test_listAppRoleEntityAssociations_with_safe_successfully() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String roleName = "testAppRole";
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":[\"r_shared_funsafe\"," +
                "\"w_shared_funsafe\"]}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"" + roleName + "\"}", tkn))
                .thenReturn(appRoleResponse);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        List<String> policies = new ArrayList<>();
        policies.add("r_shared_funsafe");
        policies.add("w_shared_funsafe");
        appRoleMetadataMap.put("policies", policies);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);

        ResponseEntity<String> expectedResponse = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[{\"safes\":\"[funsafe]\"}," +
                "{\"iamsvcaccs\":\"[]\"},{\"adsvcaccs\":\"[]\"},{\"azuresvcaccs\":\"[]\"},{\"certs\":\"[]\"}]}");
        assertEquals(expectedResponse, appRoleService.listAppRoleEntityAssociations(roleName, tkn));
    }

    @Test
    public void test_listAppRoleEntityAssociations_with_iamsvcacc_successfully() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String roleName = "testAppRole";
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true,
                "{\"data\": {\"policies\":[\"r_iamsvcacc_323456859_svc_tvt_test4\"]}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"" + roleName + "\"}", tkn))
                .thenReturn(appRoleResponse);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        List<String> policies = new ArrayList<>();
        policies.add("r_iamsvcacc_323456859_svc_tvt_test4");
        appRoleMetadataMap.put("policies", policies);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);

        ResponseEntity<String> expectedResponse = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[{\"safes\":\"[]\"}," +
                "{\"iamsvcaccs\":\"[svc_tvt_test4]\"},{\"adsvcaccs\":\"[]\"},{\"azuresvcaccs\":\"[]\"},{\"certs\":\"[]\"}]}");
        assertEquals(expectedResponse, appRoleService.listAppRoleEntityAssociations(roleName, tkn));
    }

    @Test
    public void test_listAppRoleEntityAssociations_with_adsvcacc_successfully() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String roleName = "testAppRole";
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true,
                "{\"data\": {\"policies\":[\"o_svcacct_svc_acc_multiple_underscores\"]}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"" + roleName + "\"}", tkn))
                .thenReturn(appRoleResponse);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        List<String> policies = new ArrayList<>();
        policies.add("o_svcacct_svc_acc_multiple_underscores");
        appRoleMetadataMap.put("policies", policies);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);

        ResponseEntity<String> expectedResponse = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[{\"safes\":\"[]\"}," +
                "{\"iamsvcaccs\":\"[]\"},{\"adsvcaccs\":\"[svc_acc_multiple_underscores]\"},{\"azuresvcaccs\":\"[]\"},{\"certs\":\"[]\"}]}");
        assertEquals(expectedResponse, appRoleService.listAppRoleEntityAssociations(roleName, tkn));
    }

    @Test
    public void test_listAppRoleEntityAssociations_with_azuresvcacc_successfully() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String roleName = "testAppRole";
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true,
                "{\"data\": {\"policies\":[\"o_svcacct_svc_acc_multiple_underscores\"]}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"" + roleName + "\"}", tkn))
                .thenReturn(appRoleResponse);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        List<String> policies = new ArrayList<>();
        policies.add("o_svcacct_svc_acc_multiple_underscores");
        appRoleMetadataMap.put("policies", policies);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);

        ResponseEntity<String> expectedResponse = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[{\"safes\":\"[]\"}," +
                "{\"iamsvcaccs\":\"[]\"},{\"adsvcaccs\":\"[svc_acc_multiple_underscores]\"},{\"azuresvcaccs\":\"[]\"},{\"certs\":\"[]\"}]}");
        assertEquals(expectedResponse, appRoleService.listAppRoleEntityAssociations(roleName, tkn));
    }

    @Test
    public void test_listAppRoleEntityAssociations_with_cert_successfully() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String roleName = "testAppRole";
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true,
                "{\"data\": {\"policies\":[\"r_cert_CertificateName.t-mobile.com\"]}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"" + roleName + "\"}", tkn))
                .thenReturn(appRoleResponse);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        List<String> policies = new ArrayList<>();
        policies.add("r_cert_CertificateName.t-mobile.com");
        appRoleMetadataMap.put("policies", policies);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);

        ResponseEntity<String> expectedResponse = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[{\"safes\":\"[]\"}," +
                "{\"iamsvcaccs\":\"[]\"},{\"adsvcaccs\":\"[]\"},{\"azuresvcaccs\":\"[]\"},{\"certs\":\"[CertificateName.t-mobile.com]\"}]}");
        assertEquals(expectedResponse, appRoleService.listAppRoleEntityAssociations(roleName, tkn));
    }

    @Test
    public void test_listAppRoleEntityAssociations_approle_not_found_failure() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String roleName = "testAppRole";
        Response appRoleResponse = getMockResponse(HttpStatus.NOT_FOUND, false, "{}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"" + roleName + "\"}", tkn))
                .thenReturn(appRoleResponse);

        ResponseEntity<String> expectedResponse = ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body("{\"errors\":[\"AppRole doesn't exist\"]}");
        assertEquals(expectedResponse, appRoleService.listAppRoleEntityAssociations(roleName, tkn));
    }

    @Test
    public void test_listAppRoleEntityAssociations_empty_response_map_failure() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String roleName = "testAppRole";
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":[\"r_shared_funsafe\"," +
                "\"w_shared_funsafe\"]}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"" + roleName + "\"}", tkn))
                .thenReturn(appRoleResponse);

        Map<String, Object> responseMap = new HashMap<>();
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);

        ResponseEntity<String> expectedResponse = ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body("{\"errors\":[\"AppRole doesn't exist\"]}");
        assertEquals(expectedResponse, appRoleService.listAppRoleEntityAssociations(roleName, tkn));
    }

    @Test
    public void test_listAppRoleEntityAssociations_no_policies_success() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String roleName = "testAppRole";
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":[]}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"" + roleName + "\"}", tkn))
                .thenReturn(appRoleResponse);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("token_max_ttl", 100);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);

        ResponseEntity<String> expectedResponse = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":" +
                "[{\"safes\":\"[]\"},{\"iamsvcaccs\":\"[]\"},{\"adsvcaccs\":\"[]\"},{\"azuresvcaccs\":\"[]\"},{\"certs\":\"[]\"}]}");
        assertEquals(expectedResponse, appRoleService.listAppRoleEntityAssociations(roleName, tkn));
    }

    @Test
    public void test_isAppRoleOwner_successfully() {
        UserDetails userDetails = getMockUser(false);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        List<String> sharedTo = new ArrayList<>();
        sharedTo.add("shareduser");
        appRoleMetadataDetails.setSharedTo(sharedTo);
        appRoleMetadataDetails.setCreatedBy("normaluser");
        assertTrue(appRoleService.isAppRoleOwner(userDetails.getUsername(), appRoleMetadataDetails));
    }

    @Test
    public void test_isAppRoleOwner_failure_different_owner() {
        UserDetails userDetails = getMockUser(false);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        List<String> sharedTo = new ArrayList<>();
        sharedTo.add("shareduser");
        appRoleMetadataDetails.setSharedTo(sharedTo);
        appRoleMetadataDetails.setCreatedBy("someotheruser");
        assertFalse(appRoleService.isAppRoleOwner(userDetails.getUsername(), appRoleMetadataDetails));
    }

    @Test
    public void test_isAppRoleOwner_failure_null_metadata_details() {
        UserDetails userDetails = getMockUser(false);
        assertFalse(appRoleService.isAppRoleOwner(userDetails.getUsername(), null));
    }

    @Test
    public void test_createSecretId_successfully() {
        String responseJson = "{\"data\":{ \"secret_id\": \"5973a6de-38c1-0402-46a3-6d76e38b773c\", \"secret_id_accessor\": \"cda12712-9845-c271-aeb1-833681fac295\"}}";
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, responseJson);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Secret ID created for AppRole\"]}");
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        AppRoleSecretData appRoleSecretData = new AppRoleSecretData("approle1", new SecretData("dev", "appl"));

        String jsonStr = "{\"role_name\":\"approle1\",\"data\":{\"env\":\"dev\",\"appname\":\"appl\"}}";
        
        when(reqProcessor.process("/auth/approle/secretid/create", jsonStr,token)).thenReturn(response);
        when(ControllerUtil.convertAppRoleSecretIdToLowerCase(Mockito.any())).thenReturn(jsonStr);
        when(JSONUtil.getJSON(appRoleSecretData)).thenReturn(jsonStr);
        
        ResponseEntity<String> responseEntityActual = appRoleService.createsecretId(token, appRoleSecretData);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_createSecretId_access_denied_failure() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        AppRoleSecretData appRoleSecretData = new AppRoleSecretData("iamportal_admin_approle",
                new SecretData("dev", "appl"));

        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("{\"errors\":[\"Access denied: no permission to create secretID for this AppRole\"]}");
        ResponseEntity<String> responseEntityActual = appRoleService.createsecretId(tkn, appRoleSecretData);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_createSecretId_failure() {
        String responseJson = "{\"error\":[\"Internal Server Error\"]}";
        Response response =getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, responseJson);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseJson);
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        AppRoleSecretData appRoleSecretData = new AppRoleSecretData("approle1", new SecretData("dev", "appl"));

        String jsonStr = "{\"role_name\":\"approle1\",\"data\":{\"env\":\"dev\",\"appname\":\"appl\"}}";

        when(reqProcessor.process("/auth/approle/secretid/create", jsonStr,token)).thenReturn(response);
        when(ControllerUtil.convertAppRoleSecretIdToLowerCase(Mockito.any())).thenReturn(jsonStr);
        when(JSONUtil.getJSON(appRoleSecretData)).thenReturn(jsonStr);

        ResponseEntity<String> responseEntityActual = appRoleService.createsecretId(token, appRoleSecretData);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_readSecretId_successfully() {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\"data\":{ \"secret_id\": \"5973a6de-38c1-0402-46a3-6d76e38b773c\", \"secret_id_accessor\": \"cda12712-9845-c271-aeb1-833681fac295\"}}";
        Response response =getMockResponse(HttpStatus.OK, true, responseJson);
        String appRoleName = "approle1";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);
        
        when(reqProcessor.process("/auth/approle/secretid/lookup","{\"role_name\":\""+appRoleName+"\"}",token)).thenReturn(response);
        
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleSecretId(token, appRoleName);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_deleteSecretIds_successfully() {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        AppRoleAccessorIds appRoleAccessorIds = new AppRoleAccessorIds();
        appRoleAccessorIds.setRole_name(role_name);
        appRoleAccessorIds.setAccessorIds(new String[] {"deleted01", "failed01"});
        UserDetails userDetails = getMockUser(true);
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/delete/secretids"),Mockito.any(),Mockito.any())).thenReturn(response);
        ResponseEntity<String> responseEntityActual=  appRoleService.deleteSecretIds(token, appRoleAccessorIds,userDetails);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
    }

    @Test
    public void test_deleteSecretIds_successfully_with_shared_to() throws JsonProcessingException {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        AppRoleAccessorIds appRoleAccessorIds = new AppRoleAccessorIds();
        appRoleAccessorIds.setRole_name(role_name);
        appRoleAccessorIds.setAccessorIds(new String[] {"deleted01", "failed01"});
        UserDetails userDetails = getMockUser(false);
        List<String> sharedTo = new ArrayList<>();
        sharedTo.add("normaluser");

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        appRoleMetadataDetails.setSharedTo(sharedTo);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        appRoleMetadataMap.put("sharedTo", sharedTo);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/delete/secretids"), Mockito.any(), Mockito.any())).thenReturn(response);
        ResponseEntity<String> responseEntityActual=  appRoleService.deleteSecretIds(token, appRoleAccessorIds,userDetails);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
    }

    @Test
    public void test_deleteSecretIds_Failure_500() {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        AppRoleAccessorIds appRoleAccessorIds = new AppRoleAccessorIds();
        appRoleAccessorIds.setRole_name(role_name);
        appRoleAccessorIds.setAccessorIds(new String[] {"deleted01", "failed01"});
        UserDetails userDetails = getMockUser(true);
        Response response =getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, "");
        response.setResponse("failed to find accessor entry for secret_id_accessor");
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/delete/secretids"),Mockito.any(),Mockito.any())).thenReturn(response);
        ResponseEntity<String> responseEntityActual=  appRoleService.deleteSecretIds(token, appRoleAccessorIds,userDetails);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
    }
    @Test
    public void test_deleteSecretIds_Failure_400() {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        AppRoleAccessorIds appRoleAccessorIds = new AppRoleAccessorIds();
        appRoleAccessorIds.setRole_name(role_name);
        appRoleAccessorIds.setAccessorIds(new String[] {"deleted01", "failed01"});
        UserDetails userDetails = getMockUser(true);
        Response response =getMockResponse(HttpStatus.BAD_REQUEST, true, "");
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/delete/secretids"),Mockito.any(),Mockito.any())).thenReturn(response);
        ResponseEntity<String> responseEntityActual=  appRoleService.deleteSecretIds(token, appRoleAccessorIds,userDetails);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
    }

    @Test
    public void test_deleteAppRole_successfully_with_all_policies() throws Exception{

        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseOK =getMockResponse(HttpStatus.OK, true, "{\"createdBy\":\"safeadmin\"}");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole deleted\"]}");
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";

        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr, tkn)).thenReturn(response);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.any(),Mockito.eq(tkn))).thenReturn(responseOK);
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("createdBy", "safeadmin");
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);
        when(reqProcessor.process(Mockito.eq("/delete"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        // START - isAllowed
        String approleusername="safeadmin";
        String role_name=appRole.getRole_name();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
        String appRoleResponseJspn = "{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"safeadmin\",\"sharedTo\":null}}";
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",approleusername);
        appRoleResponseMap.put ("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleResponseJspn)).thenReturn(appRoleResponseMap);
        // END - isAllowed
        Response permissionResponse =getMockResponse(HttpStatus.OK, true, "");
        when(ControllerUtil.canDeleteRole(appRole.getRole_name(), tkn, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH)).thenReturn(permissionResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":[\"r_cert_\"," +
                "\"r_externalcerts_\",\"r_externalcerts_\",\"r_users_\",\"r_shared_\",\"r_apps_\",\"r_iamsvcacc_\",\"r_svcacct_\",\"r_azuresvcacc_\",\"w_cert_\",\"d_cert_\",\"o_cert_\"" +
                ",\"o_azuresvcacc_\",\"w_externalcerts_\",\"d_externalcerts_\",\"o_externalcerts_\",\"w_users_\",\"d_users_\",\"w_shared_\",\"d_shared_\",\"w_apps_\",\"d_apps_\",\"w_iamsvcacc_\"" +
                ",\"d_iamsvcacc_\",\"w_svcacct_\",\"d_svcacct_\",\"w_azuresvcacc_\",\"d_azuresvcacc_\",\"o_iamsvcacc_\",\"o_svcacc_\"]}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        Response metaDataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(ControllerUtil.updateMetadata(Mockito.anyMap(), Mockito.eq(tkn))).thenReturn(metaDataResponse);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(tkn, appRole, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_deleteAppRole_with_abnormal_policy_names_successfully() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseOK =getMockResponse(HttpStatus.OK, true, "{\"createdBy\":\"safeadmin\"}");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole deleted\"]}");
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";

        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr, tkn)).thenReturn(response);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.any(),Mockito.eq(tkn))).thenReturn(responseOK);
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("createdBy", "safeadmin");
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);
        when(reqProcessor.process(Mockito.eq("/delete"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        // START - isAllowed
        String approleusername="safeadmin";
        String role_name=appRole.getRole_name();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
        String appRoleResponseJspn = "{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"safeadmin\",\"sharedTo\":null}}";
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",approleusername);
        appRoleResponseMap.put ("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleResponseJspn)).thenReturn(appRoleResponseMap);
        // END - isAllowed
        Response permissionResponse =getMockResponse(HttpStatus.OK, true, "");
        when(ControllerUtil.canDeleteRole(appRole.getRole_name(), tkn, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH)).thenReturn(permissionResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":[\"some weird policy name\", \"default\", \"comma\"]}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        Response metaDataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(ControllerUtil.updateMetadata(Mockito.anyMap(), Mockito.eq(tkn))).thenReturn(metaDataResponse);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(tkn, appRole, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_deleteAppRole_successfully() throws Exception{

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseOK =getMockResponse(HttpStatus.OK, true, "{\"createdBy\":\"safeadmin\"}");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole deleted\"]}");
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";

        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr,token)).thenReturn(response);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.any(),Mockito.eq(token))).thenReturn(responseOK);
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("createdBy", "safeadmin");
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);
        when(reqProcessor.process(Mockito.eq("/delete"),Mockito.any(),Mockito.eq(token))).thenReturn(response);
        // START - isAllowed
        String approleusername="safeadmin";
        String role_name=appRole.getRole_name();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
    	String appRoleResponseJspn = "{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"safeadmin\",\"sharedTo\":null}}";
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",approleusername);
        appRoleResponseMap.put ("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleResponseJspn)).thenReturn(appRoleResponseMap);
        // END - isAllowed
        Response permissionResponse =getMockResponse(HttpStatus.OK, true, "");
        when(ControllerUtil.canDeleteRole(appRole.getRole_name(), token, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH)).thenReturn(permissionResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}",token)).thenReturn(appRoleResponse);
        Response metaDataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(ControllerUtil.updateMetadata(Mockito.anyMap(), Mockito.eq(token))).thenReturn(metaDataResponse);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(token, appRole, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_deleteAppRole_with_shared_to_successfully() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseOK = getMockResponse(HttpStatus.OK, true, "{\"createdBy\":\"safeadmin\", \"sharedTo\":\"someone\"}");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole deleted\"]}");
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";
        List<String> sharedToList = new ArrayList<>();
        sharedToList.add("someone");

        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr, tkn)).thenReturn(response);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.any(),Mockito.eq(tkn))).thenReturn(responseOK);
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("createdBy", "safeadmin");
        when(reqProcessor.process(Mockito.eq("/delete"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        // START - isAllowed
        String approleusername="safeadmin";
        String role_name = appRole.getRole_name();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;

        AppRoleMetadata appRoleMetadata = getAppRoleMetadata(path, approleusername, role_name);
        AppRoleMetadataDetails appRoleMetadataDetails = appRoleMetadata.getAppRoleMetadataDetails();
        appRoleMetadataDetails.setSharedTo(sharedToList);
        appRoleMetadata.setAppRoleMetadataDetails(appRoleMetadataDetails);

        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, objMapper.writeValueAsString(appRoleMetadata));
        when(reqProcessor.process(Mockito.eq("/read"), Mockito.eq("{\"path\":\""+path+"\"}"), Mockito.any()))
                .thenReturn(approleMetadataResponse);
        String appRoleResponseJspn = "{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"safeadmin\",\"sharedTo\":[\"someone\"]}}";
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", approleusername);
        appRoleMetadataMap.put("sharedTo", sharedToList);
        appRoleResponseMap.put ("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleResponseJspn)).thenReturn(appRoleResponseMap);
        // END - isAllowed
        Response permissionResponse = getMockResponse(HttpStatus.OK, true, "");
        when(ControllerUtil.canDeleteRole(appRole.getRole_name(), tkn, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH)).thenReturn(permissionResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        Response metaDataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(ControllerUtil.updateMetadata(Mockito.anyMap(), Mockito.eq(tkn))).thenReturn(metaDataResponse);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(tkn, appRole, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_deleteAppRole_empty_shared_to_list_successfully() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseOK = getMockResponse(HttpStatus.OK, true, "{\"createdBy\":\"safeadmin\", \"sharedTo\":\"\"}");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole deleted\"]}");
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";
        List<String> sharedToList = new ArrayList<>();

        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr, tkn)).thenReturn(response);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.any(),Mockito.eq(tkn))).thenReturn(responseOK);
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("createdBy", "safeadmin");
        when(reqProcessor.process(Mockito.eq("/delete"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        // START - isAllowed
        String approleusername="safeadmin";
        String role_name = appRole.getRole_name();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;

        AppRoleMetadata appRoleMetadata = getAppRoleMetadata(path, approleusername, role_name);
        AppRoleMetadataDetails appRoleMetadataDetails = appRoleMetadata.getAppRoleMetadataDetails();
        appRoleMetadataDetails.setSharedTo(sharedToList);
        appRoleMetadata.setAppRoleMetadataDetails(appRoleMetadataDetails);

        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, objMapper.writeValueAsString(appRoleMetadata));
        when(reqProcessor.process(Mockito.eq("/read"), Mockito.eq("{\"path\":\""+path+"\"}"), Mockito.any()))
                .thenReturn(approleMetadataResponse);
        String appRoleResponseJspn = "{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"safeadmin\",\"sharedTo\":[]}}";
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", approleusername);
        appRoleMetadataMap.put("sharedTo", sharedToList);
        appRoleResponseMap.put ("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleResponseJspn)).thenReturn(appRoleResponseMap);
        // END - isAllowed
        Response permissionResponse = getMockResponse(HttpStatus.OK, true, "");
        when(ControllerUtil.canDeleteRole(appRole.getRole_name(), tkn, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH)).thenReturn(permissionResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        Response metaDataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(ControllerUtil.updateMetadata(Mockito.anyMap(), Mockito.eq(tkn))).thenReturn(metaDataResponse);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(tkn, appRole, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_deleteAppRole_successfully_meta_failure() throws Exception {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response response404 =getMockResponse(HttpStatus.NOT_FOUND, true, "");
        Response responseOK =getMockResponse(HttpStatus.OK, true, "{\"createdBy\":\"safeadmin\"}");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole deleted, metadata delete failed\"]}");
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";

        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr,token)).thenReturn(response);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.any(),Mockito.eq(token))).thenReturn(responseOK);
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("createdBy", "safeadmin");
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);
        when(reqProcessor.process(Mockito.eq("/delete"),Mockito.any(),Mockito.eq(token))).thenReturn(response404);
        // START - isAllowed
        String approleusername="safeadmin";
        String role_name=appRole.getRole_name();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
    	String appRoleResponseJspn = "{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"safeadmin\",\"sharedTo\":null}}";
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",approleusername);
        appRoleResponseMap.put ("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleResponseJspn)).thenReturn(appRoleResponseMap);
        // END - isAllowed
        Response permissionResponse =getMockResponse(HttpStatus.OK, true, "");
        when(ControllerUtil.canDeleteRole(appRole.getRole_name(), token, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH)).thenReturn(permissionResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}",token)).thenReturn(appRoleResponse);
        Response metaDataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(ControllerUtil.updateMetadata(Mockito.anyMap(), Mockito.eq(token))).thenReturn(metaDataResponse);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(token, appRole, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_deleteAppRole_successfully_normaluser() {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseOK =getMockResponse(HttpStatus.OK, true, "{\"data\":{\"createdBy\":\"normaluser\"}}");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole deleted\"]}");
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";

        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr,token)).thenReturn(response);
        UserDetails userDetails = getMockUser(false);
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.any(),Mockito.eq(token))).thenReturn(responseOK);
        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> data = new HashMap<>();
        data.put("createdBy", "normaluser");
        responseMap.put("data", data);
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);
        when(reqProcessor.process(Mockito.eq("/delete"),Mockito.any(),Mockito.eq(token))).thenReturn(response);
        Response permissionResponse =getMockResponse(HttpStatus.OK, true, "");
        when(ControllerUtil.canDeleteRole(appRole.getRole_name(), token, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH)).thenReturn(permissionResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}",token)).thenReturn(appRoleResponse);
        Response metaDataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(ControllerUtil.updateMetadata(Mockito.anyMap(), Mockito.eq(token))).thenReturn(metaDataResponse);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(token, appRole, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_deleteAppRole_successfully_metadata404() throws Exception{

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response response404 =getMockResponse(HttpStatus.NOT_FOUND, true, "");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole deleted\"]}");
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";

        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr,token)).thenReturn(response);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.any(),Mockito.eq(token))).thenReturn(response404);
        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> data = new HashMap<>();
        data.put("createdBy", "normaluser");
        responseMap.put("data", data);
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);
        when(reqProcessor.process(Mockito.eq("/delete"),Mockito.any(),Mockito.eq(token))).thenReturn(response);
        // START - isAllowed
        String approleusername="safeadmin";
        String role_name=appRole.getRole_name();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
        // END - isAllowed
        Response permissionResponse =getMockResponse(HttpStatus.OK, true, "");
        when(ControllerUtil.canDeleteRole(appRole.getRole_name(), token, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH)).thenReturn(permissionResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}",token)).thenReturn(appRoleResponse);
        Response metaDataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(ControllerUtil.updateMetadata(Mockito.anyMap(), Mockito.eq(token))).thenReturn(metaDataResponse);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(token, appRole, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_deleteAppRole_failure_metadata_403() {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response response403 =getMockResponse(HttpStatus.UNAUTHORIZED, true, "");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Either role doesn't exist or you don't have enough permission to remove this role from Safe\"]}");
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";

        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr,token)).thenReturn(response);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.any(),Mockito.eq(token))).thenReturn(response403);
        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> data = new HashMap<>();
        data.put("createdBy", "normaluser");
        responseMap.put("data", data);
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);
        when(reqProcessor.process(Mockito.eq("/delete"),Mockito.any(),Mockito.eq(token))).thenReturn(response);
        Response permissionResponse =getMockResponse(HttpStatus.UNAUTHORIZED, true, "Either role doesn't exist or you don't have enough permission to remove this role from Safe");
        when(ControllerUtil.canDeleteRole(appRole.getRole_name(), token, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH)).thenReturn(permissionResponse);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(token, appRole, userDetails);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_deleteAppRole_failure_401() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        String responseJson = "{\"errors\":[\"{} \t\"]}";
        Response response = getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, responseJson);
        Response response401 = getMockResponse(HttpStatus.UNAUTHORIZED, true, "{}");

        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseJson);
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";

        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr, tkn)).thenReturn(response);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response401);
        Map<String, Object> responseMap = new HashMap<>();
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);
        when(reqProcessor.process(Mockito.eq("/delete"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        // START - isAllowed
        String approleusername="safeadmin";
        String role_name=appRole.getRole_name();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
        String appRoleResponseJspn = "{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"safeadmin\",\"sharedTo\":null}}";
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",approleusername);
        appRoleResponseMap.put ("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleResponseJspn)).thenReturn(appRoleResponseMap);
        // END - isAllowed
        Response permissionResponse = getMockResponse(HttpStatus.UNAUTHORIZED, false, "");
        when(ControllerUtil.canDeleteRole(appRole.getRole_name(), tkn, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH)).thenReturn(permissionResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        Response metaDataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(ControllerUtil.updateMetadata(Mockito.anyMap(), Mockito.eq(tkn))).thenReturn(metaDataResponse);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(tkn, appRole, userDetails);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_deleteAppRole_failure_reading_appRole() throws Exception{
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        String responseJson = "{\"error\":[\"Internal Server Error\"]}";
        Response response = getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, responseJson);
        Response responseOK = getMockResponse(HttpStatus.OK, true, "{\"createdBy\":\"safeadmin\"}");

        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseJson);
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";

        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr, tkn)).thenReturn(response);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.any(),Mockito.eq(tkn))).thenReturn(responseOK);
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("createdBy", "safeadmin");
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);
        when(reqProcessor.process(Mockito.eq("/delete"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        // START - isAllowed
        String approleusername = "safeadmin";
        String role_name=appRole.getRole_name();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
        String appRoleResponseJspn = "{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"safeadmin\",\"sharedTo\":null}}";
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", approleusername);
        appRoleResponseMap.put ("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleResponseJspn)).thenReturn(appRoleResponseMap);
        // END - isAllowed
        Response permissionResponse = getMockResponse(HttpStatus.OK, true, "");
        when(ControllerUtil.canDeleteRole(appRole.getRole_name(), tkn, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH)).thenReturn(permissionResponse);
        Response responseData = getMockResponse(HttpStatus.OK, true, "");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\""+appRole.getRole_name()+"\"}", tkn)).thenReturn(responseData);
        Response appRoleResponse = getMockResponse(HttpStatus.NOT_FOUND, false, "{}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        Response metaDataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(ControllerUtil.updateMetadata(Mockito.anyMap(), Mockito.eq(tkn))).thenReturn(metaDataResponse);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(tkn, appRole, userDetails);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_deleteAppRole_null_policies_array() throws Exception{
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        String responseJson = "{\"error\":[\"Internal Server Error\"]}";
        Response response = getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, responseJson);
        Response responseOK = getMockResponse(HttpStatus.OK, true, "{\"createdBy\":\"safeadmin\"}");

        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseJson);
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";

        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr, tkn)).thenReturn(response);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.any(),Mockito.eq(tkn))).thenReturn(responseOK);
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("createdBy", "safeadmin");
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);
        when(reqProcessor.process(Mockito.eq("/delete"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        // START - isAllowed
        String approleusername="safeadmin";
        String role_name=appRole.getRole_name();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
        String appRoleResponseJspn = "{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"safeadmin\",\"sharedTo\":null}}";
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",approleusername);
        appRoleResponseMap.put ("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleResponseJspn)).thenReturn(appRoleResponseMap);
        // END - isAllowed
        Response permissionResponse = getMockResponse(HttpStatus.OK, true, "");
        when(ControllerUtil.canDeleteRole(appRole.getRole_name(), tkn, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH))
                .thenReturn(permissionResponse);
        Response responseData = getMockResponse(HttpStatus.OK, true, "");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\""+appRole.getRole_name()+"\"}", tkn))
                .thenReturn(responseData);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"somekey\":\"somevalue\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        Response metaDataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(ControllerUtil.updateMetadata(Mockito.anyMap(), Mockito.eq(tkn))).thenReturn(metaDataResponse);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(tkn, appRole, userDetails);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_deleteAppRole_json_parse_exception() throws Exception{
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        String responseJson = "{\"error\":[\"Internal Server Error\"]}";
        Response response = getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, responseJson);
        Response responseOK = getMockResponse(HttpStatus.OK, true, "{\"createdBy\":\"safeadmin\"}");

        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseJson);
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";

        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr, tkn)).thenReturn(response);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.any(),Mockito.eq(tkn))).thenReturn(responseOK);
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("createdBy", "safeadmin");
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);
        when(reqProcessor.process(Mockito.eq("/delete"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        // START - isAllowed
        String approleusername="safeadmin";
        String role_name=appRole.getRole_name();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
        String appRoleResponseJspn = "{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"safeadmin\",\"sharedTo\":null}}";
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",approleusername);
        appRoleResponseMap.put ("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleResponseJspn)).thenReturn(appRoleResponseMap);
        // END - isAllowed
        Response permissionResponse = getMockResponse(HttpStatus.OK, true, "");
        when(ControllerUtil.canDeleteRole(appRole.getRole_name(), tkn, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH))
                .thenReturn(permissionResponse);
        Response responseData = getMockResponse(HttpStatus.OK, true, "");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\""+appRole.getRole_name()+"\"}", tkn))
                .thenReturn(responseData);
        // JSON Parse Exception
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": }");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        Response metaDataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(ControllerUtil.updateMetadata(Mockito.anyMap(), Mockito.eq(tkn))).thenReturn(metaDataResponse);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(tkn, appRole, userDetails);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_deleteAppRole_failure() throws Exception{

        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        String responseJson = "{\"error\":[\"Internal Server Error\"]}";
        Response response =getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, responseJson);
        Response responseOK =getMockResponse(HttpStatus.OK, true, "{\"createdBy\":\"safeadmin\"}");

        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseJson);
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";

        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr, tkn)).thenReturn(response);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.any(),Mockito.eq(tkn))).thenReturn(responseOK);
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("createdBy", "safeadmin");
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);
        when(reqProcessor.process(Mockito.eq("/delete"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        // START - isAllowed
        String approleusername="safeadmin";
        String role_name=appRole.getRole_name();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
    	String appRoleResponseJspn = "{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"safeadmin\",\"sharedTo\":null}}";
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",approleusername);
        appRoleResponseMap.put ("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleResponseJspn)).thenReturn(appRoleResponseMap);
        // END - isAllowed
        Response permissionResponse =getMockResponse(HttpStatus.OK, true, "");
        when(ControllerUtil.canDeleteRole(appRole.getRole_name(), tkn, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH)).thenReturn(permissionResponse);
        Response responseData =getMockResponse(HttpStatus.OK, true, "");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\""+appRole.getRole_name()+"\"}", tkn)).thenReturn(responseData);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        Response metaDataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(ControllerUtil.updateMetadata(Mockito.anyMap(), Mockito.eq(tkn))).thenReturn(metaDataResponse);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(tkn, appRole, userDetails);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_deleteAppRole_failure_500() throws Exception{

        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        String responseJson = "{\"error\":[\"Error reading role info\"]}";
        Response response =getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, responseJson);
        Response responseOK =getMockResponse(HttpStatus.OK, true, "{\"createdBy\":\"safeadmin\"}");

        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseJson);
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";

        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/role/delete",jsonStr, tkn)).thenReturn(response);
        UserDetails userDetails = getMockUser(true);
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.any(),Mockito.eq(tkn))).thenReturn(responseOK);
        Map<String, Object> responseMap = new HashMap<>();
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);
        when(reqProcessor.process(Mockito.eq("/delete"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        // START - isAllowed
        String approleusername="safeadmin";
        String role_name=appRole.getRole_name();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
    	String appRoleResponseJspn = "{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"safeadmin\",\"sharedTo\":null}}";
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",approleusername);
        appRoleResponseMap.put ("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleResponseJspn)).thenReturn(appRoleResponseMap);
        // END - isAllowed
        Response permissionResponse =getMockResponse(HttpStatus.OK, true, "");
        when(ControllerUtil.canDeleteRole(appRole.getRole_name(), tkn, userDetails, TVaultConstants.APPROLE_METADATA_MOUNT_PATH)).thenReturn(permissionResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        Response metaDataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        when(ControllerUtil.updateMetadata(Mockito.anyMap(), Mockito.eq(tkn))).thenReturn(metaDataResponse);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(tkn, appRole, userDetails);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_deleteAppRole_failure_403() {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "selfservicesupportrole";
        String responseJson = "{\"errors\":[\"Access denied: no permission to remove this AppRole\"]}";
        Response response =getMockResponse(HttpStatus.BAD_REQUEST, true, responseJson);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseJson);
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleId);
        UserDetails userDetails = getMockUser(true);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteAppRole(token, appRole, userDetails);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_deleteSecretId_successfully() {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        AppRoleNameSecretId appRoleNameSecretId = new AppRoleNameSecretId(appRoleId, "5973a6de-38c1-0402-46a3-6d76e38b773c");
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        String jsonStr = "{\"role_name\":\"approle1\",\"secret_id\":\"5973a6de-38c1-0402-46a3-6d76e38b773c\"}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"SecretId for AppRole deleted\"]}");
        
        when(JSONUtil.getJSON(appRoleNameSecretId)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/secret/delete",jsonStr,token)).thenReturn(response);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteSecretId(token, appRoleNameSecretId);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
        
    }

    @Test
    public void test_deleteSecretId_failure_400() {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "selfservicesupportrole";
        AppRoleNameSecretId appRoleNameSecretId = new AppRoleNameSecretId(appRoleId, "5973a6de-38c1-0402-46a3-6d76e38b773c");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: no permission to delete secretId for this approle\"]}");

        ResponseEntity<String> responseEntityActual = appRoleService.deleteSecretId(token, appRoleNameSecretId);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_deleteSecretId_failure() {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String appRoleId = "approle1";
        AppRoleNameSecretId appRoleNameSecretId = new AppRoleNameSecretId(appRoleId, "5973a6de-38c1-0402-46a3-6d76e38b773c");
        String jsonStr = "{\"role_name\":\"approle1\",\"secret_id\":\"5973a6de-38c1-0402-46a3-6d76e38b773c\"}";

        String responseJson = "{\"error\":[\"Internal Server Error\"]}";
        Response response =getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, responseJson);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseJson);

        when(JSONUtil.getJSON(appRoleNameSecretId)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/secret/delete",jsonStr,token)).thenReturn(response);
        ResponseEntity<String> responseEntityActual = appRoleService.deleteSecretId(token, appRoleNameSecretId);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_readAccessorIds_MatchWithSelfSupportAdminApprole() {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "azure_admin_approle";
        String responseJson = "{\r\n" +
                "  \"keys\": [\r\n" +
                "    \"generated-accessor-id1\"\r\n" +
                "  ]\r\n" +
                "}";
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);

        Map<String, Object> responseMap = new HashMap<>();
        ArrayList<String> accessorIds = new ArrayList<String>();
        accessorIds.add("generated-accessor-id1");
        responseMap.put("keys", accessorIds);
        when(ControllerUtil.parseJson(responseJson)).thenReturn(responseMap);

        when(reqProcessor.process("/auth/approle/role/accessors/list", "{\"role_name\":\""+role_name+"\"}",token)).thenReturn(response);
        List<String> actualAccessorIds = appRoleService.readAccessorIds(token, role_name);
        assertNull(actualAccessorIds);
        assertEquals(null, actualAccessorIds);
    }

    @Test
    public void test_AssociateAppRole_succssfully() throws Exception {

        Response response = getMockResponse(HttpStatus.OK, true, "");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle associated to SDB\"]}");
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        SafeAppRoleAccess safeAppRoleAccess = new SafeAppRoleAccess("approle1", "shared/mysafe01", "write");
        String jsonStr = "{\"role_name\":\"approle1\",\"path\":\"shared/mysafe01\",\"access\":\"write\"}";
        Map<String, Object> requestMap = new ObjectMapper().readValue(jsonStr, new TypeReference<Map<String, Object>>(){});
        Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
        Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(requestMap);
        when(reqProcessor.process(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(response);
        when(ControllerUtil.isValidSafePath(Mockito.any())).thenReturn(true);
        when(ControllerUtil.isValidSafe(Mockito.any(), Mockito.any())).thenReturn(true);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"),Mockito.any(),Mockito.eq(token))).thenReturn(configureAppRoleResponse);
        when(ControllerUtil.areSafeAppRoleInputsValid(Mockito.anyMap())).thenReturn(true);
        when(ControllerUtil.canAddPermission(Mockito.any(), Mockito.any())).thenReturn(true);
        when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.any())).thenReturn(updateMetadataResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}",token)).thenReturn(appRoleResponse);
        ResponseEntity<String> responseEntityActual =  appRoleService.associateApprole(token, safeAppRoleAccess);
        
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_AssociateAppRole_read_access_successfully() throws Exception {
        Response response = getMockResponse(HttpStatus.OK, true, "");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle associated to SDB\"]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        SafeAppRoleAccess safeAppRoleAccess = new SafeAppRoleAccess("approle1", "shared/mysafe01", "read");
        String jsonStr = "{\"role_name\":\"approle1\",\"path\":\"shared/mysafe01\",\"access\":\"read\"}";
        Map<String, Object> requestMap = new ObjectMapper().readValue(jsonStr, new TypeReference<Map<String, Object>>(){});
        Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
        Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(requestMap);
        when(reqProcessor.process(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(response);
        when(ControllerUtil.isValidSafePath(Mockito.any())).thenReturn(true);
        when(ControllerUtil.isValidSafe(Mockito.any(), Mockito.any())).thenReturn(true);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"),Mockito.any(),Mockito.eq(tkn))).thenReturn(configureAppRoleResponse);
        when(ControllerUtil.areSafeAppRoleInputsValid(Mockito.anyMap())).thenReturn(true);
        when(ControllerUtil.canAddPermission(Mockito.any(), Mockito.any())).thenReturn(true);
        when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.any())).thenReturn(updateMetadataResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        ResponseEntity<String> responseEntityActual =  appRoleService.associateApprole(tkn, safeAppRoleAccess);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_AssociateAppRole_safe_name_already_exists_failure() throws Exception {
        Response response = getMockResponse(HttpStatus.OK, true, "");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("{\"errors\":[\"Role configuration failed.Contact Admin \"]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        SafeAppRoleAccess safeAppRoleAccess = new SafeAppRoleAccess("approle1", "shared/mysafe01", "read");
        String jsonStr = "{\"role_name\":\"approle1\",\"path\":\"shared/mysafe01\",\"access\":\"read\"}";
        Map<String, Object> requestMap = new ObjectMapper().readValue(jsonStr, new TypeReference<Map<String, Object>>(){});
        Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
        Response updateMetadataResponse = getMockResponse(HttpStatus.OK, true, "");

        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(requestMap);
        when(reqProcessor.process(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(response);
        when(ControllerUtil.isValidSafePath(Mockito.any())).thenReturn(true);
        when(ControllerUtil.isValidSafe(Mockito.any(), Mockito.any())).thenReturn(true);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"),Mockito.any(),Mockito.eq(tkn))).thenReturn(configureAppRoleResponse);
        when(ControllerUtil.areSafeAppRoleInputsValid(Mockito.anyMap())).thenReturn(true);
        when(ControllerUtil.canAddPermission(Mockito.any(), Mockito.any())).thenReturn(true);
        when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.any())).thenReturn(updateMetadataResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        when(ControllerUtil.getSafeType("shared/mysafe01")).thenReturn("shared");
        when(ControllerUtil.getSafeName("shared/mysafe01")).thenReturn("mysafe01");
        when(ControllerUtil.getAllExistingSafeNames("shared", tkn)).thenReturn(Arrays.asList("mysafe01"));
        ResponseEntity<String> responseEntityActual =  appRoleService.associateApprole(tkn, safeAppRoleAccess);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_AssociateAppRole_io_exception_failure() throws Exception {
        Response response = getMockResponse(HttpStatus.OK, true, "");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle associated to SDB\"]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        SafeAppRoleAccess safeAppRoleAccess = new SafeAppRoleAccess("approle1", "shared/mysafe01", "deny");
        String jsonStr = "{\"role_name\":\"approle1\",\"path\":\"shared/mysafe01\",\"access\":\"deny\"}";
        Map<String, Object> requestMap = new ObjectMapper().readValue(jsonStr, new TypeReference<Map<String, Object>>(){});
        Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
        Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(requestMap);
        when(reqProcessor.process(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(response);
        when(ControllerUtil.isValidSafePath(Mockito.any())).thenReturn(true);
        when(ControllerUtil.isValidSafe(Mockito.any(), Mockito.any())).thenReturn(true);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"),Mockito.any(),Mockito.eq(tkn))).thenReturn(configureAppRoleResponse);
        when(ControllerUtil.areSafeAppRoleInputsValid(Mockito.anyMap())).thenReturn(true);
        when(ControllerUtil.canAddPermission(Mockito.any(), Mockito.any())).thenReturn(true);
        when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.any())).thenReturn(updateMetadataResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{duck\"data\": null}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        ResponseEntity<String> responseEntityActual =  appRoleService.associateApprole(tkn, safeAppRoleAccess);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_AssociateAppRole_empty_policy_failure() throws Exception {
        Response response = getMockResponse(HttpStatus.OK, true, "");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
                .body("{\"errors\":[\"Incorrect access requested. Valid values are read,write,deny \"]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        SafeAppRoleAccess safeAppRoleAccess = new SafeAppRoleAccess("approle1", "shared/mysafe01", "notarealaccessname");
        String jsonStr = "{\"role_name\":\"approle1\",\"path\":\"shared/mysafe01\",\"access\":\"notarealaccessname\"}";
        Map<String, Object> requestMap = new ObjectMapper().readValue(jsonStr, new TypeReference<Map<String, Object>>(){});
        Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
        Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(requestMap);
        when(reqProcessor.process(Mockito.any(),Mockito.any(), Mockito.any())).thenReturn(response);
        when(ControllerUtil.isValidSafePath(Mockito.any())).thenReturn(true);
        when(ControllerUtil.isValidSafe(Mockito.any(), Mockito.any())).thenReturn(true);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"),Mockito.any(),Mockito.eq(tkn))).thenReturn(configureAppRoleResponse);
        when(ControllerUtil.areSafeAppRoleInputsValid(Mockito.anyMap())).thenReturn(true);
        when(ControllerUtil.canAddPermission(Mockito.any(), Mockito.any())).thenReturn(true);
        when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.any())).thenReturn(updateMetadataResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": null}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        ResponseEntity<String> responseEntityActual =  appRoleService.associateApprole(tkn, safeAppRoleAccess);

        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_AssociateAppRole_access_denied_failure() throws Exception {
        Response response = getMockResponse(HttpStatus.OK, true, "");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("{\"errors\":[\"Access denied: no permission to associate this AppRole to any safe\"]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        SafeAppRoleAccess safeAppRoleAccess = new SafeAppRoleAccess("iamportal_admin_approle", "shared/mysafe01", "write");
        String jsonStr = "{\"role_name\":\"approle1\",\"path\":\"shared/mysafe01\",\"access\":\"write\"}";
        Map<String, Object> requestMap = new ObjectMapper().readValue(jsonStr, new TypeReference<Map<String, Object>>(){});
        Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
        Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(requestMap);
        when(reqProcessor.process(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(response);
        when(ControllerUtil.isValidSafePath(Mockito.any())).thenReturn(true);
        when(ControllerUtil.isValidSafe(Mockito.any(), Mockito.any())).thenReturn(true);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"),Mockito.any(),Mockito.eq(tkn))).thenReturn(configureAppRoleResponse);
        when(ControllerUtil.areSafeAppRoleInputsValid(Mockito.anyMap())).thenReturn(true);
        when(ControllerUtil.canAddPermission(Mockito.any(), Mockito.any())).thenReturn(true);
        when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.any())).thenReturn(updateMetadataResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        ResponseEntity<String> responseEntityActual =  appRoleService.associateApprole(tkn, safeAppRoleAccess);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_AssociateAppRole_failure_approle_not_exists() throws Exception {

        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body("{\"errors\":[\"Non existing role name. Please configure approle as first step\"]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        SafeAppRoleAccess safeAppRoleAccess = new SafeAppRoleAccess("approle1", "shared/mysafe01", "write");
        String jsonStr = "{\"role_name\":\"approle1\",\"path\":\"shared/mysafe01\",\"access\":\"write\"}";
        Map<String, Object> requestMap = new ObjectMapper().readValue(jsonStr, new TypeReference<Map<String, Object>>(){});
        Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
        Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(requestMap);
        when(reqProcessor.process(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(response);
        when(ControllerUtil.isValidSafePath(Mockito.any())).thenReturn(true);
        when(ControllerUtil.isValidSafe(Mockito.any(), Mockito.any())).thenReturn(true);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"),Mockito.any(),Mockito.eq(tkn))).thenReturn(configureAppRoleResponse);
        when(ControllerUtil.areSafeAppRoleInputsValid(Mockito.anyMap())).thenReturn(true);
        when(ControllerUtil.canAddPermission(Mockito.any(), Mockito.any())).thenReturn(true);
        when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.any())).thenReturn(updateMetadataResponse);

        ResponseEntity<String> responseEntityActual =  appRoleService.associateApprole(tkn, safeAppRoleAccess);

        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_AssociateAppRole_succssfully_new_meta() throws Exception {

        Response response = getMockResponse(HttpStatus.OK, true, "");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle associated to SDB\"]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        SafeAppRoleAccess safeAppRoleAccess = new SafeAppRoleAccess("approle1", "shared/mysafe01", "write");
        String jsonStr = "{\"role_name\":\"approle1\",\"path\":\"shared/mysafe01\",\"access\":\"write\"}";
        Map<String, Object> requestMap = new ObjectMapper().readValue(jsonStr, new TypeReference<Map<String, Object>>(){});
        Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
        Response updateMetadataResponse_404 = getMockResponse(HttpStatus.NOT_FOUND, true, "");
        Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(requestMap);
        when(reqProcessor.process(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(response);
        when(ControllerUtil.isValidSafePath(Mockito.any())).thenReturn(true);
        when(ControllerUtil.isValidSafe(Mockito.any(), Mockito.any())).thenReturn(true);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"),Mockito.any(),Mockito.eq(tkn))).thenReturn(configureAppRoleResponse);
        when(ControllerUtil.areSafeAppRoleInputsValid(Mockito.anyMap())).thenReturn(true);
        when(ControllerUtil.canAddPermission(Mockito.any(), Mockito.any())).thenReturn(true);

        Map<String,String> params = new HashMap<String,String>();
        params.put("type", "app-roles");
        params.put("name","approle1");
        params.put("path","shared/mysafe01");
        params.put("access","write");

        //when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.eq(token))).thenReturn(updateMetadataResponse_404);
        when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.eq(tkn))).thenAnswer(new Answer() {
            private int count = 0;

            public Object answer(InvocationOnMock invocation) {
                if (count++ == 1)
                    return updateMetadataResponse;

                return updateMetadataResponse_404;
            }
        });
        when(ControllerUtil.getSafeType("shared/mysafe01")).thenReturn("shared");
        when(ControllerUtil.getSafeName("shared/mysafe01")).thenReturn("mysafe01");
        when(ControllerUtil.getAllExistingSafeNames("shared", tkn)).thenReturn(Arrays.asList("mysafe02"));
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        ResponseEntity<String> responseEntityActual =  appRoleService.associateApprole(tkn, safeAppRoleAccess);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_AssociateAppRole_failed_configuration() throws Exception {

        Response response = getMockResponse(HttpStatus.OK, true, "");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Role configuration failed.Contact Admin \"]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        SafeAppRoleAccess safeAppRoleAccess = new SafeAppRoleAccess("approle1", "shared/mysafe01", "write");
        String jsonStr = "{\"role_name\":\"approle1\",\"path\":\"shared/mysafe01\",\"access\":\"write\"}";
        Map<String, Object> requestMap = new ObjectMapper().readValue(jsonStr, new TypeReference<Map<String, Object>>(){});
        Response configureAppRoleResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response updateMetadataResponse_404 = getMockResponse(HttpStatus.NOT_FOUND, true, "");
        Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(requestMap);
        when(reqProcessor.process(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(response);
        when(ControllerUtil.isValidSafePath(Mockito.any())).thenReturn(true);
        when(ControllerUtil.isValidSafe(Mockito.any(), Mockito.any())).thenReturn(true);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"),Mockito.any(),Mockito.eq(tkn))).thenReturn(configureAppRoleResponse);
        when(ControllerUtil.areSafeAppRoleInputsValid(Mockito.anyMap())).thenReturn(true);
        when(ControllerUtil.canAddPermission(Mockito.any(), Mockito.any())).thenReturn(true);

        Map<String,String> params = new HashMap<String,String>();
        params.put("type", "app-roles");
        params.put("name","approle1");
        params.put("path","shared/mysafe01");
        params.put("access","write");

        //when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.eq(token))).thenReturn(updateMetadataResponse_404);
        when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.eq(tkn))).thenReturn(updateMetadataResponse_404);
        when(ControllerUtil.getSafeType("shared/mysafe01")).thenReturn("shared");
        when(ControllerUtil.getSafeName("shared/mysafe01")).thenReturn("mysafe01");
        when(ControllerUtil.getAllExistingSafeNames("shared", tkn)).thenReturn(Arrays.asList("mysafe02"));
        params.put("path","shared/mysafe02");
        when(ControllerUtil.updateMetadata(params, tkn)).thenReturn(updateMetadataResponse);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", tkn)).thenReturn(appRoleResponse);
        ResponseEntity<String> responseEntityActual =  appRoleService.associateApprole(tkn, safeAppRoleAccess);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
    }

    @Test
    public void test_AssociateAppRole_failed() throws Exception {

        Response response = getMockResponse(HttpStatus.OK, true, "");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"messages\":[\"Approle :approle1 failed to be associated with SDB\"]}");
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        SafeAppRoleAccess safeAppRoleAccess = new SafeAppRoleAccess("approle1", "shared/mysafe01", "write");
        String jsonStr = "{\"role_name\":\"approle1\",\"path\":\"shared/mysafe01\",\"access\":\"write\"}";
        Map<String, Object> requestMap = new ObjectMapper().readValue(jsonStr, new TypeReference<Map<String, Object>>(){});
        Response configureAppRoleResponse = getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, "{\"errors\":[\"Internal server error\"]}");
        Response updateMetadataResponse_404 = getMockResponse(HttpStatus.NOT_FOUND, true, "");
        Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");

        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(requestMap);
        when(reqProcessor.process(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(response);
        when(ControllerUtil.isValidSafePath(Mockito.any())).thenReturn(true);
        when(ControllerUtil.isValidSafe(Mockito.any(), Mockito.any())).thenReturn(true);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"),Mockito.any(),Mockito.eq(token))).thenReturn(configureAppRoleResponse);
        when(ControllerUtil.areSafeAppRoleInputsValid(Mockito.anyMap())).thenReturn(true);
        when(ControllerUtil.canAddPermission(Mockito.any(), Mockito.any())).thenReturn(true);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_shared_mysafe01\"}}");
        when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}",token)).thenReturn(appRoleResponse);
        ResponseEntity<String> responseEntityActual =  appRoleService.associateApprole(token, safeAppRoleAccess);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
    }

    @Test
    public void test_AssociateAppRole_failed_400() throws Exception {

        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Invalid input values\"]}");
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        SafeAppRoleAccess safeAppRoleAccess = new SafeAppRoleAccess("approle1", "shared/mysafe01", "write");
        String jsonStr = "{\"role_name\":\"approle1\",\"path\":\"shared/mysafe01\",\"access\":\"write\"}";
        Map<String, Object> requestMap = new ObjectMapper().readValue(jsonStr, new TypeReference<Map<String, Object>>(){});

        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(requestMap);

        when(ControllerUtil.areSafeAppRoleInputsValid(Mockito.anyMap())).thenReturn(false);
        ResponseEntity<String> responseEntityActual =  appRoleService.associateApprole(token, safeAppRoleAccess);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertTrue(responseEntityActual.getBody().contains("Invalid input values"));

    }

    @Test
    public void test_AssociateAppRole_failed_403() throws Exception {

        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"messages\":[\"Approle : approle1 failed to be associated with SDB.. Invalid Path specified\"]}");
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        SafeAppRoleAccess safeAppRoleAccess = new SafeAppRoleAccess("approle1", "shared/mysafe01", "write");
        String jsonStr = "{\"role_name\":\"approle1\",\"path\":\"shared/mysafe01\",\"access\":\"write\"}";
        Map<String, Object> requestMap = new ObjectMapper().readValue(jsonStr, new TypeReference<Map<String, Object>>(){});

        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(requestMap);

        when(ControllerUtil.areSafeAppRoleInputsValid(Mockito.anyMap())).thenReturn(true);
        when(ControllerUtil.canAddPermission(Mockito.any(), Mockito.any())).thenReturn(false);
        ResponseEntity<String> responseEntityActual =  appRoleService.associateApprole(token, safeAppRoleAccess);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertTrue(responseEntityActual.getBody().contains("Approle :approle1 failed to be associated with SDB.. Invalid Path specified"));

    }

    @Test
    public void test_loginWithApprole_successfully() {
        String expectedLoginResponse = "{  \"auth\": {   \"renewable\": true,    \"lease_duration\": 2764800,    \"metadata\": {},    \"policies\": [      \"default\"    ],    \"accessor\": \"5d7fb475-07cb-4060-c2de-1ca3fcbf0c56\",    \"client_token\": \"98a4c7ab-b1fe-361b-ba0b-e307aacfd587\"  }}";
        Response response =getMockResponse(HttpStatus.OK, true, expectedLoginResponse);
        AppRoleIdSecretId appRoleIdSecretId = new AppRoleIdSecretId("approle1", "5973a6de-38c1-0402-46a3-6d76e38b773c");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedLoginResponse);
        String jsonStr = "{\"role_id\":\"approle1\",\"secret_id\":\"5973a6de-38c1-0402-46a3-6d76e38b773c\"}";
        
        when(JSONUtil.getJSON(appRoleIdSecretId)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/login",jsonStr,"")).thenReturn(response);

        ResponseEntity<String> responseEntityActual = appRoleService.login(appRoleIdSecretId);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
        
    }

    @Test
    public void test_loginWithApprole_Failure() {

        Response response =getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, false, "");
        AppRoleIdSecretId appRoleIdSecretId = new AppRoleIdSecretId("approle1", "5973a6de-38c1-0402-46a3-6d76e38b773c");
        String jsonStr = "{\"role_id\":\"approle1\",\"secret_id\":\"5973a6de-38c1-0402-46a3-6d76e38b773c\"}";
        when(JSONUtil.getJSON(appRoleIdSecretId)).thenReturn(jsonStr);
        when(reqProcessor.process("/auth/approle/login",jsonStr,"")).thenReturn(response);

        ResponseEntity<String> responseEntityActual = appRoleService.login(appRoleIdSecretId);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());

    }

    @Test
    public void test_listAppRoles_successfully() throws JsonProcessingException {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\r\n" +
        		"  \"keys\": [\r\n" +
        		"    \"testapprole01\"\r\n" +
        		"  ]\r\n" +
        		"}";
        AppRoleListObject appRoleListObject = new AppRoleListObject();
        appRoleListObject.setRoleName("testapprole01");
        appRoleListObject.setOwner(true);
        List<AppRoleListObject> appRoleListObjects = new ArrayList<>();
        appRoleListObjects.add(appRoleListObject);
        ResponseEntity<List<AppRoleListObject>> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(appRoleListObjects);
        UserDetails userDetails = getMockUser("testuser1", false);
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);
        Response responseAfterHide = response;
        String _path = "metadata/approle_users/" + userDetails.getUsername();
        String jsonStr = "{\"path\":\""+_path+"\"}";
        when(reqProcessor.process("/auth/approles/rolesbyuser/list", jsonStr, userDetails.getSelfSupportToken()))
                .thenReturn(response);

        Map<String, Object> responseMap = new HashMap<>();
        List<String> keys = new ArrayList<>();
        keys.add("testapprole01");
        responseMap.put("keys", keys);
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);

        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy("testuser1");
        appRoleMetadataDetails.setName("testapprole01");
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String readResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response readResponse = getMockResponse(HttpStatus.OK, true, readResponseJson);
        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.any())).thenReturn(readResponse);

        Map<String, Object> readResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", userDetails.getUsername());
        readResponseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(readResponseJson)).thenReturn(readResponseMap);

        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(), Mockito.any()))
                .thenReturn(responseAfterHide);
        ResponseEntity<List<AppRoleListObject>> responseEntityActual = appRoleService.listAppRoles(tkn, userDetails, 1, 0);
        assertEquals(responseEntityExpected.getStatusCode(), responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected.getBody().get(0).getRoleName(), responseEntityActual.getBody().get(0).getRoleName());
    }

    @Test
    public void test_listAppRoles_as_admin_successfully() throws JsonProcessingException {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\r\n" +
                "  \"keys\": [\r\n" +
                "    \"testapprole01\"\r\n" +
                "  ]\r\n" +
                "}";
        AppRoleListObject appRoleListObject = new AppRoleListObject();
        appRoleListObject.setRoleName("testapprole01");
        appRoleListObject.setOwner(true);
        List<AppRoleListObject> appRoleListObjects = new ArrayList<>();
        appRoleListObjects.add(appRoleListObject);
        ResponseEntity<List<AppRoleListObject>> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(appRoleListObjects);
        UserDetails userDetails = getMockUser("testuser1", true);
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);
        Response responseAfterHide = response;
        String _path = "metadata/approle_users/" + userDetails.getUsername();
        String jsonStr = "{\"path\":\""+_path+"\"}";
        when(reqProcessor.process("/auth/approle/role/list", jsonStr, tkn)).thenReturn(response);
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(), Mockito.any())).thenReturn(responseAfterHide);

        Map<String, Object> responseMap = new HashMap<>();
        List<String> keys = new ArrayList<>();
        keys.add("testapprole01");
        responseMap.put("keys", keys);
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);

        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy("testuser1");
        appRoleMetadataDetails.setName("testapprole01");
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String readResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response readResponse = getMockResponse(HttpStatus.OK, true, readResponseJson);
        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.any())).thenReturn(readResponse);

        Map<String, Object> readResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", userDetails.getUsername());
        readResponseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(readResponseJson)).thenReturn(readResponseMap);

        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(), Mockito.any()))
                .thenReturn(responseAfterHide);
        ResponseEntity<List<AppRoleListObject>> responseEntityActual = appRoleService.listAppRoles(tkn, userDetails, 1, 0);
        assertEquals(responseEntityExpected.getStatusCode(), responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected.getBody().get(0).getRoleName(), responseEntityActual.getBody().get(0).getRoleName());
    }

    @Test
    public void test_listAppRoles_empty_response_failure() throws JsonProcessingException {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\r\n" +
                "  \"keys\": [\r\n" +
                "    \"testapprole01\"\r\n" +
                "  ]\r\n" +
                "}";
        AppRoleListObject appRoleListObject = new AppRoleListObject();
        appRoleListObject.setRoleName("testapprole01");
        appRoleListObject.setOwner(true);
        List<AppRoleListObject> appRoleListObjects = new ArrayList<>();
        appRoleListObjects.add(appRoleListObject);
        ResponseEntity<List<AppRoleListObject>> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(appRoleListObjects);
        UserDetails userDetails = getMockUser("testuser1", false);
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);
        Response responseAfterHide = response;
        String _path = "metadata/approle_users/" + userDetails.getUsername();
        String jsonStr = "{\"path\":\""+_path+"\"}";
        when(reqProcessor.process("/auth/approles/rolesbyuser/list", jsonStr, userDetails.getSelfSupportToken()))
                .thenReturn(response);

        Map<String, Object> responseMap = new HashMap<>();
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);

        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy("testuser1");
        appRoleMetadataDetails.setName("testapprole01");
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String readResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response readResponse = getMockResponse(HttpStatus.OK, true, readResponseJson);
        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.any())).thenReturn(readResponse);

        Map<String, Object> readResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", userDetails.getUsername());
        readResponseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(readResponseJson)).thenReturn(readResponseMap);

        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(), Mockito.any()))
                .thenReturn(responseAfterHide);
        ResponseEntity<List<AppRoleListObject>> responseEntityActual = appRoleService.listAppRoles(tkn, userDetails, 1, 0);
        assertEquals(responseEntityExpected.getStatusCode(), responseEntityActual.getStatusCode());
        assertTrue(responseEntityActual.getBody().isEmpty());
    }

    @Test
    public void test_listAppRoles_null_metadata_failure() throws JsonProcessingException {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\r\n" +
                "  \"keys\": [\r\n" +
                "    \"testapprole01\"\r\n" +
                "  ]\r\n" +
                "}";
        AppRoleListObject appRoleListObject = new AppRoleListObject();
        appRoleListObject.setRoleName("testapprole01");
        appRoleListObject.setOwner(true);
        List<AppRoleListObject> appRoleListObjects = new ArrayList<>();
        appRoleListObjects.add(appRoleListObject);
        ResponseEntity<List<AppRoleListObject>> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(appRoleListObjects);
        UserDetails userDetails = getMockUser("testuser1", false);
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);
        Response responseAfterHide = response;
        String _path = "metadata/approle_users/" + userDetails.getUsername();
        String jsonStr = "{\"path\":\""+_path+"\"}";
        when(reqProcessor.process("/auth/approles/rolesbyuser/list", jsonStr, userDetails.getSelfSupportToken()))
                .thenReturn(response);

        Map<String, Object> responseMap = new HashMap<>();
        List<String> keys = new ArrayList<>();
        keys.add("testapprole01");
        responseMap.put("keys", keys);
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap);

        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy("testuser1");
        appRoleMetadataDetails.setName("testapprole01");
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String readResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response readResponse = getMockResponse(HttpStatus.NOT_FOUND, true, readResponseJson);
        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.any())).thenReturn(readResponse);

        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(), Mockito.any()))
                .thenReturn(responseAfterHide);
        ResponseEntity<List<AppRoleListObject>> responseEntityActual = appRoleService.listAppRoles(tkn, userDetails, 1, 0);
        assertEquals(responseEntityExpected.getStatusCode(), responseEntityActual.getStatusCode());
        assertTrue(responseEntityActual.getBody().isEmpty());
    }

    @Test
    public void test_listAppRoles_not_found_failure() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\r\n" +
                "  \"error\": \r\n" +
                "    \"\"\r\n" +
                "  \r\n" +
                "}";
        UserDetails userDetails = getMockUser("testuser1", false);
        Response response = getMockResponse(HttpStatus.NOT_FOUND, false, responseJson);
        String _path = "metadata/approle_users/" + userDetails.getUsername();
        String jsonStr = "{\"path\":\""+_path+"\"}";
        when(reqProcessor.process("/auth/approles/rolesbyuser/list", jsonStr,userDetails.getSelfSupportToken())).thenReturn(response);
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(response);

        ResponseEntity<List<AppRoleListObject>> responseEntityActual = appRoleService.listAppRoles(tkn, userDetails, 1, 0);
        assertTrue(responseEntityActual.getBody().isEmpty());
    }

    @Test
    public void test_listAppRoles_bad_request_failure() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\r\n" +
        		"  \"error\": \r\n" +
        		"    \"\"\r\n" +
        		"  \r\n" +
        		"}";
        UserDetails userDetails = getMockUser("testuser1", false);
        Response response =getMockResponse(HttpStatus.BAD_REQUEST, true, responseJson);
        String _path = "metadata/approle_users/" + userDetails.getUsername();
        String jsonStr = "{\"path\":\""+_path+"\"}";
        when(reqProcessor.process("/auth/approles/rolesbyuser/list", jsonStr,userDetails.getSelfSupportToken())).thenReturn(response);
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(response);
        ResponseEntity<List<AppRoleListObject>> responseEntityActual = appRoleService.listAppRoles(tkn, userDetails, 1, 0);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertTrue(responseEntityActual.getBody().isEmpty());
    }

    @Test
    public void test_readRoleId_successfully() {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        String roleId = "generated-role-id";
        String responseJson = "{\"data\":{ \"role_id\": \"generated-role-id\"}}";
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);
        
        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", roleId);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"data\":{ \"role_id\": \"generated-role-id\"}}")).thenReturn(responseMap);
        
        when(reqProcessor.process("/auth/approle/role/readRoleID", "{\"role_name\":\""+role_name+"\"}",token)).thenReturn(response);
        String actualRoleId = appRoleService.readRoleId(token, role_name);
        assertEquals(roleId, actualRoleId);
    }

    @Test
    public void test_readRoleId_access_denied_failure() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "iamportal_admin_approle";
        String responseJson = "{\"data\":{ \"role_id\": \"generated-role-id\"}}";
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", null);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"data\":{ \"role_id\": \"generated-role-id\"}}")).thenReturn(responseMap);

        when(reqProcessor.process("/auth/approle/role/readRoleID", "{\"role_name\":\""+role_name+"\"}", tkn)).thenReturn(response);
        String actualRoleId = appRoleService.readRoleId(tkn, role_name);
        assertNull(actualRoleId);
    }

    @Test
    public void test_readRoleId_empty_response() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        String responseJson = "{\"data\":{ \"role_id\": \"generated-role-id\"}}";
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);

        Map<String, Object> responseMap = new HashMap<>();
        when(ControllerUtil.parseJson("{\"data\":{ \"role_id\": \"generated-role-id\"}}")).thenReturn(responseMap);

        when(reqProcessor.process("/auth/approle/role/readRoleID", "{\"role_name\":\""+role_name+"\"}", tkn)).thenReturn(response);
        String actualRoleId = appRoleService.readRoleId(tkn, role_name);
        assertNull(actualRoleId);
    }

    @Test
    public void test_readRoleId_empty_response_data() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        String responseJson = "{\"data\":{ \"role_id\": \"generated-role-id\"}}";
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);

        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("data", null);
        when(ControllerUtil.parseJson("{\"data\":{ \"role_id\": \"generated-role-id\"}}")).thenReturn(responseMap);

        when(reqProcessor.process("/auth/approle/role/readRoleID", "{\"role_name\":\""+role_name+"\"}", tkn)).thenReturn(response);
        String actualRoleId = appRoleService.readRoleId(tkn, role_name);
        assertNull(actualRoleId);
    }
    
    @Test
    public void test_readRoleId_failure() {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        String roleId = "generated-role-id";
        String responseJson = "{\"data\":{ \"role_id\": \"generated-role-id\"}}";
        Response response = getMockResponse(HttpStatus.NOT_FOUND, true, responseJson);
        
        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", roleId);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"data\":{ \"role_id\": \"generated-role-id\"}}")).thenReturn(responseMap);
        
        when(reqProcessor.process("/auth/approle/role/readRoleID", "{\"role_name\":\""+role_name+"\"}",token)).thenReturn(response);
        String actualRoleId = appRoleService.readRoleId(token, role_name);
        assertNull(actualRoleId);
    }
    
    @Test
    public void test_readAccessorIds_successfully() {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        String responseJson = "{\r\n" + 
        		"  \"keys\": [\r\n" + 
        		"    \"generated-accessor-id1\"\r\n" + 
        		"  ]\r\n" + 
        		"}";
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);
        
        Map<String, Object> responseMap = new HashMap<>();
        ArrayList<String> accessorIds = new ArrayList<String>();
        accessorIds.add("generated-accessor-id1");
        responseMap.put("keys", accessorIds);
        when(ControllerUtil.parseJson(responseJson)).thenReturn(responseMap);
        
        when(reqProcessor.process("/auth/approle/role/accessors/list", "{\"role_name\":\""+role_name+"\"}",token)).thenReturn(response);
        List<String> actualAccessorIds = appRoleService.readAccessorIds(token, role_name);
        assertNotNull(actualAccessorIds);
        assertEquals("generated-accessor-id1", (String)actualAccessorIds.get(0));
    }

    @Test
    public void test_readAccessorIds_empty_response() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        String responseJson = "{\r\n" +
                "  \"keys\": [\r\n" +
                "    \"generated-accessor-id1\"\r\n" +
                "  ]\r\n" +
                "}";
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);

        Map<String, Object> responseMap = new HashMap<>();
        when(ControllerUtil.parseJson(responseJson)).thenReturn(responseMap);

        when(reqProcessor.process("/auth/approle/role/accessors/list", "{\"role_name\":\""+role_name+"\"}", tkn)).thenReturn(response);
        List<String> actualAccessorIds = appRoleService.readAccessorIds(tkn, role_name);
        assertNull(actualAccessorIds);
    }

    @Test
    public void test_readAccessorIds_failure() {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        String responseJson = "{\r\n" + 
        		"  \"error\": [\r\n" + 
        		"    \"\"\r\n" + 
        		"  ]\r\n" + 
        		"}";
        Response response = getMockResponse(HttpStatus.NOT_FOUND, true, responseJson);
        
        Map<String, Object> responseMap = new HashMap<>();
        ArrayList<String> accessorIds = new ArrayList<String>();
        accessorIds.add("generated-accessor-id1");
        responseMap.put("keys", accessorIds);
        when(ControllerUtil.parseJson(responseJson)).thenReturn(responseMap);
        
        when(reqProcessor.process("/auth/approle/role/accessors/list", "{\"role_name\":\""+role_name+"\"}",token)).thenReturn(response);
        List<String> actualAccessorIds = appRoleService.readAccessorIds(token, role_name);
        assertEquals(null, actualAccessorIds);
    }
    
    @Test
    public void test_readAppRoleMetadata_successfully() throws Exception {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);
        
        String responseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);
        
        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",username);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(responseJson)).thenReturn(responseMap);
        
        when(reqProcessor.process("/read", "{\"path\":\""+_path+"\"}",token)).thenReturn(response);
        AppRoleMetadata appRoleMetadataExpected = appRoleService.readAppRoleMetadata(token, role_name);
        assertNotNull(appRoleMetadataExpected);
        assertNotNull(appRoleMetadataExpected.getAppRoleMetadataDetails());
        assertEquals(username, appRoleMetadataExpected.getAppRoleMetadataDetails().getCreatedBy());
    }

    @Test
    public void test_readAppRoleMetadata_no_response_data() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String responseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",username);
        responseMap.put("data", null);
        when(ControllerUtil.parseJson(responseJson)).thenReturn(responseMap);

        when(reqProcessor.process("/read", "{\"path\":\""+_path+"\"}", tkn)).thenReturn(response);
        AppRoleMetadata appRoleMetadataActual = appRoleService.readAppRoleMetadata(tkn, role_name);
        assertNull(appRoleMetadataActual);
    }
    
    @Test
    public void test_readAppRoleMetadata_failure() throws Exception{
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        String username = "testuser1";
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        String _path = "metadata/approle/" + role_name;
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);
        
        String responseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response response = getMockResponse(HttpStatus.NOT_FOUND, true, responseJson);
        

        when(ControllerUtil.parseJson(responseJson)).thenReturn(null);
        
        when(reqProcessor.process("/read", "{\"path\":\""+_path+"\"}", tkn)).thenReturn(response);
        AppRoleMetadata appRoleMetadataExpected = appRoleService.readAppRoleMetadata(tkn, role_name);
        assertEquals(null, appRoleMetadataExpected);
    }
    
    @Test
    public void test_readAppRoleBasicDetails_successfully() throws Exception{
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        
        AppRole appRoleExpected = new AppRole(role_name, policies, true, 0, 0, 0);
        
        String responseJson = new ObjectMapper().writeValueAsString(appRoleExpected);
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);
        
        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        responseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        
        when(ControllerUtil.parseJson(responseJson)).thenReturn(responseMap);
        
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",token)).thenReturn(response);
        AppRole approleActual = appRoleService.readAppRoleBasicDetails(token, role_name);
        assertNotNull(approleActual);
        assertNotNull(approleActual.getRole_name());
        assertEquals(role_name, approleActual.getRole_name());
    }

    @Test
    public void test_readAppRoleBasicDetails_access_denied() throws Exception{
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "iamportal_admin_approle";
        ArrayList<String> policiesList = new ArrayList<>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);

        AppRole appRoleExpected = new AppRole(role_name, policies, true, 0, 0, 0);

        String responseJson = new ObjectMapper().writeValueAsString(appRoleExpected);
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        responseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id", true);
        dataMap.put("secret_id_num_uses", 0);
        dataMap.put("secret_id_ttl", 0);
        dataMap.put("token_num_uses", 0);
        dataMap.put("token_ttl", 0);
        dataMap.put("token_max_ttl", 0);

        when(ControllerUtil.parseJson(responseJson)).thenReturn(responseMap);

        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\"" + role_name + "\"}", tkn)).thenReturn(response);
        AppRole approleActual = appRoleService.readAppRoleBasicDetails(tkn, role_name);
        assertNull(approleActual);
    }

    @Test
    public void test_readAppRoleBasicDetails_no_policies_data() throws Exception{
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        ArrayList<String> policiesList = new ArrayList<>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);

        AppRole appRoleExpected = new AppRole(role_name, policies, true, 0, 0, 0);

        String responseJson = new ObjectMapper().writeValueAsString(appRoleExpected);
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        responseMap.put("data", dataMap);
        dataMap.put("bind_secret_id", true);
        dataMap.put("secret_id_num_uses", 0);
        dataMap.put("secret_id_ttl", 0);
        dataMap.put("token_num_uses", 0);
        dataMap.put("token_ttl", 0);
        dataMap.put("token_max_ttl", 0);

        when(ControllerUtil.parseJson(responseJson)).thenReturn(responseMap);

        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}", tkn)).thenReturn(response);
        AppRole approleActual = appRoleService.readAppRoleBasicDetails(tkn, role_name);
        assertNull(approleActual.getPolicies());
    }

    @Test
    public void test_readAppRoleBasicDetails_no_response_data() throws Exception{
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        ArrayList<String> policiesList = new ArrayList<>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);

        AppRole appRoleExpected = new AppRole(role_name, policies, true, 0, 0, 0);

        String responseJson = new ObjectMapper().writeValueAsString(appRoleExpected);
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);

        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("data", null);

        when(ControllerUtil.parseJson(responseJson)).thenReturn(responseMap);

        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}", tkn)).thenReturn(response);
        AppRole approleActual = appRoleService.readAppRoleBasicDetails(tkn, role_name);
        assertNull(approleActual);
    }
    
    @Test
    public void test_readAppRoleBasicDetails_failure() throws Exception{
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "testapprole01";
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        
        AppRole appRoleExpected = new AppRole(role_name, policies, true, 0, 0, 0);
        
        String responseJson = new ObjectMapper().writeValueAsString(appRoleExpected);
        Response response = getMockResponse(HttpStatus.NOT_FOUND, true, responseJson);
        
        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        responseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        
        when(ControllerUtil.parseJson(responseJson)).thenReturn(responseMap);
        
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",token)).thenReturn(response);
        AppRole approleActual = appRoleService.readAppRoleBasicDetails(token, role_name);
        assertEquals(null, approleActual);
    }
    
    @Test
    public void test_readAppRoleRoleId_successfully() {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\r\n" + 
        		"  \"data\": {\r\n" + 
        		"    \"role_id\": \"generated-role-id\"\r\n" + 
        		"  }\r\n" + 
        		"}";
        Response response =getMockResponse(HttpStatus.OK, true, responseJson);
        String appRoleName = "approle1";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);
        
        when(reqProcessor.process("/auth/approle/role/readRoleID","{\"role_name\":\""+appRoleName+"\"}",token)).thenReturn(response);
        
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleRoleId(token, appRoleName);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_readAppRoleRoleId_access_denied_failure() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\"errors\":[\"Access denied: no permission to read roleID of this AppRole\"]}";

        Response response = getMockResponse(HttpStatus.OK, true, responseJson);
        String appRoleName = "iamportal_admin_approle";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseJson);

        when(reqProcessor.process("/auth/approle/role/readRoleID","{\"role_name\":\""+appRoleName+"\"}", tkn)).thenReturn(response);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleRoleId(tkn, appRoleName);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRoleRoleId_failure() {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\"error\":[\"Internal Server Error\"]}";
        Response response =getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, responseJson);
        String appRoleName = "approle1";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseJson);
        
        when(reqProcessor.process("/auth/approle/role/readRoleID","{\"role_name\":\""+appRoleName+"\"}",token)).thenReturn(response);
        
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleRoleId(token, appRoleName);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }
    
    @Test
    public void test_readAppRoleSecretId_successfully() {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\r\n" + 
        		"  \"data\": {\r\n" + 
        		"    \"secret_id\": \"generated-secret-id\",\r\n" + 
        		"    \"secret_id_accessor\": \"generated-accessor-id\"\r\n" + 
        		"  }\r\n" + 
        		"}";
        Response response =getMockResponse(HttpStatus.OK, true, responseJson);
        String appRoleName = "approle1";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);
        
        when(reqProcessor.process("/auth/approle/secretid/lookup","{\"role_name\":\""+appRoleName+"\"}",token)).thenReturn(response);
        
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleSecretId(token, appRoleName);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_readAppRoleSecretId_access_denied_failure() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\r\n" +
                "  \"data\": {\r\n" +
                "    \"secret_id\": \"generated-secret-id\",\r\n" +
                "    \"secret_id_accessor\": \"generated-accessor-id\"\r\n" +
                "  }\r\n" +
                "}";
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);
        String appRoleName = "iamportal_admin_approle";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("{\"errors\":[\"Access denied: no permission to read secretID for this AppRole\"]}");

        when(reqProcessor.process("/auth/approle/secretid/lookup","{\"role_name\":\""+appRoleName+"\"}", tkn))
                .thenReturn(response);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleSecretId(tkn, appRoleName);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }
    
    @Test
    public void test_readAppRoleSecretId_failure() {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\"error\":[\"Internal Server Error\"]}";
        Response response =getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, responseJson);
        String appRoleName = "approle1";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseJson);
        
        when(reqProcessor.process("/auth/approle/secretid/lookup","{\"role_name\":\""+appRoleName+"\"}",token)).thenReturn(response);
        
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleSecretId(token, appRoleName);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }
    private String getAppRoleMetadataJSON(String path, String username, String role_name ) throws Exception {
        return objMapper.writeValueAsString(getAppRoleMetadata(path, username, role_name));
    }
    
    private AppRoleMetadata getAppRoleMetadata(String path, String username, String role_name ) throws Exception {
        AppRoleMetadata approleMetadata = new AppRoleMetadata();
        approleMetadata.setPath(path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadata.setAppRoleMetadataDetails(appRoleMetadataDetails);
        return approleMetadata;
    }

    @Test
    public void test_readAppRoles_successfully() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(reqProcessor.process("/auth/approle/role/list", "{}", tkn))
                .thenReturn(responseList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoles(tkn);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"keys\": [ \"role1\" ]}");
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRoles_not_found_failure() {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        Response responseList = getMockResponse(HttpStatus.NOT_FOUND, false, "{}");
        when(reqProcessor.process("/auth/approle/role/list", "{}", tkn))
                .thenReturn(responseList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoles(tkn);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.NOT_FOUND).body("{}");
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRoleRoleId_WithUserDetails_successfully() throws Exception {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser1", false);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        
        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        // START - isAllowed
        String approleusername=username;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
        // END - isAllowed
        
        String responseJson = "{\r\n" + 
        		"  \"data\": {\r\n" + 
        		"    \"role_id\": \"generated-role-id\"\r\n" + 
        		"  }\r\n" + 
        		"}";
        Response response =getMockResponse(HttpStatus.OK, true, responseJson);
        when(reqProcessor.process("/auth/approle/role/readRoleID","{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(response);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(response.getResponse());

        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", username);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"path\":\""+path+"\",\"data\":{\"name\":\""+role_name+"\",\"createdBy\":\""+username+"\",\"sharedTo\":null}}")).thenReturn(responseMap);
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleRoleId(token, role_name, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_readAppRoleRoleId_WithUserDetails_as_admin_successfully() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser1", true);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;

        // Check if AppRole exists
        ArrayList<String> policiesList = new ArrayList<>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id", true);
        dataMap.put("secret_id_num_uses", 0);
        dataMap.put("secret_id_ttl", 0);
        dataMap.put("token_num_uses", 0);
        dataMap.put("token_ttl", 0);
        dataMap.put("token_max_ttl", 0);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/read"), Mockito.eq("{\"role_name\":\"" + role_name + "\"}"),
                Mockito.any())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);

        // Check if isAllowed
        String approleusername = username;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.eq("{\"path\":\"" + path + "\"}"),
                Mockito.any())).thenReturn(approleMetadataResponse);

        String responseJson = "{\r\n" +
                "  \"data\": {\r\n" +
                "    \"role_id\": \"generated-role-id\"\r\n" +
                "  }\r\n" +
                "}";
        Response response =getMockResponse(HttpStatus.OK, true, responseJson);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/readRoleID"), Mockito.eq("{\"role_name\":\"" + role_name + "\"}"),
                Mockito.any())).thenReturn(response);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(response.getResponse());

        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", username);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"path\":\"" + path + "\",\"data\":{\"name\":\"" + role_name + "\",\"createdBy\":\"" +
                username + "\",\"sharedTo\":null}}")).thenReturn(responseMap);
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleRoleId(tkn, role_name, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRoleRoleId_WithUserDetails_failure_BAD_REQUEST() throws Exception {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser1", false);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        
        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        // START - isAllowed
        String approleusername="nonexisting";
        Response approleMetadataResponse = getMockResponse(HttpStatus.BAD_REQUEST, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
        // END - isAllowed
        
        String responseJson = "{\"errors\":[\"Access denied: You don't have enough permission to read the role_id associated with the AppRole\"]}";
        Response response =getMockResponse(HttpStatus.BAD_REQUEST, true, responseJson);
        when(reqProcessor.process("/auth/approle/role/readRoleID","{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(response);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response.getResponse());

        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", username);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"path\":\""+path+"\",\"data\":{\"name\":\""+role_name+"\",\"createdBy\":\""+username+"\"}}")).thenReturn(responseMap);
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleRoleId(token, role_name, userDetails);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }
    @Test
    public void test_readAppRoleRoleId_WithUserDetails_failure() throws Exception {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser1", false);
        String role_name = "selfservicesupportrole";
        String responseJson = "{\"errors\":[\"Access denied: You don't have enough permission to read the role_id associated with the AppRole\"]}";
        Response response =getMockResponse(HttpStatus.BAD_REQUEST, true, responseJson);
        when(reqProcessor.process("/auth/approle/role/readRoleID","{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(response);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response.getResponse());

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleRoleId(token, role_name, userDetails);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }
    @Test
    public void test_readAppRoleRoleId_WithUserDetails_failure_NonExistingRole() throws Exception {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser1", false);
        String role_name = "approle1x";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        
        // START - AppRole exists

        AppRole appRole = null;
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.NOT_FOUND, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",null);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        // START - isAllowed
        String approleusername=username;
        Response approleMetadataResponse = getMockResponse(HttpStatus.BAD_REQUEST, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
        // END - isAllowed
        
        String responseJson = "{\"errors\":[\"AppRole doesn't exist\"]}";
        Response response =getMockResponse(HttpStatus.OK, true, responseJson);
        when(reqProcessor.process("/auth/approle/role/readRoleID","{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(response);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(response.getResponse());

        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", username);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"path\":\""+path+"\",\"data\":{\"name\":\""+role_name+"\",\"createdBy\":\""+username+"\"}}")).thenReturn(responseMap);
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleRoleId(token, role_name, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }
    @Test
    public void test_readAppRoleSecretId_WithUserDetails_failure() throws Exception {
    	
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser1", false);
        String role_name = "selfservicesupportrole";
        String responseJson = "{\"errors\":[\"Access denied: You don't have enough permission to read the secret_id associated with the AppRole\"]}";
        
        Response response =getMockResponse(HttpStatus.BAD_REQUEST, true, responseJson);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response.getResponse());
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleSecretId(token, role_name, userDetails);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }
    
    @Test
    public void test_readAppRoleSecretId_WithUserDetails_successfully() throws Exception {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser1", false);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        
        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        // START - isAllowed
        String approleusername=username;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
        // END - isAllowed
        
        String responseJson = "{\r\n" + 
        		"  \"data\": {\r\n" + 
        		"    \"secret_id\": \"generated-secret-id\",\r\n" + 
        		"    \"secret_id_accessor\": \"generated-accessor-id\"\r\n" + 
        		"  }\r\n" + 
        		"}";
        
        Response response =getMockResponse(HttpStatus.OK, true, responseJson);
        when(reqProcessor.process("/auth/approle/secretid/lookup","{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(response);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(response.getResponse());
        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", username);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"path\":\""+path+"\",\"data\":{\"name\":\""+role_name+"\",\"createdBy\":\""+username+"\",\"sharedTo\":null}}")).thenReturn(responseMap);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleSecretId(token, role_name, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRoleSecretId_WithUserDetails_as_admin_successfully() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser1", true);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id", true);
        dataMap.put("secret_id_num_uses", 0);
        dataMap.put("secret_id_ttl", 0);
        dataMap.put("token_num_uses", 0);
        dataMap.put("token_ttl", 0);
        dataMap.put("token_max_ttl", 0);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/read"), Mockito.eq("{\"role_name\":\"" + role_name + "\"}"),
                Mockito.any())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);

        // START - isAllowed
        String approleusername = username;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process(Mockito.eq("/read"), Mockito.eq("{\"path\":\""+path+"\"}"),
                Mockito.any())).thenReturn(approleMetadataResponse);

        String responseJson = "{\r\n" +
                "  \"data\": {\r\n" +
                "    \"secret_id\": \"generated-secret-id\",\r\n" +
                "    \"secret_id_accessor\": \"generated-accessor-id\"\r\n" +
                "  }\r\n" +
                "}";

        Response response = getMockResponse(HttpStatus.OK, true, responseJson);
        when(reqProcessor.process(Mockito.eq("/auth/approle/secretid/lookup"), Mockito.eq("{\"role_name\":\"" + role_name + "\"}"),
                Mockito.any())).thenReturn(response);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(response.getResponse());
        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", username);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"path\":\""+path+"\",\"data\":{\"name\":\""+role_name+"\",\"createdBy\":\""+username+"\",\"sharedTo\":null}}")).thenReturn(responseMap);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleSecretId(tkn, role_name, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRoleSecretId_WithUserDetails_appRole_is_null_failure() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser1", true);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.BAD_REQUEST, true, "{}");
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id", true);
        dataMap.put("secret_id_num_uses", 0);
        dataMap.put("secret_id_ttl", 0);
        dataMap.put("token_num_uses", 0);
        dataMap.put("token_ttl", 0);
        dataMap.put("token_max_ttl", 0);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/read"), Mockito.eq("{\"role_name\":\"" + role_name + "\"}"),
                Mockito.any())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);

        // START - isAllowed
        String approleusername = username;
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process(Mockito.eq("/read"), Mockito.eq("{\"path\":\""+path+"\"}"),
                Mockito.any())).thenReturn(approleMetadataResponse);

        String responseJson = "{\r\n" +
                "  \"data\": {\r\n" +
                "    \"secret_id\": \"generated-secret-id\",\r\n" +
                "    \"secret_id_accessor\": \"generated-accessor-id\"\r\n" +
                "  }\r\n" +
                "}";

        Response response = getMockResponse(HttpStatus.OK, true, responseJson);
        when(reqProcessor.process(Mockito.eq("/auth/approle/secretid/lookup"), Mockito.eq("{\"role_name\":\"" + role_name + "\"}"),
                Mockito.any())).thenReturn(response);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK)
                .body("{\"errors\":[\"AppRole doesn't exist\"]}");
        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", username);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"path\":\""+path+"\",\"data\":{\"name\":\""+role_name+"\",\"createdBy\":\""+username+"\",\"sharedTo\":null}}")).thenReturn(responseMap);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleSecretId(tkn, role_name, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }
    
    @Test
    public void test_readAppRoleSecretId_WithUserDetails_failure_BAD_REQUEST() throws Exception {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser1", false);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        
        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        // START - isAllowed
        String approleusername="nonexisting";
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, approleusername, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
        // END - isAllowed
        
        String responseJson = "{\"errors\":[\"Access denied: You don't have enough permission to read the secret_id associated with the AppRole\"]}";
        
        Response response =getMockResponse(HttpStatus.BAD_REQUEST, true, responseJson);
        when(reqProcessor.process("/auth/approle/secretid/lookup","{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(response);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response.getResponse());
        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", username);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"path\":\""+path+"\",\"data\":{\"name\":\""+role_name+"\",\"createdBy\":\""+username+"\"}}")).thenReturn(responseMap);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleSecretId(token, role_name, userDetails);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }
    
    @Test
    public void test_readSecretIdAccessors_WithUserDetails_successfully() throws Exception {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\r\n" + 
        		"  \"keys\": [\r\n" + 
        		"    \"generated-accessor-id1\",\r\n" + 
        		"    \"generated-accessor-id2\"\r\n" + 
        		"  ]\r\n" + 
        		"}";
    	String role_id_response = "{\n" + 
    			"  \"data\": {\n" + 
    			"    \"role_id\": \"generated-role-id\"\n" + 
    			"  }\n" + 
    			"}";
        Response response =getMockResponse(HttpStatus.OK, true, responseJson);
        UserDetails userDetails = getMockUser("testuser1", false);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        
        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", username);
        responseMap.put("data", roleIdDataMap);
        
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);
        
        when(reqProcessor.process("/auth/approle/role/accessors/list","{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/readRoleID","{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn
        (getMockResponse(HttpStatus.OK, true, role_id_response));
        when(ControllerUtil.parseJson(role_id_response)).thenReturn(responseMap);
        
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, username, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);

        when(ControllerUtil.parseJson("{\"path\":\""+path+"\",\"data\":{\"name\":\""+role_name+"\",\"createdBy\":\""+username+"\",\"sharedTo\":null}}")).thenReturn(responseMap);
        ResponseEntity<String> responseEntityActual = appRoleService.readSecretIdAccessors(token, role_name, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_readSecretIdAccessors_WithUserDetails_as_admin_successfully() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\r\n" +
                "  \"keys\": [\r\n" +
                "    \"generated-accessor-id1\",\r\n" +
                "    \"generated-accessor-id2\"\r\n" +
                "  ]\r\n" +
                "}";
        String role_id_response = "{\n" +
                "  \"data\": {\n" +
                "    \"role_id\": \"generated-role-id\"\n" +
                "  }\n" +
                "}";
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);
        UserDetails userDetails = getMockUser("testuser1", true);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;

        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", username);
        responseMap.put("data", roleIdDataMap);

        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/accessors/list"), Mockito.eq("{\"role_name\":\"" + role_name + "\"}"),
                Mockito.any())).thenReturn(response);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/readRoleID"), Mockito.eq("{\"role_name\":\"" + role_name + "\"}"),
                Mockito.any())).thenReturn(getMockResponse(HttpStatus.OK, true, role_id_response));
        when(ControllerUtil.parseJson(role_id_response)).thenReturn(responseMap);

        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, username, role_name));
        when(reqProcessor.process(Mockito.eq("/read"),Mockito.eq("{\"path\":\"" + path + "\"}"), Mockito.any()))
                .thenReturn(approleMetadataResponse);

        when(ControllerUtil.parseJson("{\"path\":\"" + path + "\",\"data\":{\"name\":\"" + role_name + "\",\"createdBy\":\"" +
                username + "\",\"sharedTo\":null}}")).thenReturn(responseMap);
        ResponseEntity<String> responseEntityActual = appRoleService.readSecretIdAccessors(tkn, role_name, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readSecretIdAccessors_WithUserDetails_response_not_found_failure() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\r\n" +
                "  \"keys\": [\r\n" +
                "    \"generated-accessor-id1\",\r\n" +
                "    \"generated-accessor-id2\"\r\n" +
                "  ]\r\n" +
                "}";
        String role_id_response = "{\n" +
                "  \"data\": {\n" +
                "    \"role_id\": \"generated-role-id\"\n" +
                "  }\n" +
                "}";
        Response response = getMockResponse(HttpStatus.NOT_FOUND, true, "{}");
        UserDetails userDetails = getMockUser("testuser1", false);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;

        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", username);
        responseMap.put("data", roleIdDataMap);

        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"keys\":[]}");

        when(reqProcessor.process("/auth/approle/role/accessors/list","{\"role_name\":\"" + role_name + "\"}",
                userDetails.getSelfSupportToken())).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/readRoleID","{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn
                (getMockResponse(HttpStatus.OK, true, role_id_response));
        when(ControllerUtil.parseJson(role_id_response)).thenReturn(responseMap);

        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, username, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);

        when(ControllerUtil.parseJson("{\"path\":\""+path+"\",\"data\":{\"name\":\""+role_name+"\",\"createdBy\":\""+username+"\",\"sharedTo\":null}}")).thenReturn(responseMap);
        ResponseEntity<String> responseEntityActual = appRoleService.readSecretIdAccessors(tkn, role_name, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readSecretIdAccessors_WithUserDetails_response_internal_server_error_failure() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\r\n" +
                "  \"keys\": [\r\n" +
                "    \"generated-accessor-id1\",\r\n" +
                "    \"generated-accessor-id2\"\r\n" +
                "  ]\r\n" +
                "}";
        String role_id_response = "{\n" +
                "  \"data\": {\n" +
                "    \"role_id\": \"generated-role-id\"\n" +
                "  }\n" +
                "}";
        Response response = getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, "{}");
        UserDetails userDetails = getMockUser("testuser1", false);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;

        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", username);
        responseMap.put("data", roleIdDataMap);

        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("{\"errors\":[\"Not able to read accessor_ids.\"]}");

        when(reqProcessor.process("/auth/approle/role/accessors/list","{\"role_name\":\"" + role_name + "\"}",
                userDetails.getSelfSupportToken())).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/readRoleID","{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn
                (getMockResponse(HttpStatus.OK, true, role_id_response));
        when(ControllerUtil.parseJson(role_id_response)).thenReturn(responseMap);

        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, username, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);

        when(ControllerUtil.parseJson("{\"path\":\""+path+"\",\"data\":{\"name\":\""+role_name+"\",\"createdBy\":\""+username+"\",\"sharedTo\":null}}")).thenReturn(responseMap);
        ResponseEntity<String> responseEntityActual = appRoleService.readSecretIdAccessors(tkn, role_name, userDetails);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readSecretIdAccessors_WithUserDetails_access_denied_failure() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\r\n" +
                "  \"keys\": [\r\n" +
                "    \"generated-accessor-id1\",\r\n" +
                "    \"generated-accessor-id2\"\r\n" +
                "  ]\r\n" +
                "}";
        String role_id_response = "{\n" +
                "  \"data\": {\n" +
                "    \"role_id\": \"generated-role-id\"\n" +
                "  }\n" +
                "}";
        Response response = getMockResponse(HttpStatus.OK, true, responseJson);
        UserDetails userDetails = getMockUser("testuser1", false);
        String role_name = "iamportal_admin_approle";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;

        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", username);
        responseMap.put("data", roleIdDataMap);

        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("{\"errors\":[\"Access denied: You don't have enough permission to read the accessors of SecretIds associated with the AppRole\"]}");

        when(reqProcessor.process("/auth/approle/role/accessors/list","{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/readRoleID","{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn
                (getMockResponse(HttpStatus.OK, true, role_id_response));
        when(ControllerUtil.parseJson(role_id_response)).thenReturn(responseMap);

        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, username, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);

        when(ControllerUtil.parseJson("{\"path\":\""+path+"\",\"data\":{\"name\":\""+role_name+"\",\"createdBy\":\""+username+"\",\"sharedTo\":null}}")).thenReturn(responseMap);
        ResponseEntity<String> responseEntityActual = appRoleService.readSecretIdAccessors(tkn, role_name, userDetails);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_readSecretIdAccessors_WithUserDetails_failure() throws Exception {

        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String responseJson = "{\"errors\":[\"Unable to read AppRole. AppRole does not exist.\"]}";
        Response response =getMockResponse(HttpStatus.OK, true, responseJson);
        UserDetails userDetails = getMockUser("testuser1", false);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;

        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);
        
        when(reqProcessor.process("/auth/approle/role/accessors/list","{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/readRoleID","{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn
        (getMockResponse(HttpStatus.NOT_FOUND, true, responseJson));
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, username, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", username);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"path\":\""+path+"\",\"data\":{\"name\":\""+role_name+"\",\"createdBy\":\""+username+"\"}}")).thenReturn(responseMap);
        ResponseEntity<String> responseEntityActual = appRoleService.readSecretIdAccessors(tkn, role_name, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }
    @Test
    public void test_readSecretIdAccessors_WithUserDetails_BAD_REQUEST() throws Exception {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser1", false);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;

    	String role_id_response = "{\n" + 
    			"  \"data\": {\n" + 
    			"    \"role_id\": \"generated-role-id\"\n" + 
    			"  }\n" + 
    			"}";
        Map<String, Object> roleIdResponseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", username);
        roleIdResponseMap.put("data", roleIdDataMap);
        when(reqProcessor.process("/auth/approle/role/readRoleID","{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(getMockResponse(HttpStatus.OK, true, role_id_response));
        when(ControllerUtil.parseJson(role_id_response)).thenReturn(roleIdResponseMap);
        
        Response approleMetadataResponse = getMockResponse(HttpStatus.OK, true, getAppRoleMetadataJSON(path, username, role_name));
        when(reqProcessor.process("/read","{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(approleMetadataResponse);
        Map<String, Object> responseMap = new HashMap<>();
        roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", "generated-id");
        roleIdDataMap.put("createdBy", "testuser2");
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"path\":\""+path+"\",\"data\":{\"name\":\""+role_name+"\",\"createdBy\":\""+username+"\"}}")).thenReturn(responseMap);

        String responseJson = "{\"errors\":[\"Access denied: You don't have enough permission to read the accessors of SecretIds associated with the AppRole\"]}";
        Response response =getMockResponse(HttpStatus.OK, true, responseJson);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseJson);
        ResponseEntity<String> responseEntityActual = appRoleService.readSecretIdAccessors(token, role_name, userDetails);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }
    @Test
    public void test_readAppRoleDetails_WithUserDetails_successfully() throws Exception {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";

        UserDetails userDetails = getMockUser("testuser1", true);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        String roleId="generated-role-id";
        


        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);
        
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",token)).thenReturn(appRoleResponse);
        
        
        AppRoleMetadata approleMetadata = new AppRoleMetadata();
        approleMetadata.setPath(path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadata.setAppRoleMetadataDetails(appRoleMetadataDetails);
        
        String appRoleMetadataResponseJson = new ObjectMapper().writeValueAsString(approleMetadata);
        Response appRoleMetadataResponse = getMockResponse(HttpStatus.OK, true, appRoleMetadataResponseJson);
        
        Map<String, Object> appRoleMetadatResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",username);
        appRoleMetadatResponseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleMetadataResponseJson)).thenReturn(appRoleMetadatResponseMap);
        when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}",token)).thenReturn(appRoleMetadataResponse);
        
        String roleIdResponseJson = "{\"data\":{ \"role_id\": \""+roleId+"\"}}";
        Response roleIdResponse = getMockResponse(HttpStatus.OK, true, roleIdResponseJson);
        
        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", roleId);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"data\":{ \"role_id\": \""+roleId+"\"}}")).thenReturn(responseMap);
        when(reqProcessor.process("/auth/approle/role/readRoleID", "{\"role_name\":\""+role_name+"\"}",token)).thenReturn(roleIdResponse);
        
        String accessorIdResponseJson = "{\r\n" + 
        		"  \"keys\": [\r\n" + 
        		"    \"generated-accessor-id1\"\r\n" + 
        		"  ]\r\n" + 
        		"}";
        Response accessorIdResponse = getMockResponse(HttpStatus.OK, true, accessorIdResponseJson);
        
        Map<String, Object> accessorIdResponseMap = new HashMap<>();
        ArrayList<String> accessorIds = new ArrayList<String>();
        accessorIds.add("generated-accessor-id1");
        accessorIdResponseMap.put("keys", accessorIds);
        when(ControllerUtil.parseJson(accessorIdResponseJson)).thenReturn(responseMap);
        
        when(reqProcessor.process("/auth/approle/role/accessors/list", "{\"role_name\":\""+role_name+"\"}",token)).thenReturn(accessorIdResponse);
        
		AppRoleDetails appRoleDetails = new AppRoleDetails();
        appRoleDetails.setRole_name(appRole.getRole_name());
        appRoleDetails.setPolicies(appRole.getPolicies());
        appRoleDetails.setBind_secret_id(appRole.isBind_secret_id());
        appRoleDetails.setSecret_id_num_uses(appRole.getSecret_id_num_uses());
        appRoleDetails.setSecret_id_ttl(appRole.getSecret_id_ttl());
        appRoleDetails.setToken_num_uses(appRole.getToken_num_uses());
        appRoleDetails.setToken_ttl(appRole.getToken_ttl());
        appRoleDetails.setToken_max_ttl(appRole.getToken_max_ttl());
		appRoleDetails.setRole_id(roleId);
		appRoleDetails.setAppRoleMetadata(approleMetadata);
		if (!CollectionUtils.isEmpty(accessorIds)) {
			appRoleDetails.setAccessorIds(accessorIds.toArray(new String[accessorIds.size()]));
		}
		String appRoleDetailsJson = objMapper.writeValueAsString(appRoleDetails);
        String appRoleDetailsResponseJson = objMapper.writeValueAsString(appRoleDetails);
        Response appRoleDetailsResponse =getMockResponse(HttpStatus.OK, true, appRoleDetailsResponseJson);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(appRoleDetailsResponse.getHttpstatus()).body(appRoleDetailsResponse.getResponse());
        when(JSONUtil.getJSON(Mockito.any(AppRoleDetails.class))).thenReturn(appRoleDetailsJson);
        
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleDetails(token, role_name, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_readAppRoleDetails_with_shared_to_successfully() throws Exception {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser1", false);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        String roleId="generated-role-id";

        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        List<String> sharedTo = new ArrayList<>();
        sharedTo.add("testuser2");
        sharedTo.add("testuser1");
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);
        appRole.setShared_to(sharedTo);

        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);

        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));

        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/read"), Mockito.eq("{\"role_name\":\""+role_name+"\"}"), Mockito.any())).thenReturn(appRoleResponse);

        AppRoleMetadata approleMetadata = new AppRoleMetadata();
        approleMetadata.setPath(path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy("someguy");
        appRoleMetadataDetails.setName(role_name);
        appRoleMetadataDetails.setSharedTo(sharedTo);
        approleMetadata.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String appRoleMetadataResponseJson = new ObjectMapper().writeValueAsString(approleMetadata);
        Response appRoleMetadataResponse = getMockResponse(HttpStatus.OK, true, appRoleMetadataResponseJson);

        Map<String, Object> appRoleMetadatResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", "someguy");
        appRoleMetadataMap.put("sharedTo", sharedTo);
        appRoleMetadatResponseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleMetadataResponseJson)).thenReturn(appRoleMetadatResponseMap);
        when(reqProcessor.process(Mockito.eq("/read"), Mockito.eq("{\"path\":\""+path+"\"}"), Mockito.any()))
                .thenReturn(appRoleMetadataResponse);

        String roleIdResponseJson = "{\"data\":{ \"role_id\": \""+roleId+"\"}}";
        Response roleIdResponse = getMockResponse(HttpStatus.OK, true, roleIdResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", roleId);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"data\":{ \"role_id\": \""+roleId+"\"}}")).thenReturn(responseMap);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/readRoleID"), Mockito.eq("{\"role_name\":\""+role_name+"\"}"),
                Mockito.any())).thenReturn(roleIdResponse);

        String accessorIdResponseJson = "{\r\n" +
                "  \"keys\": [\r\n" +
                "    \"generated-accessor-id1\"\r\n" +
                "  ]\r\n" +
                "}";
        Response accessorIdResponse = getMockResponse(HttpStatus.OK, true, accessorIdResponseJson);

        Map<String, Object> accessorIdResponseMap = new HashMap<>();
        ArrayList<String> accessorIds = new ArrayList<String>();
        accessorIds.add("generated-accessor-id1");
        accessorIdResponseMap.put("keys", accessorIds);
        when(ControllerUtil.parseJson(accessorIdResponseJson)).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/accessors/list"), Mockito.eq("{\"role_name\":\""+role_name+"\"}"),
                Mockito.any())).thenReturn(accessorIdResponse);

        AppRoleDetails appRoleDetails = new AppRoleDetails();
        appRoleDetails.setRole_name(appRole.getRole_name());
        appRoleDetails.setPolicies(appRole.getPolicies());
        appRoleDetails.setBind_secret_id(appRole.isBind_secret_id());
        appRoleDetails.setSecret_id_num_uses(appRole.getSecret_id_num_uses());
        appRoleDetails.setSecret_id_ttl(appRole.getSecret_id_ttl());
        appRoleDetails.setToken_num_uses(appRole.getToken_num_uses());
        appRoleDetails.setToken_ttl(appRole.getToken_ttl());
        appRoleDetails.setToken_max_ttl(appRole.getToken_max_ttl());
        appRoleDetails.setRole_id(roleId);
        appRoleDetails.setAppRoleMetadata(approleMetadata);
        if (!CollectionUtils.isEmpty(accessorIds)) {
            appRoleDetails.setAccessorIds(accessorIds.toArray(new String[accessorIds.size()]));
        }
        String appRoleDetailsJson = objMapper.writeValueAsString(appRoleDetails);
        String appRoleDetailsResponseJson = objMapper.writeValueAsString(appRoleDetails);
        Response appRoleDetailsResponse =getMockResponse(HttpStatus.OK, true, appRoleDetailsResponseJson);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(appRoleDetailsResponse.getHttpstatus()).body(appRoleDetailsResponse.getResponse());
        when(JSONUtil.getJSON(Mockito.any(AppRoleDetails.class))).thenReturn(appRoleDetailsJson);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleDetails(token, role_name, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRoleDetails_WithUserDetails_admin_success() throws Exception {

        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";

        UserDetails userDetails = getMockUser("testuser2", false);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        String roleId="generated-role-id";
        
        
        
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);
        
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        
        
        AppRoleMetadata approleMetadata = new AppRoleMetadata();
        approleMetadata.setPath(path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadata.setAppRoleMetadataDetails(appRoleMetadataDetails);
        
        String appRoleMetadataResponseJson = new ObjectMapper().writeValueAsString(approleMetadata);
        Response appRoleMetadataResponse = getMockResponse(HttpStatus.OK, true, appRoleMetadataResponseJson);
        
        Map<String, Object> appRoleMetadatResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",username);
        appRoleMetadatResponseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleMetadataResponseJson)).thenReturn(appRoleMetadatResponseMap);
        when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleMetadataResponse);
        
        String roleIdResponseJson = "{\"data\":{ \"role_id\": \""+roleId+"\"}}";
        Response roleIdResponse = getMockResponse(HttpStatus.OK, true, roleIdResponseJson);
        
        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", roleId);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"data\":{ \"role_id\": \""+roleId+"\"}}")).thenReturn(responseMap);
        when(reqProcessor.process("/auth/approle/role/readRoleID", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(roleIdResponse);
        
        String accessorIdResponseJson = "{\r\n" + 
        		"  \"keys\": [\r\n" + 
        		"    \"generated-accessor-id1\"\r\n" + 
        		"  ]\r\n" + 
        		"}";
        Response accessorIdResponse = getMockResponse(HttpStatus.OK, true, accessorIdResponseJson);
        
        Map<String, Object> accessorIdResponseMap = new HashMap<>();
        ArrayList<String> accessorIds = new ArrayList<String>();
        accessorIds.add("generated-accessor-id1");
        accessorIdResponseMap.put("keys", accessorIds);
        when(ControllerUtil.parseJson(accessorIdResponseJson)).thenReturn(responseMap);
        
        when(reqProcessor.process("/auth/approle/role/accessors/list", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(accessorIdResponse);
        
		AppRoleDetails appRoleDetails = new AppRoleDetails();
        appRoleDetails.setRole_name(appRole.getRole_name());
        appRoleDetails.setPolicies(appRole.getPolicies());
        appRoleDetails.setBind_secret_id(appRole.isBind_secret_id());
        appRoleDetails.setSecret_id_num_uses(appRole.getSecret_id_num_uses());
        appRoleDetails.setSecret_id_ttl(appRole.getSecret_id_ttl());
        appRoleDetails.setToken_num_uses(appRole.getToken_num_uses());
        appRoleDetails.setToken_ttl(appRole.getToken_ttl());
        appRoleDetails.setToken_max_ttl(appRole.getToken_max_ttl());
		appRoleDetails.setRole_id(roleId);
		appRoleDetails.setAppRoleMetadata(approleMetadata);
		if (!CollectionUtils.isEmpty(accessorIds)) {
			appRoleDetails.setAccessorIds(accessorIds.toArray(new String[accessorIds.size()]));
		}
		String appRoleDetailsJson = objMapper.writeValueAsString(appRoleDetails);
        String appRoleDetailsResponseJson = objMapper.writeValueAsString(appRoleDetails);
        Response appRoleDetailsResponse =getMockResponse(HttpStatus.OK, true, appRoleDetailsResponseJson);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(appRoleDetailsResponse.getHttpstatus()).body(appRoleDetailsResponse.getResponse());
        when(JSONUtil.getJSON(Mockito.any(AppRoleDetails.class))).thenReturn(appRoleDetailsJson);
        
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleDetails(token, role_name, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_readAppRoleDetails_WithUserDetails_with_accessor_id_successfully() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser1", true);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        String roleId="generated-role-id";

        ArrayList<String> policiesList = new ArrayList<>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);

        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);

        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id", true);
        dataMap.put("secret_id_num_uses", 0);
        dataMap.put("secret_id_ttl", 0);
        dataMap.put("token_num_uses", 0);
        dataMap.put("token_ttl", 0);
        dataMap.put("token_max_ttl", 0);

        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\"" + role_name + "\"}", tkn))
                .thenReturn(appRoleResponse);

        AppRoleMetadata approleMetadata = new AppRoleMetadata();
        approleMetadata.setPath(path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadata.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String appRoleMetadataResponseJson = new ObjectMapper().writeValueAsString(approleMetadata);
        Response appRoleMetadataResponse = getMockResponse(HttpStatus.OK, true, appRoleMetadataResponseJson);

        Map<String, Object> appRoleMetadatResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",username);
        appRoleMetadatResponseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleMetadataResponseJson)).thenReturn(appRoleMetadatResponseMap);
        when(reqProcessor.process("/read", "{\"path\":\"" + path + "\"}", tkn)).thenReturn(appRoleMetadataResponse);

        String roleIdResponseJson = "{\"data\":{ \"role_id\": \"" + roleId + "\"}}";
        Response roleIdResponse = getMockResponse(HttpStatus.OK, true, roleIdResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", roleId);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"data\":{ \"role_id\": \"" + roleId + "\"}}")).thenReturn(responseMap);
        when(reqProcessor.process("/auth/approle/role/readRoleID", "{\"role_name\":\"" + role_name + "\"}", tkn))
                .thenReturn(roleIdResponse);

        String accessorIdResponseJson = "{\r\n" +
                "  \"keys\": [\r\n" +
                "    \"generated-accessor-id1\"\r\n" +
                "  ]\r\n" +
                "}";
        Response accessorIdResponse = getMockResponse(HttpStatus.OK, true, accessorIdResponseJson);

        Map<String, Object> accessorIdResponseMap = new HashMap<>();
        ArrayList<String> accessorIds = new ArrayList<>();
        accessorIds.add("generated-accessor-id1");
        accessorIdResponseMap.put("keys", accessorIds);
        when(ControllerUtil.parseJson(accessorIdResponseJson)).thenReturn(accessorIdResponseMap);

        when(reqProcessor.process("/auth/approle/role/accessors/list", "{\"role_name\":\"" + role_name + "\"}", tkn))
                .thenReturn(accessorIdResponse);

        AppRoleDetails appRoleDetails = new AppRoleDetails();
        appRoleDetails.setRole_name(appRole.getRole_name());
        appRoleDetails.setPolicies(appRole.getPolicies());
        appRoleDetails.setBind_secret_id(appRole.isBind_secret_id());
        appRoleDetails.setSecret_id_num_uses(appRole.getSecret_id_num_uses());
        appRoleDetails.setSecret_id_ttl(appRole.getSecret_id_ttl());
        appRoleDetails.setToken_num_uses(appRole.getToken_num_uses());
        appRoleDetails.setToken_ttl(appRole.getToken_ttl());
        appRoleDetails.setToken_max_ttl(appRole.getToken_max_ttl());
        appRoleDetails.setRole_id(roleId);
        appRoleDetails.setAppRoleMetadata(approleMetadata);
        if (!CollectionUtils.isEmpty(accessorIds)) {
            appRoleDetails.setAccessorIds(accessorIds.toArray(new String[accessorIds.size()]));
        }
        String appRoleDetailsJson = objMapper.writeValueAsString(appRoleDetails);
        String appRoleDetailsResponseJson = objMapper.writeValueAsString(appRoleDetails);
        Response appRoleDetailsResponse = getMockResponse(HttpStatus.OK, true, appRoleDetailsResponseJson);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(appRoleDetailsResponse.getHttpstatus()).body(appRoleDetailsResponse.getResponse());
        when(JSONUtil.getJSON(Mockito.any(AppRoleDetails.class))).thenReturn(appRoleDetailsJson);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleDetails(tkn, role_name, userDetails);

        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }

    @Test
    public void test_readAppRoleDetails_WithUserDetails_bad_approle_name_failure() {
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleDetails("5PDrOhsy4ig8L3EpsJZSLAMg",
                "iamportal_admin_approle", getMockUser("testuser2", false));
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("{\"errors\":[\"Access denied: You don't have enough permission to read the information of the AppRole\"]}");
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRoleDetails_WithUserDetails_null_approle_failure() throws JsonProcessingException {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser2", true);
        String role_name = "testrole";
        ArrayList<String> policiesList = new ArrayList<>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);

        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.NOT_FOUND, true, "{}");

        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id", true);
        dataMap.put("secret_id_num_uses", 0);
        dataMap.put("secret_id_ttl", 0);
        dataMap.put("token_num_uses", 0);
        dataMap.put("token_ttl", 0);
        dataMap.put("token_max_ttl", 0);

        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\"" + role_name + "\"}",
                tkn)).thenReturn(appRoleResponse);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleDetails(tkn,
                "testrole", userDetails);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("{\"errors\":[\"AppRole doesn't exist\"]}");
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRoleDetails_WithUserDetails_access_denied_failure() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser2", false);
        String role_name = "approle1";
        String createdByUser = "someOtherUser";
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        String roleId="generated-role-id";

        ArrayList<String> policiesList = new ArrayList<>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);

        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);

        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id", true);
        dataMap.put("secret_id_num_uses", 0);
        dataMap.put("secret_id_ttl", 0);
        dataMap.put("token_num_uses", 0);
        dataMap.put("token_ttl", 0);
        dataMap.put("token_max_ttl", 0);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);

        AppRoleMetadata approleMetadata = new AppRoleMetadata();
        approleMetadata.setPath(path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(createdByUser);
        appRoleMetadataDetails.setName(role_name);
        approleMetadata.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String appRoleMetadataResponseJson = new ObjectMapper().writeValueAsString(approleMetadata);
        Response appRoleMetadataResponse = getMockResponse(HttpStatus.OK, true, appRoleMetadataResponseJson);

        Map<String, Object> appRoleMetadatResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", createdByUser);
        appRoleMetadatResponseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleMetadataResponseJson)).thenReturn(appRoleMetadatResponseMap);
        when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}",
                userDetails.getSelfSupportToken())).thenReturn(appRoleMetadataResponse);

        String roleIdResponseJson = "{\"data\":{ \"role_id\": \""+roleId+"\"}}";
        Response roleIdResponse = getMockResponse(HttpStatus.OK, true, roleIdResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", roleId);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"data\":{ \"role_id\": \""+roleId+"\"}}")).thenReturn(responseMap);
        when(reqProcessor.process("/auth/approle/role/readRoleID", "{\"role_name\":\""+role_name+"\"}",
                userDetails.getSelfSupportToken())).thenReturn(roleIdResponse);

        String accessorIdResponseJson = "{\r\n" +
                "  \"keys\": [\r\n" +
                "    \"generated-accessor-id1\"\r\n" +
                "  ]\r\n" +
                "}";
        Response accessorIdResponse = getMockResponse(HttpStatus.OK, true, accessorIdResponseJson);

        Map<String, Object> accessorIdResponseMap = new HashMap<>();
        ArrayList<String> accessorIds = new ArrayList<>();
        accessorIds.add("generated-accessor-id1");
        accessorIdResponseMap.put("keys", accessorIds);
        when(ControllerUtil.parseJson(accessorIdResponseJson)).thenReturn(responseMap);

        when(reqProcessor.process("/auth/approle/role/accessors/list", "{\"role_name\":\""+role_name+"\"}",
                userDetails.getSelfSupportToken())).thenReturn(accessorIdResponse);

        AppRoleDetails appRoleDetails = new AppRoleDetails();
        appRoleDetails.setRole_name(appRole.getRole_name());
        appRoleDetails.setPolicies(appRole.getPolicies());
        appRoleDetails.setBind_secret_id(appRole.isBind_secret_id());
        appRoleDetails.setSecret_id_num_uses(appRole.getSecret_id_num_uses());
        appRoleDetails.setSecret_id_ttl(appRole.getSecret_id_ttl());
        appRoleDetails.setToken_num_uses(appRole.getToken_num_uses());
        appRoleDetails.setToken_ttl(appRole.getToken_ttl());
        appRoleDetails.setToken_max_ttl(appRole.getToken_max_ttl());
        appRoleDetails.setRole_id(roleId);
        appRoleDetails.setAppRoleMetadata(approleMetadata);
        if (!CollectionUtils.isEmpty(accessorIds)) {
            appRoleDetails.setAccessorIds(accessorIds.toArray(new String[accessorIds.size()]));
        }
        String appRoleDetailsJson = objMapper.writeValueAsString(appRoleDetails);
        Response appRoleDetailsResponse = getMockResponse(HttpStatus.BAD_REQUEST, true,
                "{\"errors\":[\"Access denied: You don't have enough permission to read the secret_id associated with the AppRole\"]}");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(appRoleDetailsResponse.getHttpstatus())
                .body(appRoleDetailsResponse.getResponse());
        when(JSONUtil.getJSON(Mockito.any(AppRoleDetails.class))).thenReturn(appRoleDetailsJson);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleDetails(tkn, role_name, userDetails);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRoleDetails_WithUserDetails_access_denied_cannot_add_sharedTo_failure() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser2", false);
        String role_name = "approle1";
        String createdByUser = "someOtherUser";
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        String roleId="generated-role-id";

        ArrayList<String> policiesList = new ArrayList<>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);

        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);

        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id", true);
        dataMap.put("secret_id_num_uses", 0);
        dataMap.put("secret_id_ttl", 0);
        dataMap.put("token_num_uses", 0);
        dataMap.put("token_ttl", 0);
        dataMap.put("token_max_ttl", 0);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);

        AppRoleMetadata approleMetadata = new AppRoleMetadata();
        approleMetadata.setPath(path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(createdByUser);
        appRoleMetadataDetails.setName(role_name);
        approleMetadata.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String appRoleMetadataResponseJson = new ObjectMapper().writeValueAsString(approleMetadata);
        Response appRoleMetadataResponse = getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, "{}");

        Map<String, Object> appRoleMetadatResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", createdByUser);
        appRoleMetadatResponseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleMetadataResponseJson)).thenReturn(appRoleMetadatResponseMap);
        when(reqProcessor.process("/read", "{\"path\":\"" + path + "\"}",
                userDetails.getSelfSupportToken())).thenReturn(appRoleMetadataResponse);

        String roleIdResponseJson = "{\"data\":{ \"role_id\": \"" + roleId + "\"}}";
        Response roleIdResponse = getMockResponse(HttpStatus.OK, true, roleIdResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", roleId);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"data\":{ \"role_id\": \"" + roleId + "\"}}")).thenReturn(responseMap);
        when(reqProcessor.process("/auth/approle/role/readRoleID", "{\"role_name\":\"" + role_name + "\"}",
                userDetails.getSelfSupportToken())).thenReturn(roleIdResponse);

        String accessorIdResponseJson = "{\r\n" +
                "  \"keys\": [\r\n" +
                "    \"generated-accessor-id1\"\r\n" +
                "  ]\r\n" +
                "}";
        Response accessorIdResponse = getMockResponse(HttpStatus.OK, true, accessorIdResponseJson);

        Map<String, Object> accessorIdResponseMap = new HashMap<>();
        ArrayList<String> accessorIds = new ArrayList<>();
        accessorIds.add("generated-accessor-id1");
        accessorIdResponseMap.put("keys", accessorIds);
        when(ControllerUtil.parseJson(accessorIdResponseJson)).thenReturn(responseMap);

        when(reqProcessor.process("/auth/approle/role/accessors/list", "{\"role_name\":\""+role_name+"\"}",
                userDetails.getSelfSupportToken())).thenReturn(accessorIdResponse);

        AppRoleDetails appRoleDetails = new AppRoleDetails();
        appRoleDetails.setRole_name(appRole.getRole_name());
        appRoleDetails.setPolicies(appRole.getPolicies());
        appRoleDetails.setBind_secret_id(appRole.isBind_secret_id());
        appRoleDetails.setSecret_id_num_uses(appRole.getSecret_id_num_uses());
        appRoleDetails.setSecret_id_ttl(appRole.getSecret_id_ttl());
        appRoleDetails.setToken_num_uses(appRole.getToken_num_uses());
        appRoleDetails.setToken_ttl(appRole.getToken_ttl());
        appRoleDetails.setToken_max_ttl(appRole.getToken_max_ttl());
        appRoleDetails.setRole_id(roleId);
        appRoleDetails.setAppRoleMetadata(approleMetadata);
        if (!CollectionUtils.isEmpty(accessorIds)) {
            appRoleDetails.setAccessorIds(accessorIds.toArray(new String[accessorIds.size()]));
        }
        String appRoleDetailsJson = objMapper.writeValueAsString(appRoleDetails);
        Response appRoleDetailsResponse = getMockResponse(HttpStatus.BAD_REQUEST, true,
                "{\"errors\":[\"Access denied: You don't have enough permission to read the secret_id associated with the AppRole\"]}");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(appRoleDetailsResponse.getHttpstatus())
                .body(appRoleDetailsResponse.getResponse());
        when(JSONUtil.getJSON(Mockito.any(AppRoleDetails.class))).thenReturn(appRoleDetailsJson);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleDetails(tkn, role_name, userDetails);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRoleDetails_read_appRole_metadata_failure() throws Exception {
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = getMockUser("testuser2", false);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        String roleId="generated-role-id";

        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);

        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);

        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));

        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);

        AppRoleMetadata approleMetadata = new AppRoleMetadata();
        approleMetadata.setPath(path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadata.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String appRoleMetadataResponseJson = new ObjectMapper().writeValueAsString(approleMetadata);
        Response appRoleMetadataResponse = getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, "{}");

        Map<String, Object> appRoleMetadatResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",username);
        appRoleMetadatResponseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleMetadataResponseJson)).thenReturn(appRoleMetadatResponseMap);
        when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleMetadataResponse);

        String roleIdResponseJson = "{\"data\":{ \"role_id\": \""+roleId+"\"}}";
        Response roleIdResponse = getMockResponse(HttpStatus.OK, true, roleIdResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", roleId);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"data\":{ \"role_id\": \""+roleId+"\"}}")).thenReturn(responseMap);
        when(reqProcessor.process("/auth/approle/role/readRoleID", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(roleIdResponse);

        String accessorIdResponseJson = "{\r\n" +
                "  \"keys\": [\r\n" +
                "    \"generated-accessor-id1\"\r\n" +
                "  ]\r\n" +
                "}";
        Response accessorIdResponse = getMockResponse(HttpStatus.OK, true, accessorIdResponseJson);

        Map<String, Object> accessorIdResponseMap = new HashMap<>();
        ArrayList<String> accessorIds = new ArrayList<String>();
        accessorIds.add("generated-accessor-id1");
        accessorIdResponseMap.put("keys", accessorIds);
        when(ControllerUtil.parseJson(accessorIdResponseJson)).thenReturn(responseMap);

        when(reqProcessor.process("/auth/approle/role/accessors/list", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(accessorIdResponse);

        AppRoleDetails appRoleDetails = new AppRoleDetails();
        appRoleDetails.setRole_name(appRole.getRole_name());
        appRoleDetails.setPolicies(appRole.getPolicies());
        appRoleDetails.setBind_secret_id(appRole.isBind_secret_id());
        appRoleDetails.setSecret_id_num_uses(appRole.getSecret_id_num_uses());
        appRoleDetails.setSecret_id_ttl(appRole.getSecret_id_ttl());
        appRoleDetails.setToken_num_uses(appRole.getToken_num_uses());
        appRoleDetails.setToken_ttl(appRole.getToken_ttl());
        appRoleDetails.setToken_max_ttl(appRole.getToken_max_ttl());
        appRoleDetails.setRole_id(roleId);
        appRoleDetails.setAppRoleMetadata(approleMetadata);
        if (!CollectionUtils.isEmpty(accessorIds)) {
            appRoleDetails.setAccessorIds(accessorIds.toArray(new String[accessorIds.size()]));
        }
        String appRoleDetailsJson = objMapper.writeValueAsString(appRoleDetails);
        String appRoleDetailsResponseJson = objMapper.writeValueAsString(appRoleDetails);
        Response appRoleDetailsResponse =getMockResponse(HttpStatus.BAD_REQUEST, true,
                "{\"errors\":[\"Access denied: You don't have enough permission to read the secret_id associated with the AppRole\"]}");
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(appRoleDetailsResponse.getHttpstatus())
                .body(appRoleDetailsResponse.getResponse());
        when(JSONUtil.getJSON(Mockito.any(AppRoleDetails.class))).thenReturn(appRoleDetailsJson);

        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleDetails(tkn, role_name, userDetails);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_readAppRoleDetails_WithUserDetails_failure() throws Exception {

        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";

        UserDetails userDetails = getMockUser("testuser2", false);
        String role_name = "approle1";
        String username = userDetails.getUsername();
        String path = TVaultConstants.APPROLE_METADATA_MOUNT_PATH + "/" + role_name;
        String roleId="generated-role-id";
        
        
        
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRole appRole = new AppRole(role_name, policies, true, 0, 0, 0);
        
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        
        
        AppRoleMetadata approleMetadata = new AppRoleMetadata();
        approleMetadata.setPath(path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadata.setAppRoleMetadataDetails(appRoleMetadataDetails);
        
        String appRoleMetadataResponseJson = new ObjectMapper().writeValueAsString(approleMetadata);
        Response appRoleMetadataResponse = getMockResponse(HttpStatus.NOT_FOUND, true, appRoleMetadataResponseJson);
        
        Map<String, Object> appRoleMetadatResponseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy",username);
        appRoleMetadatResponseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(appRoleMetadataResponseJson)).thenReturn(appRoleMetadatResponseMap);
        when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleMetadataResponse);
        
        String roleIdResponseJson = "{\"data\":{ \"role_id\": \""+roleId+"\"}}";
        Response roleIdResponse = getMockResponse(HttpStatus.OK, true, roleIdResponseJson);
        
        Map<String, Object> responseMap = new HashMap<>();
        Map<String,Object> roleIdDataMap = new HashMap<>();
        roleIdDataMap.put("role_id", roleId);
        responseMap.put("data", roleIdDataMap);
        when(ControllerUtil.parseJson("{\"data\":{ \"role_id\": \""+roleId+"\"}}")).thenReturn(responseMap);
        when(reqProcessor.process("/auth/approle/role/readRoleID", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(roleIdResponse);
        
        String accessorIdResponseJson = "{\r\n" + 
        		"  \"keys\": [\r\n" + 
        		"    \"generated-accessor-id1\"\r\n" + 
        		"  ]\r\n" + 
        		"}";
        Response accessorIdResponse = getMockResponse(HttpStatus.OK, true, accessorIdResponseJson);
        
        Map<String, Object> accessorIdResponseMap = new HashMap<>();
        ArrayList<String> accessorIds = new ArrayList<String>();
        accessorIds.add("generated-accessor-id1");
        accessorIdResponseMap.put("keys", accessorIds);
        when(ControllerUtil.parseJson(accessorIdResponseJson)).thenReturn(responseMap);
        
        when(reqProcessor.process("/auth/approle/role/accessors/list", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(accessorIdResponse);
        
		AppRoleDetails appRoleDetails = new AppRoleDetails();
        appRoleDetails.setRole_name(appRole.getRole_name());
        appRoleDetails.setPolicies(appRole.getPolicies());
        appRoleDetails.setBind_secret_id(appRole.isBind_secret_id());
        appRoleDetails.setSecret_id_num_uses(appRole.getSecret_id_num_uses());
        appRoleDetails.setSecret_id_ttl(appRole.getSecret_id_ttl());
        appRoleDetails.setToken_num_uses(appRole.getToken_num_uses());
        appRoleDetails.setToken_ttl(appRole.getToken_ttl());
        appRoleDetails.setToken_max_ttl(appRole.getToken_max_ttl());
		appRoleDetails.setRole_id(roleId);
		appRoleDetails.setAppRoleMetadata(approleMetadata);
		if (!CollectionUtils.isEmpty(accessorIds)) {
			appRoleDetails.setAccessorIds(accessorIds.toArray(new String[accessorIds.size()]));
		}
        String appRoleDetailsResponseJson = "{\"errors\":[\"Access denied: You don't have enough permission to read the secret_id associated with the AppRole\"]}";
        Response appRoleDetailsResponse =getMockResponse(HttpStatus.BAD_REQUEST, true, appRoleDetailsResponseJson);
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(appRoleDetailsResponse.getHttpstatus()).body(appRoleDetailsResponse.getResponse());
        
        ResponseEntity<String> responseEntityActual = appRoleService.readAppRoleDetails(tkn, role_name, userDetails);

        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);

    }
    
    @Test
    public void test_updateAppRole_successfully() throws Exception{
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name="approle1";
        UserDetails userDetails = getMockUser("testuser1", false);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole updated successfully.\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"testuser1\",\"sharedTo\":null}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_as_admin_successfully() throws Exception{
        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name="approle1";
        UserDetails userDetails = getMockUser("testuser1", true);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id", true);
        dataMap.put("secret_id_num_uses", 0);
        dataMap.put("secret_id_ttl", 0);
        dataMap.put("token_num_uses", 0);
        dataMap.put("token_ttl", 0);
        dataMap.put("token_max_ttl", 0);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/read"), Mockito.eq("{\"role_name\":\""+role_name+"\"}"),
                Mockito.any())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole updated successfully.\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.any())).thenReturn(response);
        when(reqProcessor.process(Mockito.eq("/auth/approle/role/list"), Mockito.eq("{}"), Mockito.any())).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"testuser1\",\"sharedTo\":null}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        when(reqProcessor.process(Mockito.eq("/write"), Mockito.any(), Mockito.any())).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.any())).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_successfully_with_email() throws Exception{
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name="approle1";
        UserDetails userDetails = getMockUser("testuser1", false);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        appRoleUpdate.setOwner("newOwner");
        appRoleUpdate.setNew_owner_email("newOwner@hotmail.com");
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole updated successfully.\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        String userMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateUserMetaJson(Mockito.any(), Mockito.any())).thenReturn(userMetaJson);
        when(reqProcessor.process(Mockito.eq("/delete"), Mockito.eq(userMetaJson), Mockito.any())).thenReturn(response);

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"testuser1\",\"sharedTo\":null}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        DirectoryUser directoryUser = new DirectoryUser();
        directoryUser.setDisplayName("newOwner");
        when(commonUtils.getUserDetails(Mockito.any())).thenReturn(directoryUser);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_successfully_with_email_empty_user_lookup() throws Exception{
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name="approle1";
        UserDetails userDetails = getMockUser("testuser1", false);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        appRoleUpdate.setOwner("newOwner");
        appRoleUpdate.setNew_owner_email("newOwner@hotmail.com");
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole updated successfully.\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        String userMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateUserMetaJson(Mockito.any(), Mockito.any())).thenReturn(userMetaJson);
        when(reqProcessor.process(Mockito.eq("/delete"), Mockito.eq(userMetaJson), Mockito.any())).thenReturn(response);

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"testuser1\",\"sharedTo\":null}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        DirectoryUser directoryUser = new DirectoryUser();
        directoryUser.setDisplayName(" ");
        when(commonUtils.getUserDetails(Mockito.any())).thenReturn(directoryUser);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_successfully_with_shared_to() throws Exception{
        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name="approle1";
        UserDetails userDetails = getMockUser("testuser1", false);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        List<String> sharedTo = new ArrayList<>();
        sharedTo.add("someone");
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        appRole.setShared_to(sharedTo);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null,\"shared_to\":[\"someone\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole updated successfully.\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"testuser1\",\"sharedTo\":null}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        // update metadata for sharedTo
        String metaJson = "{\"path\":\"metadata/approle/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}";
        when(ControllerUtil.populateAppRoleMetaJson(Mockito.any(), Mockito.any())).thenReturn(metaJson);
        when(ControllerUtil.createMetadata(Mockito.eq(metaJson), Mockito.any())).thenReturn(true);

        String userMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateUserMetaJson(Mockito.any(), Mockito.any())).thenReturn(userMetaJson);
        when(ControllerUtil.createMetadata(Mockito.eq(userMetaJson), Mockito.any())).thenReturn(true);

        String sharedToUserMetaJson = "{\"path\":\"metadata/approle_users/someone/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateSharedToUserMetaJson(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(sharedToUserMetaJson);
        when(ControllerUtil.createMetadata(Mockito.eq(sharedToUserMetaJson), Mockito.any())).thenReturn(true);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_successfully_with_shared_to_changed() throws Exception{
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name="approle1";
        UserDetails userDetails = getMockUser("testuser1", false);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        List<String> sharedTo = new ArrayList<>();
        sharedTo.add("someone");
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        appRoleUpdate.setShared_to(sharedTo);
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null,\"shared_to\":[\"someone\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole updated successfully.\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        List<String> originalSharedTo = new ArrayList<>();
        originalSharedTo.add("originalperson");
        appRoleMetadataDetails.setSharedTo(originalSharedTo);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        appRoleMetadataMap.put("sharedTo", originalSharedTo);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"originalperson\"]}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        // update metadata for sharedTo
        String metaJson = "{\"path\":\"metadata/approle/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}";
        when(ControllerUtil.populateAppRoleMetaJson(Mockito.any(), Mockito.any())).thenReturn(metaJson);
        when(ControllerUtil.createMetadata(Mockito.eq(metaJson), Mockito.any())).thenReturn(true);

        String userMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateUserMetaJson(Mockito.any(), Mockito.any())).thenReturn(userMetaJson);
        when(ControllerUtil.createMetadata(Mockito.eq(userMetaJson), Mockito.any())).thenReturn(true);

        String sharedToUserMetaJson = "{\"path\":\"metadata/approle_users/someone/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateSharedToUserMetaJson(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(sharedToUserMetaJson);
        when(ControllerUtil.createMetadata(Mockito.eq(sharedToUserMetaJson), Mockito.any())).thenReturn(true);

        // remove users from shared list
        Response deleteResponse = new Response();
        deleteResponse.setHttpstatus(HttpStatus.NO_CONTENT);
        when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.any())).thenReturn(deleteResponse);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_successfully_with_new_owner() throws Exception {
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name="approle1";
        UserDetails userDetails = getMockUser("testuser1", false);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        appRoleUpdate.setOwner("newOwner");
        appRoleUpdate.setNew_owner_email("newowner@email.email");
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole updated successfully.\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        String userMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateUserMetaJson(Mockito.any(), Mockito.any())).thenReturn(userMetaJson);
        when(reqProcessor.process(Mockito.eq("/delete"), Mockito.eq(userMetaJson), Mockito.any())).thenReturn(response);

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"testuser1\",\"sharedTo\":null}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_approle_doesnt_exist_failure() throws Exception{
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name="some_insane_name_that_does_not_exist";
        UserDetails userDetails = getMockUser("testuser1", false);

        ArrayList<String> policiesList = new ArrayList<>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("{\"errors\":[\"AppRole doesn't exist.\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        Response mapResponse = getMockResponse(HttpStatus.NOT_FOUND, true, null);
        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_already_owner_failure() throws Exception{
        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "approle1";
        UserDetails userDetails = getMockUser("testuser1", false);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        appRoleUpdate.setOwner("testuser1");
        appRoleUpdate.setNew_owner_email("newowner@email.email");
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("{\"errors\":[\"Unable to transfer ownership of AppRole approle1 because testuser1 is already the owner\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"testuser1\",\"sharedTo\":null}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_with_new_owner_metadata_deletion_failure() throws Exception {
        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name="approle1";
        UserDetails userDetails = getMockUser("testuser1", false);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        appRoleUpdate.setOwner("newOwner");
        appRoleUpdate.setNew_owner_email("someEmail@email.email");
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AppRole updated successfully.\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        String userMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateUserMetaJson(Mockito.any(), Mockito.any())).thenReturn(userMetaJson);
        Response response400 = getMockResponse(HttpStatus.BAD_REQUEST, true, "");
        when(reqProcessor.process(Mockito.eq("/delete"), Mockito.eq(userMetaJson), Mockito.any())).thenReturn(response400);

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"testuser1\",\"sharedTo\":null}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_with_new_owner_no_email_given_failure() throws Exception {
        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name="approle1";
        UserDetails userDetails = getMockUser("testuser1", false);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        appRoleUpdate.setOwner("newOwner");
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"If you provide an owner you must also provide a new_owner_email, and vice versa.\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        String userMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateUserMetaJson(Mockito.any(), Mockito.any())).thenReturn(userMetaJson);
        Response response400 = getMockResponse(HttpStatus.BAD_REQUEST, true, "");
        when(reqProcessor.process(Mockito.eq("/delete"), Mockito.eq(userMetaJson), Mockito.any())).thenReturn(response400);

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"testuser1\",\"sharedTo\":null}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_new_owner_is_shared_user_failure() throws Exception {
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name="approle1";
        UserDetails userDetails = getMockUser("testuser1", false);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        appRoleUpdate.setOwner("newOwner");
        appRoleUpdate.setNew_owner_email("newowner@email.email");
        List<String> sharedTo = new ArrayList<>();
        sharedTo.add("newOwner");
        appRoleUpdate.setShared_to(sharedTo);
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("{\"errors\":[\"An AppRole cannot be shared with its owner. Please remove owner newOwner as a shared user, or change the owner.\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        String userMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"newOwner\"]}}\n";
        when(ControllerUtil.populateUserMetaJson(Mockito.any(), Mockito.any())).thenReturn(userMetaJson);
        when(reqProcessor.process(Mockito.eq("/delete"), Mockito.eq(userMetaJson), Mockito.any())).thenReturn(response);

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"testuser1\",\"sharedTo\":null}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_existing_owner_failure() throws Exception {
        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name = "approle1";
        UserDetails userDetails = getMockUser("testuser1", false);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        appRoleUpdate.setOwner("someOwner");
        appRoleUpdate.setNew_owner_email("someemail@email.email");
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("{\"errors\":[\"Unable to transfer ownership of AppRole approle1 because you are not the owner of the AppRole or an admin user.\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        String userMetaJson = "{\"path\":\"metadata/approle_users/someOwner/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"someOwner\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateUserMetaJson(Mockito.any(), Mockito.any())).thenReturn(userMetaJson);
        when(reqProcessor.process(Mockito.eq("/delete"), Mockito.eq(userMetaJson), Mockito.any())).thenReturn(response);

        String username = "someOwner";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"someOwner\",\"sharedTo\":null}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_with_shared_to_changed_metadata_delete_failure() throws Exception{
        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name="approle1";
        UserDetails userDetails = getMockUser("testuser1", false);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        List<String> sharedTo = new ArrayList<>();
        sharedTo.add("someone");
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        appRoleUpdate.setShared_to(sharedTo);
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id", true);
        dataMap.put("secret_id_num_uses", 0);
        dataMap.put("secret_id_ttl", 0);
        dataMap.put("token_num_uses", 0);
        dataMap.put("token_ttl", 0);
        dataMap.put("token_max_ttl", 0);
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null,\"shared_to\":[\"someone\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("{\"errors\":[\"Failed to delete metadata for user originalperson\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        List<String> originalSharedTo = new ArrayList<>();
        originalSharedTo.add("originalperson");
        appRoleMetadataDetails.setSharedTo(originalSharedTo);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        appRoleMetadataMap.put("sharedTo", originalSharedTo);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"originalperson\"]}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        // update metadata for sharedTo
        String metaJson = "{\"path\":\"metadata/approle/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}";
        when(ControllerUtil.populateAppRoleMetaJson(Mockito.any(), Mockito.any())).thenReturn(metaJson);
        when(ControllerUtil.createMetadata(Mockito.eq(metaJson), Mockito.any())).thenReturn(true);

        String userMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateUserMetaJson(Mockito.any(), Mockito.any())).thenReturn(userMetaJson);
        when(ControllerUtil.createMetadata(Mockito.eq(userMetaJson), Mockito.any())).thenReturn(true);

        String sharedToUserMetaJson = "{\"path\":\"metadata/approle_users/someone/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateSharedToUserMetaJson(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(sharedToUserMetaJson);
        when(ControllerUtil.createMetadata(Mockito.eq(sharedToUserMetaJson), Mockito.any())).thenReturn(true);

        // remove users from shared list
        Response deleteResponse = new Response();
        deleteResponse.setHttpstatus(HttpStatus.BAD_REQUEST);
        when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.any())).thenReturn(deleteResponse);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_non_owner_modifying_shared_to_failure() throws Exception{
        Response response =getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name="approle1";
        UserDetails userDetails = getMockUser("testuser2", false);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        List<String> sharedTo = new ArrayList<>();
        sharedTo.add("someone");
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        appRoleUpdate.setShared_to(sharedTo);
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null,\"shared_to\":[\"someone\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("{\"errors\":[\"Unable to update shared_to on AppRole approle1 because you are not the owner\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"testuser1\",\"sharedTo\":null}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        // update metadata for sharedTo
        String metaJson = "{\"path\":\"metadata/approle/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}";
        when(ControllerUtil.populateAppRoleMetaJson(Mockito.any(), Mockito.any())).thenReturn(metaJson);
        when(ControllerUtil.createMetadata(Mockito.eq(metaJson), Mockito.any())).thenReturn(true);

        String userMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateUserMetaJson(Mockito.any(), Mockito.any())).thenReturn(userMetaJson);
        when(ControllerUtil.createMetadata(Mockito.eq(userMetaJson), Mockito.any())).thenReturn(true);

        String sharedToUserMetaJson = "{\"path\":\"metadata/approle_users/someone/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"someone\"]}}\n";
        when(ControllerUtil.populateSharedToUserMetaJson(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(sharedToUserMetaJson);
        when(ControllerUtil.createMetadata(Mockito.eq(sharedToUserMetaJson), Mockito.any())).thenReturn(true);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.UNAUTHORIZED, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_shared_user_is_owner_failure() throws Exception{
        Response response = getMockResponse(HttpStatus.NO_CONTENT, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name="approle1";
        UserDetails userDetails = getMockUser("testuser1", false);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        List<String> sharedTo = new ArrayList<>();
        sharedTo.add("testuser1");
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        appRoleUpdate.setShared_to(sharedTo);
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);
        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null,\"shared_to\":[\"testuser1\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("{\"errors\":[\"An AppRole cannot be shared with the current owner\"]}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        appRoleMetadataDetails.setSharedTo(sharedTo);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        appRoleMetadataMap.put("sharedTo", sharedTo);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"testuser1\"]}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

        // update metadata for sharedTo
        String metaJson = "{\"path\":\"metadata/approle/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"testuser1\"]}}";
        when(ControllerUtil.populateAppRoleMetaJson(Mockito.any(), Mockito.any())).thenReturn(metaJson);
        when(ControllerUtil.createMetadata(Mockito.eq(metaJson), Mockito.any())).thenReturn(true);

        String userMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"testuser1\"]}}\n";
        when(ControllerUtil.populateUserMetaJson(Mockito.any(), Mockito.any())).thenReturn(userMetaJson);
        when(ControllerUtil.createMetadata(Mockito.eq(userMetaJson), Mockito.any())).thenReturn(true);

        String sharedToUserMetaJson = "{\"path\":\"metadata/approle_users/testuser1/test\",\"data\":{\"name\":\"test\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"testuser1\"]}}\n";
        when(ControllerUtil.populateSharedToUserMetaJson(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(sharedToUserMetaJson);
        when(ControllerUtil.createMetadata(Mockito.eq(sharedToUserMetaJson), Mockito.any())).thenReturn(true);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
        assertEquals(responseEntityExpected, responseEntityActual);
    }

    @Test
    public void test_updateAppRole_BAD_REQUEST() throws Exception{
        Response response =getMockResponse(HttpStatus.BAD_REQUEST, true, "");
        Response responseList = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        String role_name="approle1";
        UserDetails userDetails = getMockUser("testuser1", false);

        // START - AppRole exists
        ArrayList<String> policiesList = new ArrayList<String>();
        policiesList.add("r_shared_safe01");
        String[] policies = policiesList.toArray(new String[policiesList.size()]);
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate(role_name, policies, true, 0, 0, 0);
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
        String appRoleResponseJson = new ObjectMapper().writeValueAsString(appRole);
        Response appRoleResponse = getMockResponse(HttpStatus.OK, true, appRoleResponseJson);
        Map<String, Object> appRoleResponseMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        appRoleResponseMap.put("data", dataMap);
        dataMap.put("policies",policiesList);
        dataMap.put("bind_secret_id",new Boolean(true));
        dataMap.put("secret_id_num_uses", new Integer(0));
        dataMap.put("secret_id_ttl", new Integer(0));
        dataMap.put("token_num_uses", new Integer(0));
        dataMap.put("token_ttl", new Integer(0));
        dataMap.put("token_max_ttl", new Integer(0));
        when(reqProcessor.process("/auth/approle/role/read", "{\"role_name\":\""+role_name+"\"}",userDetails.getSelfSupportToken())).thenReturn(appRoleResponse);
        when(ControllerUtil.parseJson(appRoleResponseJson)).thenReturn(appRoleResponseMap);

        String username = "testuser1";
        String _path = "metadata/approle/" + role_name;
        List<String> sharedTo = new ArrayList<>();
        sharedTo.add("testuser2");
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(role_name);
        appRoleMetadataDetails.setSharedTo(sharedTo);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String sharedToResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response sharedToResponse = getMockResponse(HttpStatus.OK, true, sharedToResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        appRoleMetadataMap.put("sharedTo", sharedTo);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson("{\"path\":\"metadata/approle/approle1\",\"data\":{\"name\":\"approle1\",\"createdBy\":\"testuser1\",\"sharedTo\":[\"testuser2\"]}}")).thenReturn(responseMap);

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.any())).thenReturn(sharedToResponse);

        // END - AppRole exists
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":[\"default\"],\"bind_secret_id\":true,\"secret_id_num_uses\":\"1\",\"secret_id_ttl\":\"100m\",\"token_num_uses\":0,\"token_ttl\":null,\"token_max_ttl\":null}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{}");

        Map<String,Object> appRolesList = new HashMap<>();
        ArrayList<String> arrayList = new ArrayList<>();
        arrayList.add("role1");
        appRolesList.put("keys", arrayList);
        when(ControllerUtil.parseJson("{\"keys\": [ \"role1\" ]}")).thenReturn(appRolesList);

        Response responseAfterHide = getMockResponse(HttpStatus.OK, true, "{\"keys\": [ \"role1\" ]}");
        when(ControllerUtil.hideSelfSupportAdminAppRoleFromResponse(Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(responseAfterHide);

        when(reqProcessor.process(Mockito.eq("/auth/approle/role/create"), Mockito.any(),
                Mockito.eq(userDetails.getSelfSupportToken()))).thenReturn(response);
        when(reqProcessor.process("/auth/approle/role/list","{}", tkn)).thenReturn(responseList);
        when(ControllerUtil.areAppRoleInputsValid(appRole)).thenReturn(true);
        when(JSONUtil.getJSON(appRole)).thenReturn(jsonStr);
        when(ControllerUtil.convertAppRoleInputsToLowerCase(Mockito.any())).thenReturn(jsonStr);

        when(reqProcessor.process(Mockito.eq("/write"),Mockito.any(),Mockito.eq(tkn))).thenReturn(response);
        when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(true);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
    }
    
    @Test
    public void test_updateAppRole_failure() throws Exception{
        String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
        AppRoleUpdate appRoleUpdate = new AppRoleUpdate();
        UserDetails userDetails = getMockUser("testuser1", false);
        ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
        assertNotNull(responseEntityActual);
    }
    
	@Test
	public void test_updateAppRole_failure1() {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String rolename = "azure_admin_approle";
		ArrayList<String> policiesList = new ArrayList<String>();
		policiesList.add("r_shared_safe01");
		String[] policies = policiesList.toArray(new String[policiesList.size()]);
		AppRoleUpdate appRoleUpdate = new AppRoleUpdate(rolename, policies, true, 0, 0, 0);
		UserDetails userDetails = getMockUser("testuser1", false);
		ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
		assertNotNull(responseEntityActual);
	}
	
	@Test
	public void test_updateAppRole_failure2() throws Exception {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String rolename = "rolename";
		ArrayList<String> policiesList = new ArrayList<String>();
		policiesList.add("r_shared_safe01");
		String[] policies = policiesList.toArray(new String[policiesList.size()]);
		AppRoleUpdate appRoleUpdate = new AppRoleUpdate(rolename, policies, true, 0, 0, 0);
        AppRole appRole = constructAppRoleFromUpdateObject(appRoleUpdate);
		UserDetails userDetails = getMockUser("testuser1", false);
		Response response3 = new Response();
		response3.setHttpstatus(HttpStatus.OK);
		response3.setResponse("success");

        String username = "testuser1";
        String _path = "metadata/approle/" + rolename;
        AppRoleMetadata approleMetadataExpected = new AppRoleMetadata();
        approleMetadataExpected.setPath(_path);
        AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
        appRoleMetadataDetails.setCreatedBy(username);
        appRoleMetadataDetails.setName(rolename);
        approleMetadataExpected.setAppRoleMetadataDetails(appRoleMetadataDetails);

        String mapResponseJson = new ObjectMapper().writeValueAsString(approleMetadataExpected);
        Response mapResponse = getMockResponse(HttpStatus.OK, true, mapResponseJson);

        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> appRoleMetadataMap = new HashMap<>();
        appRoleMetadataMap.put("createdBy", username);
        responseMap.put("data", appRoleMetadataMap);
        when(ControllerUtil.parseJson(Mockito.any())).thenReturn(responseMap).thenReturn(new HashMap<>());

        when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(),
                Mockito.any())).thenReturn(mapResponse);

		when(reqProcessor.process(Mockito.eq("/auth/approle/role/read"), Mockito.any(), Mockito.any())).thenReturn(response3);
		ResponseEntity<String> responseEntityActual = appRoleService.updateAppRole(tkn, appRoleUpdate, userDetails);
		assertNotNull(responseEntityActual);
	}
	
	@Test
	public void test_deleteSecretIds_failure() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser("testuser1", false);
		AppRoleAccessorIds appRoleAccessorIds = new AppRoleAccessorIds();
		String[] accessorIds = {"1", "2"};
		appRoleAccessorIds.setAccessorIds(accessorIds);
		appRoleAccessorIds.setRole_name("rolename");
		Response response = new Response();
		response.setHttpstatus(HttpStatus.OK);
		when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.any())).thenReturn(response);
		ResponseEntity<String> responseEntityActual = appRoleService.deleteSecretIds(token, appRoleAccessorIds, userDetails);
		assertNotNull(responseEntityActual);
	}
	
	@Test
	public void test_deleteSecretIds_failure1() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser("testuser1", false);
		AppRoleAccessorIds appRoleAccessorIds = new AppRoleAccessorIds();
		String[] accessorIds = {"1", "2"};
		appRoleAccessorIds.setAccessorIds(accessorIds);
		appRoleAccessorIds.setRole_name("azure_admin_approle");
		Response response = new Response();
		response.setHttpstatus(HttpStatus.OK);
		when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.any())).thenReturn(response);
		ResponseEntity<String> responseEntityActual = appRoleService.deleteSecretIds(token, appRoleAccessorIds, userDetails);
		assertNotNull(responseEntityActual);
	}
	
	@Test
	public void test_deleteSecretIds_success() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser("safeadmin", false);
		AppRoleAccessorIds appRoleAccessorIds = new AppRoleAccessorIds();
		String[] accessorIds = {"1", "2"};
		appRoleAccessorIds.setAccessorIds(accessorIds);
		appRoleAccessorIds.setRole_name("rolename");
		Response response = new Response();
		response.setHttpstatus(HttpStatus.OK);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";

		response.setResponse(jsonStr);
		when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.any())).thenReturn(response);
		Map<String, Object> appRoleMetadataMap = new HashMap<>();
		Map<String, Object> appRoleResponseMap = new HashMap<>();
		String approleusername="safeadmin";
		appRoleMetadataMap.put("createdBy", approleusername);
		appRoleResponseMap.put("data", appRoleMetadataMap);
		when(ControllerUtil.parseJson(response.getResponse())).thenReturn(appRoleResponseMap);
		when(reqProcessor.process(Mockito.eq("/auth/approle/role/delete/secretids"), Mockito.any(), Mockito.any())).thenReturn(response);
		ResponseEntity<String> responseEntityActual = appRoleService.deleteSecretIds(token, appRoleAccessorIds, userDetails);
		assertNotNull(responseEntityActual);
	}
	
	@Test
	public void test_deleteSecretIds_success1() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser("safeadmin", false);
		AppRoleAccessorIds appRoleAccessorIds = new AppRoleAccessorIds();
		String[] accessorIds = {"1", "2"};
		appRoleAccessorIds.setAccessorIds(accessorIds);
		appRoleAccessorIds.setRole_name("rolename");
		Response response = new Response();
		response.setHttpstatus(HttpStatus.OK);
        String jsonStr = "{\"role_name\":\"approle1\",\"policies\":null,\"bind_secret_id\":false,\"secret_id_num_uses\":null,\"secret_id_ttl\":null,\"token_num_uses\":null,\"token_ttl\":null,\"token_max_ttl\":null}";

		response.setResponse(jsonStr);
		when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.any())).thenReturn(response);
		Map<String, Object> appRoleMetadataMap = new HashMap<>();
		Map<String, Object> appRoleResponseMap = new HashMap<>();
		String approleusername="safeadmin";
		appRoleMetadataMap.put("createdBy", approleusername);
		appRoleResponseMap.put("data", appRoleMetadataMap);
		when(ControllerUtil.parseJson(response.getResponse())).thenReturn(appRoleResponseMap);
		Response response1 = new Response();
		response1.setHttpstatus(HttpStatus.NO_CONTENT);
		when(reqProcessor.process(Mockito.eq("/auth/approle/role/delete/secretids"), Mockito.any(), Mockito.any())).thenReturn(response);
		ResponseEntity<String> responseEntityActual = appRoleService.deleteSecretIds(token, appRoleAccessorIds, userDetails);
		assertNotNull(responseEntityActual);
	}

    private AppRole constructAppRoleFromUpdateObject(AppRoleUpdate appRoleUpdate) {
        AppRole appRole = new AppRole();
        appRole.setRole_name(appRoleUpdate.getRole_name());
        appRole.setPolicies(appRoleUpdate.getPolicies());
        appRole.setBind_secret_id(appRoleUpdate.isBind_secret_id());
        appRole.setSecret_id_num_uses(appRoleUpdate.getSecret_id_num_uses());
        appRole.setToken_num_uses(appRoleUpdate.getToken_num_uses());
        appRole.setToken_ttl(appRoleUpdate.getToken_ttl());
        appRole.setToken_max_ttl(appRoleUpdate.getToken_max_ttl());
        appRole.setShared_to(appRoleUpdate.getShared_to());

        return appRole;
    }
}
