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
package com.tmobile.cso.vault.api.v2.controller;

import com.tmobile.cso.vault.api.common.TVaultConstants;
import com.tmobile.cso.vault.api.main.Application;
import com.tmobile.cso.vault.api.service.SecretService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = Application.class)
@ComponentScan(basePackages={"com.tmobile.cso.vault.api"})
@WebAppConfiguration
public class SecretControllerV2Test {

    private MockMvc mockMvc;

    @Mock
    private SecretService secretService;

    @InjectMocks
    private SecretControllerV2 secretControllerV2;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        this.mockMvc = MockMvcBuilders.standaloneSetup(secretControllerV2).build();
    }

    @Test
    public void test_readFromVault() throws Exception {

        String responseMessage = "{  \"data\": {    \"secret1\": \"value1\",    \"secret2\": \"value2\"  }}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseMessage);

        when(secretService.readFromVault(Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.eq("users/safe1"))).thenReturn(responseEntityExpected);
        when(secretService.readFoldersAndSecrets(Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.eq("users/safe1"))).thenReturn(responseEntityExpected);
        when(secretService.readFromVaultRecursive(Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.eq("users/safe1"))).thenReturn(responseEntityExpected);

        mockMvc.perform(MockMvcRequestBuilders.get("/v2/safes/folders/secrets?path=users/safe1")
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseMessage)));

        mockMvc.perform(MockMvcRequestBuilders.get("/v2/safes/folders/secrets?path=users/safe1&fetchOption=all")
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseMessage)));

        mockMvc.perform(MockMvcRequestBuilders.get("/v2/safes/folders/secrets?path=users/safe1&fetchOption=recursive")
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseMessage)));
    }

    @Test
    public void test_write() throws Exception {

        String inputJson ="{\"path\":\"shared/mysafe01/myfolder\",\"data\":{\"secret1\":\"value1\",\"secret2\":\"value2\"}}";
        String responseMessage = "{\"messages\":[\"Secret saved to vault\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseMessage);

        when(secretService.write(Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.any(), Mockito.any())).thenReturn(responseEntityExpected);

        mockMvc.perform(MockMvcRequestBuilders.post("/v2/write")
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8")
                .content(inputJson))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseMessage)));
    }

    @Test
    public void test_write_with_Delete_Flag() throws Exception {

        String inputJson ="{\"path\":\"shared/mysafe01/myfolder\",\"data\":{\"secret1\":\"value1\",\"secret2\":\"value2\"}}";
        String responseMessage = "{\"messages\":[\"Secret saved to vault\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseMessage);

        when(secretService.write(Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.any(), Mockito.any(),Mockito.any())).thenReturn(responseEntityExpected);

        mockMvc.perform(MockMvcRequestBuilders.post("/v2/write")
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8")
                .header("delete-flag", "true")
                .content(inputJson))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseMessage)));
    }

    @Test
    public void test_deleteFromVault() throws Exception {

        String responseMessage = "{\"messages\":[\"Secrets deleted\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseMessage);

        when(secretService.deleteFromVault(Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.eq("users/safe1"))).thenReturn(responseEntityExpected);

        mockMvc.perform(MockMvcRequestBuilders.delete("/v2/safes/folders/secrets?path=users/safe1")
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseMessage)));
    }

    @Test
    public void test_getSecretCount() throws Exception {

        String responseMessage = "{\n" +
                "  \"totalSecrets\": 9,\n" +
                "  \"userSafeSecretCount\": {\n" +
                "    \"totalCount\": 2,\n" +
                "    \"safeSecretCount\": {\n" +
                "      \"testsafe1\": 0,\n" +
                "\t  \"testsafe2\": 2,\n" +
                "    }\n" +
                "  },\n" +
                "  \"sharedSafeSecretCount\": {\n" +
                "    \"totalCount\": 3,\n" +
                "    \"safeSecretCount\": {\n" +
                "      \"testsafe3\": 1,\n" +
                "\t  \"testsafe4\": 2,\n" +
                "    }\n" +
                "  },\n" +
                "  \"appsSafeSecretCount\": {\n" +
                "    \"totalCount\": 4,\n" +
                "    \"safeSecretCount\": {\n" +
                "      \"testsafe5\": 2,\n" +
                "\t  \"testsafe6\": 2,\n" +
                "    }\n" +
                "  }\n" +
                "}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseMessage);

        when(secretService.getSecretCount(Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.eq(TVaultConstants.SHARED), Mockito.eq(0))).thenReturn(responseEntityExpected);
        mockMvc.perform(MockMvcRequestBuilders.get("/v2/safes/count?safeType=shared&offset=0")
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseMessage)));

    }

    @Test
    public void test_getFolderVersionInfo() throws Exception {

        String responseMessage = "{\n" +
                "  \"folderModifiedAt\": 1611148845423,\n" +
                "  \"folderModifiedBy\": \"role1 (AppRole)\",\n" +
                "  \"folderPath\": \"users/123safe/fld1\",\n" +
                "  \"secretVersions\": {\n" +
                "    \"secret2\": [\n" +
                "      {\n" +
                "        \"modifiedAt\": 1611148845423,\n" +
                "        \"modifiedBy\": \"role1 (AppRole)\"\n" +
                "      }\n" +
                "    ],\n" +
                "    \"secret3\": [\n" +
                "      {\n" +
                "        \"modifiedAt\": 1611148845423,\n" +
                "        \"modifiedBy\": \"role1 (AppRole)\"\n" +
                "      }\n" +
                "    ]\n" +
                "  }\n" +
                "}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseMessage);

        when(secretService.getFolderVersionInfo(Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.eq("users/123safe/fld1"))).thenReturn(responseEntityExpected);
        mockMvc.perform(MockMvcRequestBuilders.get("/v2/safes/folders/versioninfo?path=users/123safe/fld1")
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseMessage)));

    }
}
