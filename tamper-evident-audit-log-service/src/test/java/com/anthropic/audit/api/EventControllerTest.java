package com.anthropic.audit.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class EventControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String validEventJson(String actorId, String eventType) throws Exception {
        return objectMapper.writeValueAsString(Map.of(
                "eventType", eventType,
                "actorId", actorId,
                "resourceType", "USER",
                "resourceId", "user-1",
                "payload", Map.of("detail", "some detail")
        ));
    }

    @Test
    void ingestReturnsCreatedRecordWithServerAssignedTimestampAndHash() throws Exception {
        mockMvc.perform(post("/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validEventJson("alice", "USER_LOGIN")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.eventType").value("USER_LOGIN"))
                .andExpect(jsonPath("$.actorId").value("alice"))
                .andExpect(jsonPath("$.timestamp").exists())
                .andExpect(jsonPath("$.recordHash").isString())
                .andExpect(jsonPath("$.previousHash").isString());
    }

    @Test
    void ingestRejectsMissingRequiredFields() throws Exception {
        String badJson = objectMapper.writeValueAsString(Map.of(
                "eventType", "USER_LOGIN"
                // missing actorId, resourceType, resourceId, payload
        ));

        mockMvc.perform(post("/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(badJson))
                .andExpect(status().isBadRequest());
    }

    @Test
    void ingestIgnoresCallerSuppliedTimestampField() throws Exception {
        String jsonWithTimestamp = """
                {
                  "eventType": "USER_LOGIN",
                  "actorId": "alice",
                  "resourceType": "USER",
                  "resourceId": "user-1",
                  "payload": {},
                  "timestamp": "1999-01-01T00:00:00Z"
                }
                """;

        mockMvc.perform(post("/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonWithTimestamp))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.timestamp", not(startsWith("1999"))));
    }

    @Test
    void queryFiltersByActorId() throws Exception {
        mockMvc.perform(post("/events").contentType(MediaType.APPLICATION_JSON)
                .content(validEventJson("filter-actor", "PERMISSION_GRANTED")));
        mockMvc.perform(post("/events").contentType(MediaType.APPLICATION_JSON)
                .content(validEventJson("someone-else", "PERMISSION_GRANTED")));

        mockMvc.perform(get("/events").param("actorId", "filter-actor"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", everyItem(hasEntry("actorId", "filter-actor"))));
    }

    @Test
    void queryRejectsInvalidPageSize() throws Exception {
        mockMvc.perform(get("/events").param("size", "0"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void queryReturnsPaginationMetadata() throws Exception {
        mockMvc.perform(get("/events").param("page", "0").param("size", "5"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(5))
                .andExpect(jsonPath("$.totalElements").isNumber())
                .andExpect(jsonPath("$.totalPages").isNumber());
    }

    @Test
    void putOnEventsIsNotSupported() throws Exception {
        mockMvc.perform(put("/events/0")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    void deleteOnEventsIsNotSupported() throws Exception {
        mockMvc.perform(delete("/events/0"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    void patchOnEventsIsNotSupported() throws Exception {
        mockMvc.perform(patch("/events/0")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    void verifyReportsIntactChain() throws Exception {
        mockMvc.perform(post("/events").contentType(MediaType.APPLICATION_JSON)
                .content(validEventJson("verify-actor", "USER_LOGIN")));

        mockMvc.perform(get("/events/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true))
                .andExpect(jsonPath("$.firstBrokenSequence").doesNotExist());
    }

    @Test
    void redactClearsFieldValueAndChainRemainsIntact() throws Exception {
        String json = objectMapper.writeValueAsString(Map.of(
                "eventType", "PAYMENT_PROCESSED",
                "actorId", "redact-actor",
                "resourceType", "ACCOUNT",
                "resourceId", "acct-redact",
                "payload", Map.of("accountNumber", "1234567890")
        ));

        String response = mockMvc.perform(post("/events").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        long sequence = objectMapper.readTree(response).get("sequence").asLong();

        String redactRequest = objectMapper.writeValueAsString(Map.of(
                "field", "accountNumber",
                "reason", "privacy request"
        ));

        mockMvc.perform(post("/events/" + sequence + "/redact")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(redactRequest))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.payload.accountNumber.value").doesNotExist())
                .andExpect(jsonPath("$.payload.accountNumber.redacted").value(true))
                .andExpect(jsonPath("$.payload.accountNumber.contentHash").isString());

        mockMvc.perform(get("/events/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.intact").value(true));
    }

    @Test
    void redactUnknownFieldReturnsBadRequest() throws Exception {
        String response = mockMvc.perform(post("/events").contentType(MediaType.APPLICATION_JSON)
                        .content(validEventJson("someone", "USER_LOGIN")))
                .andReturn().getResponse().getContentAsString();
        long sequence = objectMapper.readTree(response).get("sequence").asLong();

        String redactRequest = objectMapper.writeValueAsString(Map.of(
                "field", "doesNotExist",
                "reason", "privacy request"
        ));

        mockMvc.perform(post("/events/" + sequence + "/redact")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(redactRequest))
                .andExpect(status().isBadRequest());
    }

    @Test
    void retentionApplyArchivesNothingWhenAllRecordsAreRecent() throws Exception {
        mockMvc.perform(post("/events").contentType(MediaType.APPLICATION_JSON)
                .content(validEventJson("retention-actor", "USER_LOGIN")));

        mockMvc.perform(post("/events/retention/apply")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"retentionWindow\":\"P90D\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.archivedCount").value(0));
    }

    @Test
    void exportRequiresAFilter() throws Exception {
        mockMvc.perform(get("/events/export"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void exportReturnsSelfContainedVerifiableBundle() throws Exception {
        String json = objectMapper.writeValueAsString(Map.of(
                "eventType", "DOC_VIEWED",
                "actorId", "export-actor",
                "resourceType", "DOCUMENT",
                "resourceId", "doc-export-1",
                "payload", Map.of("k", "v")
        ));
        mockMvc.perform(post("/events").contentType(MediaType.APPLICATION_JSON).content(json));

        mockMvc.perform(get("/events/export").param("resourceId", "doc-export-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records", not(empty())))
                .andExpect(jsonPath("$.precedingHash").isString())
                .andExpect(jsonPath("$.chainHeadHash").isString())
                .andExpect(jsonPath("$.chainLength").isNumber())
                .andExpect(jsonPath("$.records[0].resourceId").value("doc-export-1"));
    }
}
