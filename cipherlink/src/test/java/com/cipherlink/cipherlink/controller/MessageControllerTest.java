package com.cipherlink.cipherlink.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class MessageControllerTest {
    @Autowired private MockMvc mockMvc;
    @Test void serverSidePlaintextEncryptionEndpointIsRetired() throws Exception {
        mockMvc.perform(post("/api/messages/encrypt")).andExpect(status().isGone());
    }
}
