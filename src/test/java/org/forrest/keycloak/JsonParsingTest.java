package org.forrest.keycloak;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.forrest.keycloak.bind.RemoteUserEntity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import java.util.List;

public class JsonParsingTest {

    private ObjectMapper objectMapper;

    @BeforeEach
    public void setUp() {
        objectMapper = new ObjectMapper();
    }

    @Test
    public void testParseIdentityAdapterResponse() throws IOException {
        // Load the test JSON file
        File jsonFile = new File("src/test/data/identity-adapter-response.json");
        assertTrue(jsonFile.exists(), "Test JSON file should exist: " + jsonFile.getAbsolutePath());

        // Parse the JSON
        List<RemoteUserEntity> users = objectMapper.readValue(jsonFile, 
            new TypeReference<List<RemoteUserEntity>>() {});

        // Verify the parsing worked
        assertNotNull(users, "Parsed users list should not be null");
        assertEquals(4, users.size(), "Should have 4 users");

        // Check the first user
        RemoteUserEntity firstUser = users.get(0);
        assertEquals("bdbae799-43b9-4fbd-a904-07bd1de42d00", firstUser.getId(), "First user ID");
        assertEquals("Cloud", firstUser.getFirstName(), "First user firstName");
        assertEquals("ProcessingUser", firstUser.getLastName(), "First user lastName");
        assertEquals("cloudprocessinguser", firstUser.getUserName(), "First user userName");
        assertEquals("cloudprocessinguser@ancoradocs.com", firstUser.getEmail(), "First user email");
        assertTrue(firstUser.isEmailVerified(), "First user emailVerified should be true");
        assertTrue(firstUser.isEnabled(), "First user enabled should be true");
        assertEquals("0001-01-01T00:00:00+00:00", firstUser.getCreatedAt(), "First user createdAt");
        
        assertNotNull(firstUser.getRoles(), "First user roles should not be null");
        assertEquals(6, firstUser.getRoles().length, "First user should have 6 roles");
        assertEquals("Input", firstUser.getRoles()[0], "First user first role should be 'Input'");

        // Check user with empty fields
        RemoteUserEntity secondUser = users.get(1);
        assertEquals("GeneralUser", secondUser.getUserName(), "Second user userName");
        assertEquals("", secondUser.getFirstName(), "Second user firstName should be empty");
        assertEquals("", secondUser.getLastName(), "Second user lastName should be empty");
        assertEquals("", secondUser.getEmail(), "Second user email should be empty");
        assertTrue(secondUser.isEmailVerified(), "Second user emailVerified should be true");
        assertTrue(secondUser.isEnabled(), "Second user enabled should be true");
    }

    @Test
    public void testUserWithAdminRole() throws IOException {
        File jsonFile = new File("src/test/data/identity-adapter-response.json");
        List<RemoteUserEntity> users = objectMapper.readValue(jsonFile, 
            new TypeReference<List<RemoteUserEntity>>() {});

        // Check the connector user (third user) who has Admin role
        RemoteUserEntity connectorUser = users.get(2);
        assertEquals("connector", connectorUser.getUserName(), "Connector user userName");
        assertEquals("therefore", connectorUser.getFirstName(), "Connector user firstName");
        assertEquals("connector", connectorUser.getLastName(), "Connector user lastName");
        
        assertNotNull(connectorUser.getRoles(), "Connector user roles should not be null");
        assertEquals(7, connectorUser.getRoles().length, "Connector user should have 7 roles");
        
        // Check that Admin role is present
        boolean hasAdminRole = false;
        for (String role : connectorUser.getRoles()) {
            if ("Admin".equals(role)) {
                hasAdminRole = true;
                break;
            }
        }
        assertTrue(hasAdminRole, "Connector user should have Admin role");
    }
}
