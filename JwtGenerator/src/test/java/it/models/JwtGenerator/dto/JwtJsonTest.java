package it.models.JwtGenerator.dto;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.json.JsonTest;
import org.springframework.boot.test.json.JacksonTester;

@JsonTest
class JwtJsonTest {

    @Autowired
    private JacksonTester<Token> tokenJson;

    @Autowired
    private JacksonTester<UserProfile> userProfileJson;

    @Test
    @DisplayName("JSON - Token Serialization")
    void testTokenSerialization() throws Exception {
        Token token = new Token("sampleAccess", "sampleRefresh");

        assertThat(tokenJson.write(token)).hasJsonPathStringValue(
            "@.accessToken"
        );
        assertThat(tokenJson.write(token))
            .extractingJsonPathStringValue("@.accessToken")
            .isEqualTo("sampleAccess");
        assertThat(tokenJson.write(token)).hasJsonPathStringValue(
            "@.refreshToken"
        );
    }

    @Test
    @DisplayName("JSON - UserProfile Deserialization")
    void testUserProfileDeserialization() throws Exception {
        String jsonContent = "{\"id\":50,\"roles\":[\"ADMIN\"]}";
        UserProfile expected = new UserProfile(50L, List.of("ADMIN"));

        assertThat(userProfileJson.parse(jsonContent)).isEqualTo(expected);
        assertThat(userProfileJson.parseObject(jsonContent).id()).isEqualTo(
            50L
        );
    }
}
