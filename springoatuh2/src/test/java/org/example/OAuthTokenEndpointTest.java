package org.example;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class OAuthTokenEndpointTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void testValidMobilePhoneGrant() throws Exception {
        // 测试有效的手机号码授权请求
        // 创建请求参数
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "mobile_phone");
        params.add("client_id", "mobile-client");
        params.add("client_secret", "secret");
        params.add("phone_number", "1234567890");
        params.add("sms_code", "123456");

        // 发送POST请求到/oauth/token端点
        String authHeader = "Basic " + Base64.getEncoder().encodeToString("mobile-client:secret".getBytes());

        MvcResult result = mockMvc.perform(post("/oauth2/token")
            .params(params)
            .header("Authorization", authHeader)  // 添加 Basic Auth 头
            .contentType(MediaType.APPLICATION_FORM_URLENCODED))
            .andExpect(status().isOk())
                // 验证响应中包含access_token
                .andExpect(jsonPath("$.access_token").exists())
                // 验证token_type为bearer
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                // 验证响应中包含expires_in
                .andExpect(jsonPath("$.expires_in").exists())
                .andReturn();

        // 打印响应内容
        System.out.println("有效的手机号码授权响应:");
        System.out.println(result.getResponse().getContentAsString());
    }

    @Test
    public void testInvalidMobilePhoneGrant() throws Exception {
        // 测试无效的SMS验证码
        // 创建请求参数，使用无效的SMS验证码
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "mobile_phone");
        params.add("client_id", "mobile-client");
        params.add("client_secret", "secret");
        params.add("phone_number", "1234567890");
        params.add("sms_code", "invalid_code");

        // 发送POST请求到/oauth/token端点
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                .params(params)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                // 验证响应状态为401 Unauthorized
                .andExpect(status().isUnauthorized())
                // 验证错误类型为unauthorized
                .andExpect(jsonPath("$.error").value("unauthorized"))
                // 验证存在错误描述
                .andExpect(jsonPath("$.error_description").exists())
                .andReturn();

        // 打印响应内容
        System.out.println("无效的SMS验证码响应:");
        System.out.println(result.getResponse().getContentAsString());
    }

    @Test
    public void testInvalidClientCredentials() throws Exception {
        // 测试无效的客户端凭据
        // 创建请求参数，使用无效的客户端ID和密钥
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "mobile_phone");
        params.add("client_id", "invalid-client");
        params.add("client_secret", "invalid-secret");
        params.add("phone_number", "1234567890");
        params.add("sms_code", "123456");

        // 发送POST请求到/oauth/token端点
        MvcResult result = mockMvc.perform(post("/oauth/token")
                .params(params)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                // 验证响应状态为401 Unauthorized
                .andExpect(status().isUnauthorized())
                // 验证错误类型为unauthorized
                .andExpect(jsonPath("$.error").value("unauthorized"))
                // 验证存在错误描述
                .andExpect(jsonPath("$.error_description").exists())
                .andReturn();

        // 打印响应内容
        System.out.println("无效的客户端凭据响应:");
        System.out.println(result.getResponse().getContentAsString());
    }

    @Test
    public void testMissingRequiredParameters() throws Exception {
        // 测试缺少必需参数的情况
        // 创建请求参数，故意省略phone_number和sms_code
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "mobile_phone");
        params.add("client_id", "mobile-client");
        params.add("client_secret", "secret");
        // 缺少 phone_number 和 sms_code

        // 发送POST请求到/oauth/token端点
        MvcResult result = mockMvc.perform(post("/oauth/token")
                .params(params)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                // 验证响应状态为400 Bad Request
                .andExpect(status().isBadRequest())
                // 验证错误类型为invalid_request
                .andExpect(jsonPath("$.error").value("invalid_request"))
                // 验证存在错误描述
                .andExpect(jsonPath("$.error_description").exists())
                .andReturn();

        // 打印响应内容
        System.out.println("缺少必需参数的响应:");
        System.out.println(result.getResponse().getContentAsString());
    }
}