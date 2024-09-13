package org.example.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.TimeUnit;

@RestController
public class SmsController {


    @PostMapping("/send-sms")
    public String sendSms(@RequestParam String phoneNumber) {
        String code = "123456";
        // 这里应该调用实际的短信发送API
        return "SMS code sent successfully";
    }

    private String generateCode() {
        return String.format("%06d", (int) (Math.random() * 1000000));
    }
}