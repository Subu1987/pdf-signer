package com.infocus.pdfsigner;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.infocus.pdfsigner.config.TokenConfig;

@SpringBootApplication
@EnableConfigurationProperties(TokenConfig.class)
public class PdfSignerApplication {
    public static void main(String[] args) {
        // Launch the Spring Boot application
        SpringApplication.run(PdfSignerApplication.class, args);
    }
}
// This is the main entry point for the Spring Boot application. It uses the @SpringBootApplication annotation to enable auto-configuration, component scanning, and configuration properties scanning. The main method calls SpringApplication.run() to start the application.
// The application is designed to handle PDF signing requests, and it is expected to be run in a Java environment with the necessary dependencies for Spring Boot and PDF processing libraries. 