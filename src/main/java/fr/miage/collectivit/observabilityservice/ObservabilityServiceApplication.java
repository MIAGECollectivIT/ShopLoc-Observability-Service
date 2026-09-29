package fr.miage.collectivit.observabilityservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@SuppressWarnings("PMD.UseUtilityClass")
public class ObservabilityServiceApplication {

  public static void main(String[] args) {
    SpringApplication.run(ObservabilityServiceApplication.class, args);
  }
}
