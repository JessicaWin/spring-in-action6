package com.example.tacos.integration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController()
@RequestMapping(path = "/integration")
public class IntegrationTestController {

  @Autowired
  private FileWriterGateway fileWriterGateway;

  @PostMapping(path = "/write")
  public void writeToFile(@RequestParam String fileName, @RequestParam String fileBody) {
    fileWriterGateway.writeToFile(fileName, fileBody);
  }
}
