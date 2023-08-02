package com.example.tacos.service;

import org.springframework.jms.annotation.JmsListener;
import org.springframework.stereotype.Service;
import com.example.tacos.model.TacoOrder;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class OrderListener {

  @JmsListener(destination = "tacocloud.order.queue")
  public void receiveOrder(TacoOrder order) throws Exception {
    log.info("Received order: " + new ObjectMapper().writeValueAsString(order));
  }

}
