package com.example.tacos.service;


import org.springframework.jms.core.JmsTemplate;
import org.springframework.stereotype.Service;
import com.example.tacos.model.TacoOrder;

@Service
public class JmsOrderMessagingService implements OrderMessagingService {
  private JmsTemplate jms;

  public JmsOrderMessagingService(JmsTemplate jms) {
    this.jms = jms;
  }

  @Override
  public void sendOrder(TacoOrder order) {
    jms.send(session -> session.createObjectMessage(order));
  }
}
