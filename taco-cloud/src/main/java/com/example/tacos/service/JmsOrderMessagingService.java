package com.example.tacos.service;


import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jms.core.JmsTemplate;
import com.example.tacos.model.TacoOrder;
import com.fasterxml.jackson.databind.ObjectMapper;

@Qualifier("jms")
public class JmsOrderMessagingService implements OrderMessagingService {
  private JmsTemplate jms;
  private final static ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  public JmsOrderMessagingService(JmsTemplate jms) {
    this.jms = jms;
  }

  @Override
  public void sendOrder(TacoOrder order) {
    jms.send(session -> session.createObjectMessage(order));
  }

  @Override
  public TacoOrder receiveOrder() throws Exception {
    Object object = jms.receiveAndConvert();
    return object == null ? null
        : OBJECT_MAPPER.readValue(OBJECT_MAPPER.writeValueAsString(object), TacoOrder.class);
  }
}
