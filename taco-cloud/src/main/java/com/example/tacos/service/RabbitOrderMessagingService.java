package com.example.tacos.service;

import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.stereotype.Service;
import com.example.tacos.model.TacoOrder;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class RabbitOrderMessagingService implements OrderMessagingService {
  private RabbitTemplate rabbit;
  private MessageConverter converter;

  private final static ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  public RabbitOrderMessagingService(RabbitTemplate rabbit) {
    this.rabbit = rabbit;
    this.converter = rabbit.getMessageConverter();
  }

  public void sendOrder(TacoOrder order) {
    rabbit.convertAndSend("tacocloud.order.queue", order);
  }

  @Override
  public TacoOrder receiveOrder() throws Exception {
    Message message = rabbit.receive("tacocloud.order.queue");
    if (message != null) {
      Object object = converter.fromMessage(message);
      log.info(object.getClass().getClassLoader().toString());
      log.info(TacoOrder.class.getClassLoader().toString());
      return OBJECT_MAPPER.readValue(OBJECT_MAPPER.writeValueAsString(object), TacoOrder.class);
    }

    return null;
  }
}
