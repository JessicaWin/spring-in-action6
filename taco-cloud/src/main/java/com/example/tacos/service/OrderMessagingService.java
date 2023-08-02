package com.example.tacos.service;

import com.example.tacos.model.TacoOrder;

public interface OrderMessagingService {
  void sendOrder(TacoOrder order);

  TacoOrder receiveOrder() throws Exception;
}
