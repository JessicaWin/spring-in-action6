package com.example.tacos.dao;

import com.example.tacos.model.TacoOrder;

public interface OrderRepository {
	TacoOrder save(TacoOrder order);
}
