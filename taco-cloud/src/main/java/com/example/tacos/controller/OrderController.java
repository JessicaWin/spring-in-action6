package com.example.tacos.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Controller;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.example.tacos.dao.OrderRepository;
import com.example.tacos.model.TacoOrder;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequestMapping("/orders")
@SessionAttributes("tacoOrder")
public class OrderController {
	private OrderRepository orderRepo;

	public OrderController(OrderRepository orderRepo) {
		this.orderRepo = orderRepo;
	}

	@GetMapping("/current")
	public String orderForm() {
		return "orderForm";
	}

	@GetMapping("/{id}")
	public ModelAndView order(@PathVariable(name = "id", required = true) String id) {
		Map<String, Object> dataMap = new HashMap<>();
		if (this.orderRepo.findById(id).orElseGet(() -> null) != null) {
			dataMap.put("tacoOrder", this.orderRepo.findById(id).get());
			return new ModelAndView("orderDetail", dataMap);
		}
		return new ModelAndView("notFound");
	}

	@PostMapping
	public String processOrder(@Valid TacoOrder order, Errors errors, SessionStatus sessionStatus) {
		if (errors.hasErrors()) {
			return "orderForm";
		}

		log.info("Order submitted: {}", order);
		TacoOrder newOrder = orderRepo.save(order);
		sessionStatus.setComplete();
		return "redirect:/orders/" + newOrder.getId();
	}
}