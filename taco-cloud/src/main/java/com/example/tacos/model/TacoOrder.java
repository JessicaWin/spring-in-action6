package com.example.tacos.model;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.hibernate.validator.constraints.CreditCardNumber;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import jakarta.validation.constraints.Digits;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@Table
public class TacoOrder {
	@Id
	private Long id;

	@Column
	@NotBlank(message = "Delivery name is required")
	private String deliveryName;

	@Column
	@NotBlank(message = "Street is required")
	private String deliveryStreet;

	@Column
	@NotBlank(message = "City is required")
	private String deliveryCity;

	@Column
	@NotBlank(message = "State is required")
	@Size(min = 2, max = 2, message = "State length is 2")
	private String deliveryState;

	@Column
	@NotBlank(message = "Zip code is required")
	private String deliveryZip;

	@Column
	@CreditCardNumber(message = "Not a valid credit card number")
	private String ccNumber;

	@Column
	@Pattern(regexp = "^(0[1-9]|1[0-2])([\\/])([2-9][0-9])$", message = "Must be formatted MM/YY")
	private String ccExpiration;

	@Column
	@Digits(integer = 3, fraction = 0, message = "Invalid CVV")
	private String ccCVV;

	private List<Taco> tacos = new ArrayList<>();

	private Date placedAt = new Date();

	public void addTaco(Taco taco) {
		this.tacos.add(taco);
	}
}