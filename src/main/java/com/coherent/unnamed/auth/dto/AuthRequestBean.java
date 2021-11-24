package com.coherent.unnamed.auth.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.EqualsAndHashCode;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
@EqualsAndHashCode
public class AuthRequestBean {

	private String email;
	private Integer otp;


}
