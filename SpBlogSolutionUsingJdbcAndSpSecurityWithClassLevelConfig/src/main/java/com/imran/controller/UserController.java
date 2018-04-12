package com.imran.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.imran.service.PostService;
import com.imran.service.UserService;


@Controller
@RequestMapping(value = "/user")
public class UserController {
	
	@Autowired
	UserService userService;
	
	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String index(Model model) {
		return "user/dashboard";
	}
	
	@RequestMapping(value = "/reg", method = RequestMethod.GET)
	public String registrationView(Model model) {
		return "user/registration";
	}
	
	@RequestMapping(value = "/reg", method = RequestMethod.POST)
	public String registration(Model model, @RequestParam("gender") String gender, @RequestParam("name") String name, @RequestParam("email") String email, @RequestParam("password") String password) {
		int resultStatus = 0;  
		if(email.equals("") || password.equals("") || gender.equals("") || name.equals("")){
			  model.addAttribute("message", "Require field is Empty");
			  return "redirect:/user/reg";
			}
		resultStatus = userService.userRegistration(name, email, password, gender);
		if(resultStatus>0){
			System.out.println("Successfully registration Complete.");
		}else{
			System.out.println("Registration Failed.");
		}	  
		  return "redirect:/user/reg";
	}
}

