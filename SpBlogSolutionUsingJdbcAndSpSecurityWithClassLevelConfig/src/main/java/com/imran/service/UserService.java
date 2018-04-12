package com.imran.service;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.imran.model.User;



@Component
public class UserService {
	
	 @Autowired  
	 DataSource dataSource;  
	 private  Statement stmt;

	
	
	public int userRegistration(String name, String email, String password, String gender) {
		int resultStatus = 0;	
		try {
			stmt = dataSource.getConnection().createStatement();
			resultStatus = stmt.executeUpdate("insert into user (`active_status`, `email`, `gender`, `name`, `password`) values(1,'"+email+"','"+gender+"','"+name+"','"+password+"')");
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	  return resultStatus;
	}
	
	
	public User userLogin(String email, String password){
		User logUser = null;
		List<User> userList = new ArrayList<User>();
		String getUserQuery ="select * from user WHERE email='"+email+"'";
	        System.out.println(getUserQuery);
		try {
			stmt = dataSource.getConnection().createStatement();
			ResultSet tempResult = stmt.executeQuery(getUserQuery);
		
			while(tempResult.next()){
				User userObj = new User();
			    
				userObj.setId(tempResult.getLong("id"));
				userObj.setName(tempResult.getString("name"));
				userObj.setEmail(tempResult.getString("email"));
				userObj.setPassword(tempResult.getString("password"));
				userList.add(userObj);
			}
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		   for(User singleUser: userList){
			   
			   if(singleUser.getPassword().equals(password)){
				   logUser = singleUser;  
			   } 
		   }
		  
		
		
		return logUser;	
	}

}