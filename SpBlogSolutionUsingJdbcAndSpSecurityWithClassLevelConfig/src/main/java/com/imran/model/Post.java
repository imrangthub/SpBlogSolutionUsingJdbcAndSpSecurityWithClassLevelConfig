package com.imran.model;



public class Post {
	
	Long id;
	String title;
	String body;
	int active_status = 0;
	String feature_image;
	
	
	
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public String getTitle() {
		return title;
	}
	public void setTitle(String title) {
		this.title = title;
	}
	public String getBody() {
		return body;
	}
	public void setBody(String body) {
		this.body = body;
	}
	public int getActive_status() {
		return active_status;
	}
	public void setActive_status(int active_status) {
		this.active_status = active_status;
	}
	public String getFeature_image() {
		return feature_image;
	}
	public void setFeature_image(String feature_image) {
		this.feature_image = feature_image;
	}
	
	
	@Override
	public String toString() {
		return "Post [id=" + id + ", title=" + title + ", body=" + body + ", active_status=" + active_status
				+ ", feature_image=" + feature_image + "]";
	}
	
	
	
	
	

}
