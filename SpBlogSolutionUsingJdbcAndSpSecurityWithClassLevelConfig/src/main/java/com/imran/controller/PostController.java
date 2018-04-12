package com.imran.controller;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.imran.model.Post;
import com.imran.service.PostService;

@Controller
@RequestMapping(value = "/post")
public class PostController {

	@Autowired
	PostService postService;

	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String dashboard(ModelMap map) {
		List<Post> postList = postService.postList();
		Collections.reverse(postList);
		map.addAttribute("postList", postList);
		return "post/dashboard";
	}

	@RequestMapping(value = "/create", method = RequestMethod.GET)
	public String viewCreate(Model model, final RedirectAttributes redirectAttributes) {

		return "post/create";
	}

	@RequestMapping(value = "/create", method = RequestMethod.POST)
	public String createPost(ModelMap map, @RequestParam("file") MultipartFile file,
			@RequestParam("title") String title, @RequestParam("body") String body) throws Exception {

		if (title.equals("") || body.equals("")) {
			map.addAttribute("message", "Require field is Empty");
			return "post/create";
		}

		if (!file.getOriginalFilename().equals("")) {
			//
			boolean imageFormateCheck = postService.checkFile(file);

			if (!imageFormateCheck) {
				map.addAttribute("message", "Invalid file formate");
				return "post/create";
			}
			String uploadedFileName = postService.uploadFileName(file);
			if (uploadedFileName != null) {
				boolean status = postService.createPost(title, body, uploadedFileName);
				if (status) {
					map.addAttribute("message", "Post Creation failed");
					return "post/create";
				}
			}

		} else {
			boolean status = postService.createPost(title, body, "");
			if (status) {
				map.addAttribute("message", "Post Creation failed");
				return "post/create";
			}
		}

		map.addAttribute("message", "Post added Successfully");
		return "post/create";

	}
	
	
	@RequestMapping(value="/edit/{id}")
	public String editView(ModelMap map, @PathVariable("id") Integer id){
		Post singlePost = null;
		List<Post> postList =  postService.getPostById(id);
		for(Post p: postList){
			singlePost = p;
		}
		if(singlePost == null){
			map.addAttribute("message", "Post not found");	
			return "redirect:/post/";
		}
		map.put("singlePost",singlePost);
		return "post/edit";
	}
	
	

	@RequestMapping(value = "/update", method = RequestMethod.POST)
	public String updatePost(ModelMap map, @RequestParam("file") MultipartFile file,
			@RequestParam("title") String title, @RequestParam("body") String body, @RequestParam("id") String id, @RequestParam("current_image") String current_image) throws Exception {

		if (title.equals("") || body.equals("")) {
			map.addAttribute("message", "Require field is Empty");
			return "post/create";
		}
		if(!current_image.equals("")){
			int status = postService.updatePost(title, body, current_image, id);
			if (status>0) {
				map.addAttribute("message", "Post Update Successfully");
				return "post/create";
			}else{
				map.addAttribute("message", "Post Update failed");
				return "post/create";
			}
		}

		if (!file.getOriginalFilename().equals("")) {
			//
			boolean imageFormateCheck = postService.checkFile(file);

			if (!imageFormateCheck) {
				map.addAttribute("message", "Invalid file formate");
				return "post/create";
			}
			String uploadedFileName = postService.uploadFileName(file);
			if (uploadedFileName != null) {
				int status = postService.updatePost(title, body, uploadedFileName, id);
				if (status<=0) {
					map.addAttribute("message", "Post Creation failed");
					return "post/create";
				}
			}

		} else {
			int status = postService.updatePost(title, body, "", id);
			if (status<=0) {
				map.addAttribute("message", "Post Update failed");
				return "post/create";
			}
		}

		map.addAttribute("message", "Post Update Successfully");
		return "post/create";

	}
	
	
	
	@RequestMapping(value="/delete/{id}")
	public String delete(ModelMap map, @PathVariable("id") Integer id){
		
		System.out.println("Post Action Id:"+id);
		int resultStatus = postService.deletePost(id);
		if(resultStatus>0){
			map.put("message","Successfully Delete this Post");	
		}else{
			map.put("message","Post not found");
		}
		return "redirect:/post/";
	}
	
	
	
}
