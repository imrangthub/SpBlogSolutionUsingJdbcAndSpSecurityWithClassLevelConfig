package com.imran.service;

import javax.servlet.ServletContext;
import javax.sql.DataSource;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import com.imran.common.BaseService;
import com.imran.model.Post;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service 
public class PostService extends BaseService {

	private static final String UPLOAD_DIRECTORY = "/imgFolder";

	@Autowired
	DataSource dataSource;
	private Statement stmt;
	
	public List<Post> postList(){
		
		List<Post> postList = new ArrayList<Post>();
		
		String getAllDataQuery = "SELECT * FROM `post` ORDER BY ID"; //  LIMIT " + 1 + ","+ 2
		try {
			this.stmt = dataSource.getConnection().createStatement();
			ResultSet tempResult = stmt.executeQuery(getAllDataQuery);
			while(tempResult.next()){
				Post postModelObj = new Post();
				postModelObj.setId(Long.parseLong(tempResult.getString("id")));
				postModelObj.setTitle(tempResult.getString("title"));
				postModelObj.setBody(tempResult.getString("body"));
				postModelObj.setFeature_image(tempResult.getString("feature_image"));
				postList.add(postModelObj);
			}
			stmt.close();
			dataSource.getConnection().close();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return postList;		
	}

//	public boolean postImageHandeler(MultipartFile file) {
//		boolean uploadImgStatus = false;
//		String uniqName = null;
//		String fileName = file.getOriginalFilename();
//
//		byte[] bytes;
//		try {
//			bytes = file.getBytes();
//			Random generator = new Random();
//			int r = Math.abs(generator.nextInt());
//			uniqName = r + "_" + (String) fileName;
//			File dir = new File(
//					"G:/1_BlogWithSpringSolution/Pro1/BlogSolutionUsingSpringJdbcWithXmlConfig/src/main/webapp/resources/imgFolder/");
//			// Create the file on server
//			File serverFile = new File(dir.getAbsolutePath() + File.separator + uniqName);
//			BufferedOutputStream stream = new BufferedOutputStream(new FileOutputStream(serverFile));
//			uploadImgStatus = true;
//			stream.write(bytes);
//			stream.close();
//
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//
//		return uploadImgStatus;
//	}



	public boolean createPost(String title, String body, String image) {
		boolean createStatus = false;
		try {
			stmt = dataSource.getConnection().createStatement();
			createStatus = stmt.execute("insert into post(`title`, `body`, `feature_image`) values('" + title + "','"
					+ body + "', '" + image + "')");
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return createStatus;
	}
	
	public List<Post>  getPostById(long id){
		List<Post> singlePost = new ArrayList<Post>();
		String getQuery ="select * from post WHERE id='"+id+"'";
	        System.out.println(getQuery);
		try {
			stmt = dataSource.getConnection().createStatement();
			ResultSet tempResult = stmt.executeQuery(getQuery);
		
			while(tempResult.next()){
				Post postModelObj = new Post();
				postModelObj.setId(Long.parseLong(tempResult.getString("id")));
				postModelObj.setTitle(tempResult.getString("title"));
				postModelObj.setBody(tempResult.getString("body"));
				postModelObj.setFeature_image(tempResult.getString("feature_image"));
				singlePost.add(postModelObj);
			}
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return singlePost;	
	}
	
	public int updatePost(String title, String body, String image, String id) {
		int updateStatus = 0;
		try {
			stmt = dataSource.getConnection().createStatement();
			String updateQuery = "UPDATE post SET title='"+title+"', body='"+body+"', feature_image = '"+image+"' WHERE id ='"+id+"'";
			System.out.println(updateQuery);
			updateStatus = stmt.executeUpdate(updateQuery);
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return updateStatus;
	}

	
	public int deletePost(long id){
		int status=0;
		
		List<Post> postList = getPostById(id);
		if(postList != null){
			for(Post p : postList){
				if(!p.getFeature_image().equals("")){
					removeFile(p.getFeature_image());
				}
				String deleteQuery ="DELETE FROM post WHERE `id`='"+id+"'";		
				try {
				stmt = dataSource.getConnection().createStatement();
				status = stmt.executeUpdate(deleteQuery);			
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			}
		}		
		return status;
	}



}