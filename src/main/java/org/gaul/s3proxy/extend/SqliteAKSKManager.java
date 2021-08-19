package org.gaul.s3proxy.extend;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author yangyanbo
 */
public class SqliteAKSKManager extends AbStractAKSKManager {
    String confPath = "src/main/resources/config.db";
    Connection conn = null;

    public SqliteAKSKManager() throws SQLException {
        super();
        String dbUrl = "jdbc:sqlite:" + confPath;
        conn = DriverManager.getConnection(dbUrl);
        if (conn != null) {
            DatabaseMetaData meta = conn.getMetaData();
            System.out.println("The driver name is " + meta.getDriverName());
            System.out.println("A new database has been created.");
        }
        this.createTable();
        this.insertSomeUsers();
        this.loads2Cache();
    }

    @Override
    public void createAKSKForBucket(String bucket, String access_key, String secret_key) {
        try {
            String sql = "INSERT INTO bucket_access_manage(bucket, access_key, secret_key) VALUES(?,?, ?)";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, bucket);
            pstmt.setString(2, access_key);
            pstmt.setString(3, secret_key);
            pstmt.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    public void loads2Cache() {
        try {
            List<Map<String, AkSkPair>> bucketAkList = this.getBucketAkSKsFromDB();
            for (Map<String, AkSkPair> m :bucketAkList ){
               for (String key :m.keySet()){
                   this.getCacheManager().setKey(key, m.get(key));
               }
            }
        }catch (Exception e) {
            System.out.println("Take record from db to cache fail.");
        }

    }

    @Override
    public Map<String, AkSkPair> getBucketAkSkList() throws Exception {
        // first take from cache. if not take from db
        Map<String, AkSkPair> map = new HashMap<>();
        Map<String, Object> m = this.getCacheManager().getAll();
        for (String key: m.keySet()){
            map.put(key, (AkSkPair) m.get(key));
        }
        return map;
    }

    @Override
    public String getBucketFromAccessKey(String ak) {
        // ugly here but work
        String bucket = "";
        try{
            Map<String, Object> m = this.getCacheManager().getAll();
            for (String k : m.keySet()){
                AkSkPair akSkPair = (AkSkPair) m.get(k);
                if (akSkPair.getAccess_key().equalsIgnoreCase(ak)){
                    bucket = k;
                    break;
                }
            }

        }catch (Exception e){
            e.printStackTrace();
            return bucket;
        }finally {
            return bucket;
        }
    }

    public void createTable() {
        try {
            // SQL statement for creating a new table
            String sql = "CREATE TABLE IF NOT EXISTS bucket_access_manage (\n"
                    + " id integer PRIMARY KEY,\n"
                    + " bucket text UNIQUE NOT NULL,\n"
                    + " access_key text NOT NULL,\n"
                    + " secret_key text NOT NULL,\n"
                    + " enable integer\n"
                    + ");";
            Statement stmt = conn.createStatement();
            stmt.execute(sql);
        }catch (Exception e){
            e.printStackTrace();
        }

    }

    public List<Map<String, AkSkPair>> getBucketAkSKsFromDB() throws Exception {
        String sql = "SELECT id, bucket, access_key,secret_key FROM bucket_access_manage";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        List<Map<String, AkSkPair>> rsl = new ArrayList<>();
        // loop through the result set
        while (rs.next()) {
            System.out.println(rs.getInt("id") + "\t" +
                    rs.getString("bucket") + "\t" +
                    rs.getString("access_key") + "\t" +
                    rs.getString("secret_key"));

            Map<String, AkSkPair> m = new HashMap<>();
            AkSkPair akSkPair = new AkSkPair(rs.getString("access_key"),
                    rs.getString("secret_key"));

            m.put(rs.getString("bucket"), akSkPair);
            rsl.add(m);
        }
        return rsl;
    }

    public void insertSomeUsers() {
        // SQL statement for creating a new table
        this.createAKSKForBucket("ai-ctr", "helloworld1", "1234512345");
        this.createAKSKForBucket("jianjiang", "helloworld2", "1234512345");
        this.createAKSKForBucket("lhli3", "helloworld3", "1234512345");

    }


}
